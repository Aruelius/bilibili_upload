# coding=utf-8

# @Time    : 2020-02-29 21:32:39
# @Author  : Aruelius
# @FileName: bilibili_upload.py

import asyncio
import base64
import datetime
import hashlib
import html
import json
import math
import os
import re
import threading
import time
import traceback
from configparser import ConfigParser
from urllib import parse

import aiohttp
import redis
import requests
import rsa


class LoginError(Exception):
    pass

class UploadError(Exception):
    pass

class BiliBili(object):
    def __init__(self):
        self.s = requests.session()
        self.AppKey = "1d8b6e7d45233436"
        self.AppSecret = "560c52ccd288fed045859ed18bffd973"
        self.s.headers.update(
            {'User-Agent':'Mozilla/5.0 BiliDroid/5.38.0 (bbcallen@gmail.com)'}
        )
        self.upos_url = lambda uri: uri.replace("upos://", "")
        self.get_csrf = lambda: re.search('bili_jct=(.*?);', (self.s.headers['cookie'])).group(1)
        self.UPLOAD_URL = "https://member.bilibili.com/preupload"
        self.GET_KEY_URL = "https://passport.bilibili.com/api/oauth2/getKey"
        self.CAPTCHA_API = "http://a.jp2.mikuvps.com:19951/captcha"
        self.CAPTCHA_URL = "https://passport.bilibili.com/captcha"
        self.LOGIN_URL = "https://passport.bilibili.com/api/v2/oauth2/login"
        self.CHECK_FORMAT_URL = "https://member.bilibili.com/x/web/archive/desc/format"
        self.CHECK_LOGIN_STATUS_URL = "https://member.bilibili.com/x/web/elec/user"
        self.ADD_INFO_URL = "https://member.bilibili.com/x/vu/web/add"
        self.COVER_UP_URL = "https://member.bilibili.com/x/vu/web/cover/up"
        self.GET_TAGS_URL = "https://member.bilibili.com/x/web/archive/tags"
    
    @staticmethod
    def log(*msg: object):
        print(f'[{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}]', *msg)
    
    def md5(self, payload: any) -> str:
        hl = hashlib.md5()
        hl.update(payload.encode(encoding="utf8"))
        return hl.hexdigest()
    
    def calc_sign(self, data: dict) -> str:
        data_str = "&".join(
            f"{k}={v}" if k not in ['username', 'password']
            else f"{k}={parse.quote_plus(v)}"
            for k, v in data.items()
        )
        return self.md5(data_str + self.AppSecret)

    def encrypt(self, password: str) -> str:
        hashcode, pubkey = self.get_key()
        return base64.b64encode(
            rsa.encrypt(
                (hashcode + password).encode('utf-8'),
                rsa.PublicKey.load_pkcs1_openssl_pem(pubkey.encode())
            )
        )

    def captcha(self, image_data: bytes) -> str:
        r = requests.get(
            url = self.CAPTCHA_API,
            json = {"image": base64.b64encode(image_data).decode("utf-8")}
        ).json()
        return r["message"]
    
    def save_cookie(self, username: str):
        with open(f"./.{username}", mode="w") as f:
            json.dump(self.s.cookies.get_dict(), f, indent=2)
            f.close()

    def load_cookie(self, username: str):
        cookie_file = f"./.{username}"
        if os.path.exists(cookie_file):
            with open(cookie_file, mode="r") as f:
                cookie_dict = json.loads(f.read())
                f.close()
            [self.s.cookies.set(k, v, domain=".bilibili.com") for k, v in cookie_dict.items()]
            cookie = "; ".join(
                f"{k}={v}" for k, v in cookie_dict.items()
            )
            self.s.headers["cookie"] = cookie
            r = self.s.get(self.CHECK_LOGIN_STATUS_URL).json()
            if r["code"] == 0: return True
        return False

    def is_250(self, tid: int) -> bool:
        r = self.s.get(
            url=self.CHECK_FORMAT_URL,
            params={
                "typeid": tid,
                "copyright": "2"
            }
        ).json()
        return False if r["data"] else True

    def get_key(self) -> tuple:
        for _ in range(5):
            data = {
                "appkey": self.AppKey,
                "ts": str(int(time.time()))
            }
            data["sign"] = self.calc_sign(data)
            r = self.s.post(self.GET_KEY_URL, data).json()
            try:
                return r["data"]["hash"], r["data"]["key"]
            except KeyError:
                time.sleep(5)
    
    def login_with_captcha(self, data: dict) -> dict:
        BiliBili.log("需要验证码")
        captcha_result = self.captcha(self.s.get(self.CAPTCHA_URL).content)
        del data["sign"]
        data["captcha"] = captcha_result
        BiliBili.log(f"识别到验证码: {captcha_result}")
        data["sign"] = self.calc_sign(data)
        r = self.s.post(self.LOGIN_URL, data).json()
        if r["code"] == 0:
            BiliBili.log("使用验证码登陆成功！")
            return r
        else: raise LoginError(f"登录失败: {r}")

    def login(self, username: str, password: str) -> bool:
        def set_cookie(r: dict):
            cookie_list: list = r["data"]["cookie_info"]["cookies"]
            for item in cookie_list:
                self.s.cookies.set(item["name"], item["value"], domain='.bilibili.com')
            cookie = "; ".join(
                "%s=%s" % (item["name"], item["value"])
                for item in cookie_list
            )
            self.s.headers["cookie"] = cookie
            self.save_cookie(username)

        if self.load_cookie(username):
            BiliBili.log("Cookie 登陆成功！")
            return True
        
        data = {
            "appkey": self.AppKey,
            "password": self.encrypt(password),
            "ts": str(int(time.time())),
            "username": username,
        }
        data["sign"] = self.calc_sign(data)
        r = self.s.post(self.LOGIN_URL, data).json()
        code = r["code"]
        if code == 0:
            BiliBili.log("登陆成功！")
            set_cookie(r)
        elif code == -105:
            set_cookie(self.login_with_captcha(data))
        elif code == -449:
            raise LoginError("服务繁忙, 请稍后再试")
        else: raise LoginError(f"登陆失败: {r}")

    def preupload(self,
            title: str, source: str, tid: int, desc: str,
            file: str, tags: list, file_type: str, cover=None):
        
        def get_upload_id() -> str:
            r = self.s.post(f"https:{endpoint}/{upos_string}?uploads&output=json")
            return r.json()["upload_id"]

        self.log("开始上传")
        parts_list = []
        tasks = []
        if file.startswith("http"):
            file_size = int(requests.head(file).headers["Content-Length"])
            self.log(f"视频大小: {round(file_size/1024**2,2)}MB")
            file_name = title
        else:
            file_name = os.path.basename(file)
            file_size = os.path.getsize(file)
        params = {
            "name": f"{file_name}.{file_type}",
            "size": file_size,
            "r": "upos",
            "profile": "ugcupos/bup",
            "ssl": "0",
            "version": "2.7.1",
            "build": "2070100",
            "os": "upos",
            "upcdn": "ws",
            "probe_version": "20200224"
        }
        r = self.s.get(self.UPLOAD_URL, params=params).json()
        upos_uri = r["upos_uri"]
        endpoint = r["endpoint"]
        self.s.headers["X-Upos-Auth"] = r["auth"]
        upos_string = self.upos_url(upos_uri)
        upload_id = get_upload_id()
        chunk_size: int = r["chunk_size"]
        biz_id = r["biz_id"]

        async def handler(start: int, end: int) -> bytes:
            async with aiohttp.ClientSession() as session:
                async with session.get(file, headers = {
                        "Range": "bytes=%d-%d" % (start, end-1)
                    }) as resp:
                    return await resp.read()

        async def upload_chunk(chunk_index, chunks_num, chunk_data, chunk_size, chunks_list):
            start = chunk_index * chunk_size
            end = chunk_index * chunk_size + (len(chunk_data) if isinstance(chunk_data, bytes) else chunk_data)
            chunk_data = chunk_data if isinstance(chunk_data, bytes) else await handler(start, end)
            for _ in range(3):
                async with aiohttp.ClientSession() as session:
                    async with session.put(
                            url=f"https:{endpoint}/{upos_string}",
                            params={
                                "partNumber": chunk_index + 1,
                                "uploadId": upload_id,
                                "chunk": chunk_index,
                                "chunks": chunks_num,
                                "size": len(chunk_data),
                                "start": start,
                                "end": end,
                                "total": file_size
                            },
                            data=chunk_data,
                            headers={
                                "X-Upos-Auth": r["auth"],
                            }
                        ) as resp:
                        response_text = await resp.text()
                        if resp.status == 200:
                            break
            else:
                raise UploadError(f"分块:{chunk_index}上传超时")
            parts_list.append(chunk_index + 1)
            BiliBili.log(f"{response_text} {chunks_list.pop(0)}/{chunks_num}")
        chunks_num = math.ceil(file_size / chunk_size)
        chunks_list = [_+1 for _ in range(chunks_num)]
        async def run():
            chunk_index = -1
            if not file.startswith("http"):
                with open(file, mode="rb") as f:
                    while True:
                        chunk_data = f.read(chunk_size)
                        if not chunk_data:
                            break
                        chunk_index += 1
                        tasks.append(asyncio.create_task(upload_chunk(chunk_index, chunks_num, chunk_data, chunk_size, chunks_list)))
                    for task in tasks:
                        await task
            elif file.startswith("http"):
                for _ in range(chunks_num):
                    chunk_index += 1
                    if chunk_index == chunks_num:
                        chunk_data = file_size % (chunk_size)
                    else:
                        chunk_data = chunk_size
                    tasks.append(asyncio.create_task(upload_chunk(chunk_index, chunks_num, chunk_data, chunk_size, chunks_list)))
                for task in tasks:
                    await task
        asyncio.run(run())

        self.s.post(
            url=f"https:{endpoint}/{upos_string}",
            params={
                "output": "json",
                "name": file_name,
                "profile": "ugcupos/bup",
                "uploadId": upload_id,
                "biz_id": biz_id
            },
            json={"parts": [{"partNumber": i, "eTag": "etag"} for i in parts_list]}
        )
    
        def get_tags() -> list:
            r = self.s.get(
                url=self.GET_TAGS_URL,
                params={
                    "title": title,
                    "filename": upos_string.replace("ugc/", "").split(".")[0]
                }
            ).json()
            return [r["data"][_]["tag"] for _ in range(3)]
        
        def add():
            newtags = tags or get_tags()
            cover_url = self.cover_up(cover)
            self.s.headers["Content-Type"] = "application/json;charset=UTF-8"
            for _ in range(3):
                r = self.s.post(
                    url=self.ADD_INFO_URL,
                    params={"csrf": self.get_csrf()},
                    json={
                        "copyright": 2,
                        "videos": [{
                            "filename": upos_string.replace("ugc/", "").split(".")[0],
                            "title": title,
                            "desc": ""
                        }],
                        "source": source,
                        "tid": tid,
                        "cover": cover_url,
                        "title": title,
                        "tag": ','.join([tag for tag in newtags]),
                        "desc_format_id": 12,
                        "desc": desc,
                        "dynamic": f"#{'##'.join([tag for tag in newtags])}#",
                        "subtitle": {
                            "open": 0,
                            "lan": ""
                        }
                    }
                ).json()
                code = r["code"]
                if code == 0:
                    BiliBili.log(f"投稿成功！av号: {r['data']['aid']}")
                    break
                elif code == 20001:
                    BiliBili.log(f"5s后尝试重新提交稿件 {_}/3,错误: {r}")
                    time.sleep(5)
                    continue
                elif code == 21070:
                    BiliBili.log(r["message"] + " 等待10s后重新上传")
                    time.sleep(10)
                    continue
                else:
                    raise UploadError(f"投稿视频失败！, {r}")
            else:
                raise UploadError("投稿视频超过重试次数！")
        add()
        
    def cover_up(self, image_url: str) -> str:
        if not image_url: return
        self.s.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = self.s.post(
            url=self.COVER_UP_URL,
            data={
                "cover": b"data:image/jpeg;base64," + (base64.b64encode(
                    requests.get(image_url).content)),
                "csrf": self.get_csrf()
            }
        ).json()
        return r["data"]["url"]

class NicoNico(object):
    def __init__(self, username, password, proxy=None):
        self._username = username
        self._password = password
        self._session = requests.session()
        self._session.proxies.update({"http": proxy, "https": proxy}) if proxy else None
        self._session.headers.update({"referer": "https://www.nicovideo.jp/"})
        self.LOGIN_URL = "https://account.nicovideo.jp/api/v1/login"
        self.SESSIONS_URL = "https://api.dmc.nico/api/sessions"
        self.info_dict = lambda html_body: json.loads(html.unescape(re.findall(r'data-api-data="(.+?)"', html_body)[0]))
        
    def nico_login(self):
        self._session.post(
            url=self.LOGIN_URL,
            params={"site": "niconico"},
            data={
                "mail_tel": self._username,
                "password": self._password
            },
            allow_redirects=False
        )

    def get_tags_desp(self, watch_url: str) -> tuple:
        reg = re.compile('<[^>]+>',re.S)
        response = self.get_video_info(watch_url)

        tags = [tag["name"] for tag in response["tags"]]

        description = response["video"]["originalDescription"]
        description = html.unescape(description)
        description = html.unescape(description)
        description = reg.sub("",description.replace("<br>","\n"))

        thumbnail_url = response["video"]["largeThumbnailURL"]

        return tags, description, thumbnail_url

    def get_video_info(self, watch_url: str) -> str:
        r = requests.get(watch_url).text
        response = self.info_dict(r)
        thumbnail_url = re.findall(r'thumbnail" content="(.+?)"', r)[0]
        response["video"]["largeThumbnailURL"] = thumbnail_url
        return response

    def get_download_url(self, watch_url: str) -> tuple:
        r = self._session.get(watch_url).text
        try:
            vip_level = re.findall(r"user.member_status = '(.+?)';", r)[0]
        except:
            raise LoginError("登录失败！请检查帐号密码是否正确！")
       
        response = self.info_dict(r)

        postedDateTime = response["video"]["postedDateTime"].replace("/","-")
        print(f"[{postedDateTime}] N站上传")

        movieType = response["video"]["movieType"]
        session_api_json = response["video"]["dmcInfo"]["session_api"]
        recipe_id = session_api_json["recipe_id"]
        content_id = session_api_json["content_id"]
        video_src_ids = session_api_json["videos"]
        audio_src_ids = session_api_json["audios"]
        lifetime = session_api_json["heartbeat_lifetime"]

        if vip_level == "premium":
            transfer_preset = session_api_json["transfer_presets"][0]
            storyboard = response["video"]["dmcInfo"]["storyboard_session_api"]
            player_id = storyboard["player_id"]
            auth_type = storyboard["auth_types"]["storyboard"]
        elif vip_level == "normal":
            transfer_preset = ""
            player_id = session_api_json["player_id"]
            auth_type = "ht2"

        signature = session_api_json["signature"]
        content_key_timeout = session_api_json["content_key_timeout"]
        
        token = session_api_json["token"]
        token_json = json.loads(token)
        service_id = token_json["service_id"]
        service_user_id = token_json["service_user_id"]
        priority = token_json["priority"]

        r = self._session.post(
            url=self.SESSIONS_URL,
            params={"_format": "json"},
            json={
                "session":{
                    "recipe_id": recipe_id,
                    "content_id": content_id,
                    "content_type": "movie",
                    "content_src_id_sets":[
                        {
                            "content_src_ids":[
                                {
                                    "src_id_to_mux":{
                                        "video_src_ids":video_src_ids,
                                        "audio_src_ids":audio_src_ids
                                    }
                                }
                            ]
                        }
                    ],
                    "timing_constraint":"unlimited",
                    "keep_method":{
                        "heartbeat":{
                            "lifetime": lifetime
                        }
                    },
                    "protocol":{
                        "name":"http",
                        "parameters":{
                            "http_parameters":{
                                "parameters":{
                                    "http_output_download_parameters":{
                                        "use_well_known_port":"yes",
                                        "use_ssl":"yes",
                                        "transfer_preset": transfer_preset
                                    }
                                }
                            }
                        }
                    },
                    "content_uri":"",
                    "session_operation_auth":{
                        "session_operation_auth_by_signature":{
                            "token": token,
                            "signature": signature
                        }
                    },
                    "content_auth":{
                        "auth_type": auth_type,
                        "content_key_timeout": content_key_timeout,
                        "service_id": service_id,
                        "service_user_id": service_user_id
                    },
                    "client_info":{
                        "player_id": player_id
                    },
                    "priority": priority
                }
            }
        )

        code = r.status_code
        if code in [200, 201]:
            response = r.json()
            content_uri = response["data"]["session"]["content_uri"]
            return movieType, content_uri
        elif code in [403, 400]:
            raise requests.exceptions.HTTPError(f"{code}错误: {r.text}")
        else:
            raise requests.exceptions.HTTPError(f"未知错误: {r.text}")

    def _handler(self, start: int, end: int, video_url: str, file_path: str):
        headers = {
            "Range": "bytes=%d-%d" % (start, end)
        }
        r = self._session.get(video_url, headers=headers, stream=True)
        with open(file_path, mode="r+b") as f:
            f.seek(start)
            f.tell()
            f.write(r.content)
    
    def download(self, watch_url: str, num_thread=50):
        self.nico_login()
        video_dir = "./videos/"
        movieType, video_download_url = self.get_download_url(watch_url)
        down_start = datetime.datetime.now().replace(microsecond=0)
        r = self._session.head(video_download_url)
        try:
            if not os.path.exists(video_dir):
                os.makedirs(video_dir)
            file_name = f"{watch.split('/')[-1]}.{movieType}"
            file_size = int(r.headers["content-length"])
            file_size_to_mb = file_size / 1024**2
        except:
            print("检查URL，或不支持多线程下载")
            return
        
        file_path = f"{video_dir}{file_name}"
        with open(file_path, "wb") as f:
            f.truncate(file_size)
            f.close()
        
        chunk_size = file_size // num_thread
        for i in range(num_thread):
            start = chunk_size * i
            if i == num_thread - 1:
                end = file_size
            else:
                end = start + chunk_size
            
            t = threading.Thread(target=self._handler,kwargs={
                "start": start,
                "end": end,
                "video_url": video_download_url,
                "file_path": file_path
            })
            t.setDaemon(True)
            t.start()
        threads = threading.current_thread()
        for thread in threads:
            if thread is threads:
                continue
            thread.join()

        down_end = datetime.datetime.now().replace(microsecond=0)
        BiliBili.log("下载完成:{file_name},大小:{file_size}MB,耗时:{downtime}".format(
                    file_name=file_name,
                    file_size=round(file_size_to_mb, 2),
                    downtime=(down_end-down_start)))
        return file_path

class Monitor(object):
    def __init__(self):
        self.cfg = ConfigParser()
        self.cfg.read("config.ini")
        self.nico_username = self.cfg.get("niconico", "username")
        self.nico_password = self.cfg.get("niconico", "password")
        self.bili_username = self.cfg.get("bilibili", "username")
        self.bili_password = self.cfg.get("bilibili", "password")
        self.options = self.cfg["options"]
        self.up_list = ["nicovideo.user.video.upload", "nicovideo.channel.video.upload"]
        self.NICOREPO_URL = "https://www.nicovideo.jp/api/nicorepo/timeline/my/all"
        self.WATCH_URL = "https://www.nicovideo.jp/watch/"
        self.pool = redis.ConnectionPool(
            host=self.cfg.get("redis", "host"), port=self.cfg.get("redis", "port"),
            db=0, decode_responses=True, password=self.cfg.get("redis", "password")
        )

    def notification(self, text: str):
        if self.options.getboolean("notice"):
            key = self.options["key"]
            r = requests.post(
                url=f"https://sc.ftqq.com/{key}.send",
                data={
                    "text": "投稿通知",
                    "desp": text
                }
            )
            code = r.json()["errmsg"]
            if code == 0:
                BiliBili.log("通知发送完毕")

    def write_in_redis(self, sm: str):
        r = redis.Redis(connection_pool=self.pool)
        r.sadd("nico_videos", sm)
        BiliBili.log(f"写Redis: {sm} 成功")
    
    def is_in_redis(self, sm: str) -> bool:
        r = redis.Redis(connection_pool=self.pool)
        video_set = r.smembers("nico_videos")
        return True if sm in video_set else False

    @staticmethod
    def delete_video():
        [os.remove(f"./videos/{file}") for file in os.listdir("./videos")]

    def start_upload(self, watch_url: str, video_tile: str, sm: str,
            description: str, tags: list, file: str, cover: str, file_type: str):
        tid = self.cfg.getint("bilibili", "tid")
        bilibili.login(self.bili_username, self.bili_password)
        if bilibili.is_250(tid):
            description = description[0:249]
        bilibili.preupload(
            title=video_tile, source=sm, tid=tid,
            desc=description, file=file, tags=tags,
            file_type=file_type, cover=cover
        )

    def main(self):
        niconico = NicoNico(self.nico_username, self.nico_password)
        niconico.nico_login()
        while True:
            try:
                try: r = niconico._session.get(self.NICOREPO_URL,params={"client_app": "pc_myrepo"})
                except KeyboardInterrupt: break
                except: continue
                if r.status_code != 200: niconico.nico_login()
                else:
                    response = r.json()
                    for data in response["data"]:
                        if data["topic"] in self.up_list and data["video"]["status"] == "PUBLIC":
                            sm = data["video"]["id"]
                            watch_url = f"{self.WATCH_URL}{sm}"
                            if self.is_in_redis(sm): continue
                            print("".join("="*35))
                            BiliBili.log(f"视频更新 {sm}")
                            video_title = data["video"]["title"]
                            tags, description, cover = niconico.get_tags_desp(watch_url)
                            if self.options.getboolean("stream_upload"):
                                _, file = niconico.get_download_url(watch_url)
                                self.start_upload(watch_url, video_title, sm, description, tags, file, cover, _)
                            else:
                                file = niconico.download(watch_url)
                                self.start_upload(watch_url, video_title, sm, description, tags, file, cover, _)
                                self.delete_video()
                            if self.options.getboolean("notice"):
                                try:
                                    nickname = data["senderNiconicoUser"]["nickname"]
                                except KeyError:
                                    nickname = data["senderChannel"]["name"]
                                text = "视频作者: {}\n视频标题: {}\n视频链接{}\n".format(
                                    nickname, video_title, f"http://acg.tv/{sm}"
                                )
                                self.notification(text)
                            self.write_in_redis(sm)
                            time.sleep(33)
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except:
                traceback.print_exc()
                if not self.options.getboolean("stream_upload"): self.delete_video()

if __name__ == "__main__":
    bilibili = BiliBili()
    monitor = Monitor()
    monitor.main()
