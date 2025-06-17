# 签名模块：https://github.com/thshu/fnos-tv
import hashlib
import json
import math
import random
import time
from urllib.parse import parse_qsl, urlencode, unquote

import requests

class FNSIGN:
    @staticmethod
    def get_random_number(min_val: float = 0, max_val: float = 100, round_type: str = 'round') -> int:
        """
        获取范围内随机数，可指定取整方式：round、floor、ceil
        :param min_val: 最小值
        :param max_val: 最大值
        :param round_type: 取整方式
        :return: 随机整数
        """
        val = random.random() * (max_val - min_val) + min_val
        if round_type == 'floor':
            return math.floor(val)
        if round_type == 'ceil':
            return math.ceil(val)
        return round(val)

    @staticmethod
    def is_undefined(value) -> bool:
        """
        判断是否为 None（映射 JS 中的 undefined）
        """
        return value is None

    @staticmethod
    def is_null(value) -> bool:
        """
        判断是否为 None（映射 JS 中的 null）
        """
        return value is None

    @staticmethod
    def stringify_params(params: dict = None) -> str:
        """
        将字典按键排序并编码为查询字符串，过滤掉 None 值，空格编码为 %20
        :param params: 参数字典
        :return: 排序后的查询字符串
        """
        if params is None:
            params = {}
        filtered = {
            k: v for k, v in sorted(params.items())
            if not FNSIGN.is_undefined(v) and not FNSIGN.is_null(v)
        }
        qs = urlencode(filtered, doseq=True)
        return qs.replace('+', '%20')

    @staticmethod
    def parse_url(url: str) -> tuple:
        """
        将 URL 拆分为路径和参数字典，过滤掉值为 'undefined' 或 'null' 的参数
        :param url: 原始 URL 字符串
        :return: (path, params_dict)
        """
        parts = url.split('?', 1)
        path = parts[0]
        params = {}
        if len(parts) > 1 and parts[1]:
            for k, v in parse_qsl(parts[1], keep_blank_values=True):
                if v not in ('undefined', 'null'):
                    params[k] = v
        return path, params

    @staticmethod
    def hash_signature_data(data: str = '') -> str:
        """
        对字符串进行解码并计算 MD5，若解码失败则直接对原始串计算
        :param data: 原始字符串（可能包含百分号编码）
        :return: MD5 十六进制摘要
        """
        try:
            safe = data.replace('%(?![0-9A-Fa-f]{2})', '%25')
            decoded = unquote(safe)
            return hashlib.md5(decoded.encode('utf-8')).hexdigest()
        except Exception:
            return hashlib.md5(data.encode('utf-8')).hexdigest()

    @staticmethod
    def generate_signature(request_info: dict, secret: str = '') -> str:
        """
        根据请求信息生成签名参数串：nonce、timestamp、sign
        :param request_info: 请求信息，包含 method、url、params、data
        :param secret: 签名中附加的密钥字符串
        :return: 格式化后的签名参数串，如 nonce=...&timestamp=...&sign=...
        """
        try:
            method = request_info.get('method', '').upper()
            is_get = method == 'GET'
            url = request_info.get('url', '')
            path, query_params = FNSIGN.parse_url(url)

            if is_get:
                combined = {**request_info.get('params', {}), **query_params}
                request_text = FNSIGN.stringify_params(combined)
            else:
                request_text = json.dumps(
                    request_info.get('data', {}),
                    separators=(',', ':'),
                    ensure_ascii=False
                ) if request_info.get('data') is not None else ''

            signature_text = FNSIGN.hash_signature_data(request_text)
            nonce = str(FNSIGN.get_random_number(1e5, 1e6)).zfill(6)
            timestamp = str(int(time.time() * 1000))
            raw = '_'.join([
                "NDzZTVxnRKP8Z0jXg1VAMonaG8akvh",
                path,
                nonce,
                timestamp,
                signature_text,
                secret
            ])
            sign = hashlib.md5(raw.encode('utf-8')).hexdigest()

            return f"nonce={nonce}&timestamp={timestamp}&sign={sign}"
        except Exception as e:
            print(f"生成签名时出错: {e}")
            return ''

class FNWEB:
    BASE_URL = "/v/api/v1"
    SECRET = "16CCEB3D-AB42-077D-36A1-F355324E4237"

    @staticmethod
    def login(username: str, password: str) -> str:
        """
        登录并获取token
        :param username: 用户名
        :param password: 密码
        :return: token字符串
        """
        sign = FNSIGN.generate_signature({
            'method': "POST",
            'url': '/v/api/v1/login'
        }, FNWEB.SECRET)

        headers = {
            'Authorization': '',
            'authx': sign
        }

        json_data = {
            'username': username,
            'password': password,
            'app_name': 'trimemedia-web',
        }

        response = requests.post(
            f'{FNWEB.BASE_URL}/login',
            headers=headers,
            json=json_data
        )
        response.raise_for_status()

        return response.json()['data']['token']

    @staticmethod
    def get_media_list(token: str) -> list:
        """
        获取媒体列表
        :param token: 认证token
        :return: 媒体列表
        """
        sign = FNSIGN.generate_signature({
            'method': "GET",
            'url': '/v/api/v1/mediadb/list'
        }, FNWEB.SECRET)

        headers = {
            'Authorization': token,
            'authx': sign,
        }

        response = requests.get(
            f'{FNWEB.BASE_URL}/mediadb/list',
            headers=headers
        )
        response.raise_for_status()

        return response.json()['data']

    @staticmethod
    def scan_media(guid: str, token: str) -> dict:
        """
        扫描指定媒体
        :param guid: 媒体GUID
        :param token: 认证token
        :return: 扫描结果
        """
        sign = FNSIGN.generate_signature({
            'method': "POST",
            'url': f'/v/api/v1/mdb/scan/{guid}',
            'data': {}
        }, FNWEB.SECRET)

        headers = {
            'Authorization': token,
            'authx': sign,
        }
        response = requests.post(
            f'{FNWEB.BASE_URL}/mdb/scan/{guid}',
            headers=headers,
            json={}
        )
        response.raise_for_status()

        return response.json()

class Fnys:

    default_config = {
        "url": "",  # 飞牛影视服务器地址
        "username": "", #飞牛影视账号
        "password": "", #飞牛影视密码
    }
    default_task_config = {
        "media_name": "",  # 媒体库名称
    }

    token = ""

    is_active = False

    def __init__(self, **kwargs):
        self.plugin_name = self.__class__.__name__.lower()
        if kwargs:
            for key, _ in self.default_config.items():
                if key in kwargs:
                    setattr(self, key, kwargs[key])
                else:
                    print(f"{self.plugin_name} 模块缺少必要参数: {key}")
            if self.url and self.username and self.password:
                if self.url.endswith('/'):
                    self.url = self.url[:-1] 
                FNWEB.BASE_URL = self.url+FNWEB.BASE_URL
                try:
                    self.token = FNWEB.login(self.username, self.password)
                except Exception as e:
                    print(f"{self.plugin_name} 模块发生未知错误: {e}")
                if self.token:
                    self.is_active = True

    def run(self, task, **kwargs):
        task_config = task.get("addition", {}).get(
            self.plugin_name, self.default_task_config
        )
        if media_name := task_config.get("media_name"):
            try:
                # 获取媒体列表
                media_list = FNWEB.get_media_list(self.token)
                
                guid = next(
                    (item["guid"] for item in media_list if item["title"] == media_name),
                    None
                )
                
                if not guid:
                    print(f"{self.plugin_name} 模块未找到媒体库：'{media_name}，检查是否拼写错误！❌'")
                    return
                
                #print(f"{self.plugin_name} 模块找到目标媒体库GUID: {guid}")
                
                # 扫描媒体
                result = FNWEB.scan_media(guid, self.token)
                if result['data']:
                    print(f"{self.plugin_name} 模块扫描媒体库【{media_name}】成功✅")
                else:
                    print(f"{self.plugin_name} 模块扫描媒体库【{media_name}】失败！❌\n结果：{result}")
                
            except requests.exceptions.RequestException as e:
                print(f"{self.plugin_name} 模块请求出错: {e}")
            except KeyError as e:
                print(f"{self.plugin_name} 模块响应数据格式错误，缺少字段: {e}")
            except Exception as e:
                print(f"{self.plugin_name} 模块发生未知错误: {e}")
