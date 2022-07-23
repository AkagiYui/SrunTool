import json
import os
import time
import base64
from typing import Union

import requests
import re
from sruntool.ecode_explain import ecode_explain
from sruntool.srun_encrypt import SrunEncrypt
from sruntool.exception import TooFastException
from sruntool.utils import get_hmac_md5, get_sha1


# 常见的错误码
# E2531 用户不存在
# E2901 第三方错误(对接运营商) Status_Err欠费/Passwd_Err密码错误/UserName_Err销号
# E1606 用户禁用
# E2620 密码正确 已在线
# 0  ok 密码正确 登录成功


def get_explain(ecode: Union[str, int]) -> str:
    """
    获取错误码的解释
    :param ecode: 错误码
    :return: 错误码的解释
    """

    return ecode_explain[ecode]


class SrunOperator:
    """
    深澜校园网操作类

    支持 登录/注销/获取已登录账号信息/获取已登录的号主姓名
    """

    def __init__(
        self,
        auth_server: str = '192.168.0.170',
        ac_id: str = '2',
        callback: str = 'SrunTool',
        _name: str = 'SrunTool',
        _type: str = '1',
        n: str = '200'
    ):
        """
        初始化，设置认证服务器、子网id、回调名称等参数

        :param auth_server: 认证服务器
        :param ac_id: 子网id
        :param callback: 回调名称
        :param _name:
        :param _type: 平台类型
        :param n:
        """

        self.callback = callback
        self._type = _type
        self.ac_id = ac_id
        self._name = _name  # TODO: 查找意义
        self.n = n  # TODO: 查找意义

        self.protocol = 'http'
        self.base_url = f'{self.protocol}://{auth_server}/cgi-bin'  # 基础url
        self.url_srun_portal = f'{auth_server}/srun_portal'  # 深澜入口 url

    def _get_token_and_ip(self, username: str) -> (str, str):
        """
        获取token和ip，用于登录

        :param username: 用户名
        :return: token, ip
        """

        params = {
            'callback': self.callback,
            'username': username,
            '_': int(time.time() * 1000)  # 当前时间戳
        }

        result = requests.get(f'{self.base_url}/get_challenge', params=params)
        result = re.search(r'{.+}', result.text)
        result = json.loads(result.group())

        if result['error'] == 'speed_limit_error':
            raise TooFastException('请求过于频繁')
        return result['challenge'], result['client_ip']

    def current_info(self) -> dict:
        """
        获取当前已登录的账号信息

        :return: 账号信息
        """

        params_get_token = {
            'callback': self.callback,
            '_': int(time.time() * 1000)  # 当前时间戳
        }
        result = requests.get(f'{self.base_url}/rad_user_info', params=params_get_token)
        result = re.search(r'{.+}', result.text)
        result = json.loads(result.group())
        return result  # TODO: 补充返回信息注释或改为对象

    def login(self, username: str, password: str) -> dict:
        """
        登录

        :param username: 用户名
        :param password: 密码
        :return: 登录结果
        """

        token, ip = self._get_token_and_ip(username)
        hmd5 = get_hmac_md5(password, token)

        # 账号信息加密
        info = {
            'username': username,
            'password': password,
            'ip': ip,
            'acid': self.ac_id,
            'enc_ver': 'srun_bx1'
        }
        info = re.sub("'", '"', str(info))  # 单引号转双引号
        info = re.sub(' ', '', info)  # 删所有空
        info = SrunEncrypt.get_xencode(info, token)  # srun自家加密
        info = SrunEncrypt.get_base64(info)  # srun魔改base64加密
        info = '{SRBX1}' + info

        # 计算校验和
        chksum = token + username
        chksum += token + hmd5
        chksum += token + self.ac_id
        chksum += token + ip
        chksum += token + self.n
        chksum += token + self._type
        chksum += token + info
        chksum = get_sha1(chksum)

        params = {
            'callback': self.callback,
            'action': 'login',
            'username': username,
            'password': '{MD5}' + hmd5,
            'ac_id': self.ac_id,
            'ip': ip,
            'chksum': chksum,
            'info': info,
            'n': self.n,
            'type': self._type,
            'os': os,  # TODO: 这是什么
            'name': self._name,
            'double_stack': '0',  # TODO: 这是什么
            '_': int(time.time() * 1000)
        }

        result = requests.get(self.url_srun_portal, params=params)
        result = re.search(r'{.+}', result.text)
        result = json.loads(result.group())

        if result['error'] == 'speed_limit_error':
            raise TooFastException('请求过于频繁')
        return result  # TODO: 补充返回信息注释或改为对象

    def logout(self, username: str) -> dict:
        """
        退出登录

        :param username:
        :return: 退出结果
        """

        params = {
            'callback': self.callback,
            'action': 'logout',
            'username': username,  # TODO: 在未传入时尝试自动获取
            '_': int(time.time() * 1000)
        }

        try:
            result = requests.get(self.url_srun_portal, params=params)
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError('连接认证服务器失败') from e
        result = re.search(r'{.+}', result.text)
        result = json.loads(result.group())
        return result  # TODO: 补充返回信息注释或改为对象

    def get_self_service(self, username) -> requests.Response:
        """
        获取自助服务信息，必须本机已登录该账号

        :param username: 当前已登录的账号
        :return: 自助服务信息
        """
        url = f'{self.protocol}://{self.base_url}:8800/site/sso?data='
        url += base64.b64encode(f'{username}:{username}'.encode()).decode()
        return requests.get(url)

    def get_name(self, username: str) -> str:
        """
        获取已登录的号主姓名，必须本机已登录该账号

        :param username: 当前已登录的账号
        :return: 号主姓名
        """

        # TODO: 在未传入时尝试自动获取username
        result = self.get_self_service(username).text
        result = re.search('姓名</label>(.*)</li>', result)
        return result[1] if result is not None else None


if __name__ == '__main__':
    account = '16612345678'  # 账号
    so = SrunOperator('192.168.0.170')  # 创建operator

    r = so.current_info()  # 获取当前登录账号信息
    if r['error'] == 'ok':  # 已登录
        print(r['user_name'], '已经在线')
        exit(0)

    r = so.login(account, '123456')  # 登录
    if r['ecode'] == 0:
        print('登录成功', so.get_name(account))

        # 不延时容易造成请求频繁
        from time import sleep
        sleep(1)

        r = so.logout(account)
        if r['ecode'] == 0:
            print('下线成功')
    else:
        print('登录失败', get_explain(r['ecode']))
