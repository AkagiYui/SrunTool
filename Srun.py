import json
import os
import hashlib
import hmac
import math
import time
import base64
import requests
import re

# E2531 用户不存在
# E2901 第三方错误(对接运营商) Status_Err欠费/Passwd_Err密码错误/UserName_Err销号
# E1606 用户禁用
# E2620 密码正确 已在线
# 0  ok 密码正确 登录成功

ecode_explain = {
    0: '操作成功',
    'ok': '操作成功',
    'E0000': '登录成功',
    'E2401': 'User-Request',
    'E2402': 'Lost-Carrier',
    'E2404': 'Idle-Timeout',
    'E2405': 'Session-Timeout',
    'E2406': 'Admin-Reset',
    'E2407': 'Admin-Reboot',
    'E2408': 'Port-Error',
    'E2409': 'NAS-Error',
    'E2410': 'NAS-Request',
    'E2411': 'NAS-Reboot',
    'E2412': 'Port-Unneeded',
    'E2413': 'Port-Preempted',
    'E2414': 'Port-Suspended',
    'E2415': 'Service-Unavailable',
    'E2416': 'Callback',
    'E2417': 'User-Error',
    'E2531': '用户不存在',
    'E2532': '您的两次认证的间隔太短,请稍候10秒后再重试登录',
    'E2533': '密码错误次数超过限制，请5分钟后再重试登录',
    'E2534': '有代理行为被暂时禁用',
    'E2535': '认证系统已经被禁用',
    'E2536': '授权已过期',
    'E2553': '帐号或密码错误',
    'E2601': '您使用的不是专用客户端,IPOE-PPPoE混杂模式请联系管理员重新打包客户端程序',
    'E2602': '您还没有绑定手机号或绑定的非联通手机号码',
    'E2606': '用户被禁用',
    'E2607': '接口被禁用',
    'E2611': '您当前使用的设备非该账号绑定设备 请绑定或使用绑定的设备登入',
    'E2613': 'NAS PORT绑定错误',
    'E2614': 'MAC地址绑定错误',
    'E2615': 'IP地址绑定错误',
    'E2616': '用户已欠费',
    'E2620': '已经在线了',
    'E2621': '已经达到授权人数',
    'E2806': '找不到符合条件的产品',
    'E2807': '找不到符合条件的计费策略',
    'E2808': '找不到符合条件的控制策略',
    'E2833': 'IP不在DHCP表中，需要重新拿地址。',
    'E2840': '校内地址不允许访问外网',
    'E2841': 'IP地址绑定错误',
    'E2842': 'IP地址无需认证可直接上网',
    'E2843': 'IP地址不在IP表中',
    'E2844': 'IP地址在黑名单中',
    'E2901': '第三方认证接口返回的错误信息',
    'E6500': '认证程序未启动',
    'E6501': '用户名输入错误',
    'E6502': '注销时发生错误，或没有帐号在线',
    'E6503': '您的账号不在线上',
    'E6504': '注销成功，请等1分钟后登录',
    'E6505': '您的MAC地址不正确',
    'E6506': '用户名或密码错误，请重新输入',
    'E6507': '您无须认证，可直接上网',
    'E6508': '您已欠费，请尽快充值',
    'E6509': '您的资料已被修改正在等待同步，请2钟分后再试。如果您的帐号允许多个用户上线，请到WEB登录页面注销',
    'E6510': '您的帐号已经被删除',
    'E6511': 'IP已存在，请稍后再试',
    'E6512': '在线用户已满，请稍后再试',
    'E6513': '正在注销在线账号，请重新连接',
    'E6514': '你的IP地址和认证地址不附，可能是经过小路由器登录的',
    'E6515': '系统已禁止客户端登录，请使用WEB方式登录',
    'E6516': '您的流量已用尽',
    'E6517': '您的时长已用尽',
    'E6518': '您的IP地址不合法，可能是：一、与绑的IP地址附；二、IP不允许在当前区域登录',
    'E6519': '当前时段不允许连接',
    'E6520': '抱歉，您的帐号已禁用',
    'E6521': '您的IPv6地址不正确，请重新配置IPv6地址',
    'E6522': '客户端时间不正确，请先同步时间（或者是调用方传送的时间格式不正确，不是时间戳；客户端和服务器之间时差超过2小时，括号里面内容不要提示给客户）',
    'E6523': '认证服务无响应',
    'E6524': '计费系统尚未授权，目前还不能使用',
    'E6525': '后台服务器无响应;请联系管理员检查后台服务运行状态',
    'E6526': '您的IP已经在线;可以直接上网;或者先注销再重新认证',
    'E6527': '当前设备不在线',
    'E6528': '您已经被服务器强制下线',
    'E6529': '身份验证失败，但不返回错误消息',
    'ChallengeExpireError': 'Challenge时间戳错误',
    'SignError': '签名错误',
    'NotOnlineError': '当前设备不在线',
    'VcodeError': '验证码错误',
    'SpeedLimitError': '认证请求太频繁，请稍后10s重试',
    'SrunPortalServerError': 'Portal服务请求错误',
    'AuthResaultTimeoutErr': 'Portal服务请求超时',
    'IpAlreadyOnlineError': '本机IP已经使用其他账号登陆在线了',
    'MemoryDbError': 'SRun认证服务(srun_portal_server)无响应',
    'GetVerifyCode': '获取验证码',
    'S': '秒',
    'CasUsernameIsEmpty': '获取CAS用户名失败',
    'ProvisionalReleaseFail': '临时放行失败',
    'INFOFailedBASRespondTimeout': 'BAS无响应',
    'LogoutOK': 'DM下线成功',
    'SendVerifyCodeOK': '验证码发送成功',
    'PhoneNumberError': '手机号错误',
    'IsEvokingWeChat': '正在唤起微信...',
    'Info': '信息',
    'OK': '确认',
    'CheckServerTimestamp': '检查服务器时间',
    'TimestampError': '时间戳错误',
    'TypeError': '加密类型错误',
    'VerifyCodeError': '验证码错误',
    'ACIDIsRequired': '缺少ACID',
    'TypeIsEmptyOrError': '微信请求类型为空或错误',
    'ACIDIsEmpty': '缺少ACID',
    'BSSIDIsEmpty': '缺少BSSID',
    'MACIsEmpty': '缺少MAC',
    'TokenIsEmpty': '缺少Token',
    'WeChatOptionNotFound': '未找到微信配置',
    'CreateVisitorError': '创建访客失败',
    'NoResponseDataError': '无响应数据',
    'VcodeTooOftenError': '两次间隔时间太短',
    'Wait': '请稍等...',
    'YouAreNotOnline': '该设备不在线',
    'NasTypeNotFound': 'NAS设备不存在',
    'UserMustModifyPassword': '您的密码比较简单或已长时间未修改，存在安全隐患，请登录自服务重置您的密码',
    'AuthInfoError': '刷新页面后再次登录',
    'TokenError': '验证码发送失败',
    'MissingRequiredParametersError': '登录失败，请联系网络管理员',
    'NoAcidError': '网络设备出问题，请稍候',
    'OtpServerError': '身份验证器服务故障',
    'OtpCodeCheckError': '口令验证失败',
    'OtpCodeHasBeenUsed': '动态码已被使用',
    'E2901: (Third party 1)bind_user2: ldap_bind error': '账号或密码错误',
    'E2901: (Third party 1)ldap_first_entry error': '账号或密码错误',
    'CHALLENGE failed, BAS respond timeout.': '网络连接超时，请稍后重试',
    'INFO Error锛宔rr_code=2': '设备不在认证范围内'
}

__all__ = ['SrunOperation', 'ecode_explain']


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


class SrunEnc:
    # 以下是srun自家的加密算法
    @classmethod
    def get_xencode(cls, msg, key):
        if msg == '':
            return ''
        pwd = cls._sencode(msg, True)
        pwdk = cls._sencode(key, False)
        if len(pwdk) < 4:
            pwdk = pwdk + [0] * (4 - len(pwdk))
        _n = len(pwd) - 1
        z = pwd[_n]
        c = 0x86014019 | 0x183639A0
        q = math.floor(6 + 52 / (_n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < _n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p = p + 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[_n] = pwd[_n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[_n]
            q = q - 1
        return cls._lencode(pwd, False)

    @classmethod
    def _sencode(cls, msg, key):
        length = len(msg)
        pwd = []
        for i in range(0, length, 4):
            pwd.append(
                cls._ordat(msg, i) | cls._ordat(msg, i + 1) << 8 | cls._ordat(msg, i + 2) << 16
                | cls._ordat(msg, i + 3) << 24)
        if key:
            pwd.append(length)
        return pwd

    @classmethod
    def _ordat(cls, msg, idx):
        if len(msg) > idx:
            return ord(msg[idx])
        return 0

    @classmethod
    def _lencode(cls, msg, key):
        length = len(msg)
        ll = (length - 1) << 2
        if key:
            m = msg[length - 1]
            if m < ll - 3 or m > ll:
                return
            ll = m
        for i in range(0, length):
            msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
        if key:
            return ''.join(msg)[0:ll]
        return ''.join(msg)

    # 以下是srun魔改的base64
    _PADCHAR = '='
    _ALPHA = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'

    @classmethod
    def get_base64(cls, s):
        x = []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (cls._getbyte(s, i) << 16) | (cls._getbyte(s, i + 1) << 8) | cls._getbyte(s, i + 2)
            x.append(cls._ALPHA[(b10 >> 18)])
            x.append(cls._ALPHA[((b10 >> 12) & 63)])
            x.append(cls._ALPHA[((b10 >> 6) & 63)])
            x.append(cls._ALPHA[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = cls._getbyte(s, i) << 16
            x.append(cls._ALPHA[(b10 >> 18)] + cls._ALPHA[((b10 >> 12) & 63)] + cls._PADCHAR + cls._PADCHAR)
        else:
            b10 = (cls._getbyte(s, i) << 16) | (cls._getbyte(s, i + 1) << 8)
            x.append(cls._ALPHA[(b10 >> 18)] + cls._ALPHA[((b10 >> 12) & 63)] +
                     cls._ALPHA[((b10 >> 6) & 63)] + cls._PADCHAR)
        return ''.join(x)

    @classmethod
    def _getbyte(cls, s, i):
        if i >= len(s):
            return 0
        x = ord(s[i])
        if x > 255:
            print('INVALID_CHARACTER_ERR: DOM Exception 5')
            exit(0)
        return x


class SrunOperation:
    def __init__(self, auth_server='192.168.0.170',
                 ac_id='2',
                 callback='AkagiYui',
                 _name='AkagiYuiForTest',
                 _type='1',
                 n='200'):
        self.callback = callback

        self.url_self_service = 'http://' + auth_server + ':8800/site/sso?data='
        auth_server = 'http://' + auth_server + '/cgi-bin/'
        self.url_get_challenge = auth_server + 'get_challenge'
        self.url_srun_portal = auth_server + 'srun_portal'
        self.url_rad_user_info = auth_server + 'rad_user_info'
        self._type = _type
        self.ac_id = ac_id
        self._name = _name
        self.n = n

    def _get_token_and_ip(self, username):
        params_get_token = {
            'callback': self.callback,
            'username': username,
            '_': int(time.time() * 1000)
        }

        try:
            res_get_token = requests.get(self.url_get_challenge, params=params_get_token)
        except Exception as e:
            raise e
            # raise Exception('get_token Internet Error')

        result = re.search(r'{.+}', res_get_token.text)
        result = json.loads(result.group())
        # result = res_get_token.json()

        if result['error'] == 'speed_limit_error':
            raise Exception('get_token speed_limit_error')

        return result['challenge'], result['client_ip']

    def current_info(self):
        params_get_token = {
            'callback': self.callback,
            '_': int(time.time() * 1000)
        }

        try:
            res_get_token = requests.get(self.url_rad_user_info, params=params_get_token)
        except Exception as e:
            raise e

        result = re.search(r'{.+}', res_get_token.text)
        result = json.loads(result.group())
        return result

    def login(self, username, password):
        token, ip = self._get_token_and_ip(username)
        hmd5 = get_md5(password, token)

        info = {
            'username': username,
            'password': password,
            'ip': ip,
            'acid': self.ac_id,
            'enc_ver': 'srun_bx1'
        }
        info = re.sub("'", '"', str(info))  # 单引号转双引号
        info = re.sub(' ', '', info)  # 删所有空
        info = SrunEnc.get_xencode(info, token)  # srun自家加密
        info = SrunEnc.get_base64(info)  # srun魔改base64加密
        info = '{SRBX1}' + info

        chksum = token + username
        chksum += token + hmd5
        chksum += token + self.ac_id
        chksum += token + ip
        chksum += token + self.n
        chksum += token + self._type
        chksum += token + info
        chksum = get_sha1(chksum)

        params_srun_portal = {
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
            'os': os,
            'name': self._name,
            'double_stack': '0',
            '_': int(time.time() * 1000)
        }

        try:
            res_srun_portal = requests.get(self.url_srun_portal, params=params_srun_portal)
        except Exception as e:
            raise e
            # raise Exception('login Internet Error')

        # result = res_srun_portal.json()
        result = re.search(r'{.+}', res_srun_portal.text)
        result = json.loads(result.group())

        if result['error'] == 'speed_limit_error':
            raise Exception('login speed_limit_error')

        return result

    def logout(self, username):
        params_srun_portal = {
            'callback': self.callback,
            'action': 'logout',
            'username': username,
            '_': int(time.time() * 1000)
        }

        try:
            res_srun_portal = requests.get(self.url_srun_portal, params=params_srun_portal)
        except Exception as e:
            raise e
            # raise Exception('logout Internet Error')

        result = re.search(r'{.+}', res_srun_portal.text)
        result = json.loads(result.group())
        # result = res_srun_portal.json()

        return result

    # 必须本机已登录
    def get_self_service(self, username):
        url = self.url_self_service + base64.b64encode(f'{username}:{username}'.encode()).decode()
        try:
            res_srun_portal = requests.get(url)
        except Exception as e:
            raise e
        return res_srun_portal

    # 必须本机已登录
    def get_name(self, username):
        result = self.get_self_service(username).text
        result = re.search('姓名</label>(.*)</li>', result)
        return result.group(1) if result is not None else None


if __name__ == '__main__':
    account = '16612345678'
    so = SrunOperation()

    result = so.current_info()
    if result['error'] == 'ok':
        print(result['user_name'], '已经在线')
        exit(0)

    result = so.login(account, '123456')
    if result['ecode'] == 0:
        print('登录成功', so.get_name(account))

        from time import sleep
        sleep(1)

        result = so.logout(account)
        if result['ecode'] == 0:
            print('下线成功')

    else:
        print('登录失败', result)
