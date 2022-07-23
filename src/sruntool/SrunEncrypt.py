# 此处内容摘自网络，忘记是哪里取的了，想起来了会补上
import math


class SrunEncrypt:
    """srun自家的加密算法"""

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
        while q > 0:
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
                p += 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[_n] = pwd[_n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[_n]
            q -= 1
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
        return ord(msg[idx]) if len(msg) > idx else 0

    @classmethod
    def _lencode(cls, msg, key):
        length = len(msg)
        ll = (length - 1) << 2
        if key:
            m = msg[length - 1]
            if m < ll - 3 or m > ll:
                return
            ll = m
        for i in range(length):
            msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
        if key:
            return ''.join(msg)[:ll]
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

