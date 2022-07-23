import hashlib
import hmac


def get_sha1(text: str) -> str:
    """
    获取 sha1 值

    :param text: 欲计算的字符串
    :return: sha1 值
    """

    return hashlib.sha1(text.encode()).hexdigest()


def get_hmac_md5(text: str, key: str) -> str:
    """
    获取 hmac_md5 值

    :param text: 欲计算的字符串
    :param key: 密钥
    :return: hmac_md5 值
    """

    return hmac.new(key.encode(), text.encode(), hashlib.md5).hexdigest()
