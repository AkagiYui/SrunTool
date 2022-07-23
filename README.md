# SrunTool

[![release](https://github.com/AkagiYui/SrunTool/workflows/release/badge.svg)](https://github.com/AkagiYui/SrunTool/actions?query=workflow%3Arelease)  [![pypi](https://img.shields.io/pypi/v/sruntool.svg)](https://pypi.org/project/sruntool/)  ![support-version](https://img.shields.io/pypi/pyversions/sruntool)  [![license](https://img.shields.io/github/license/AkagiYui/SrunTool)](https://github.com/AkagiYui/SrunTool/blob/master/LICENSE)  [![commit](https://img.shields.io/github/last-commit/AkagiYui/SrunTool)](https://github.com/AkagiYui/SrunTool/commits/master)

深澜校园网操作类，本软件包内容仅在 [NCWU](https://www.ncwu.edu.cn/) 经过测试。

支持

- [x] 登录
- [x] 退出
- [x] 查询当前用户信息
- [x] 查询当前用户姓名

## 安装

```shell
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple sruntool
```

## 使用

```python
from sruntool import SrunOperator, get_explain

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
```

## [更新日志](https://github.com/AkagiYui/SrunTool/blob/master/Changelog.md)

## 感谢

[深澜认证协议分析,python模拟登录](https://blog.csdn.net/qq_41797946/article/details/89417722)
