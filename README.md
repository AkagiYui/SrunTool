# SrunTool

深澜校园网工具

支持
- [x] 登录
- [x] 退出
- [x] 查询当前用户信息
- [x] 查询当前用户姓名

```python
from Srun import SrunOperation
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
```

## 开发环境

Python: 3.9.10

# 更新日志

## 0.0.1 `2022-03-20`

`A` 初始版本