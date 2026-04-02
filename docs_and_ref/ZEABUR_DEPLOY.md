# Zeabur 部署指南

## 环境变量

只保留两个环境变量入口：

- `WEB_PASSWORD`：必填，管理页面登录密码
- `LOG_LEVEL`：可选，用来固定日志级别，仅支持 `info`、`warn`、`error`
- `PORT`：平台注入的监听端口

除了这三个，其他设置不再走环境变量覆盖。

说明：

- 默认值是 `info`
- `info` 是当前最详细的运行日志级别
- 审计日志不受 `LOG_LEVEL` 影响

## 卷路径

推荐在 Zeabur 只挂一个卷到：

- `/data`

用途如下：

- `/data/credentials`：正常区凭证
- `/data/credentials_abnormal`：异常区凭证
- `/data/state`：状态文件、锁文件、日志、页面保存的配置文件

管理页面保存后的配置默认写到：

- `/data/state/config.yaml`

`/data` 存在时，程序会自动优先使用这组路径；本地没有 `/data` 时，才回退到项目目录下的 `./credentials`、`./credentials_abnormal`、`./state`。

## 配置来源

配置优先级保持简单：

1. `WEB_PASSWORD`
2. `LOG_LEVEL`
3. `PORT`
4. `./config.yaml`
5. `/data/state/config.yaml`
6. `./state/config.yaml`
7. 内置默认值

说明：

- `./config.yaml` 存在时，优先读取它
- `./config.yaml` 不存在且 `/data` 存在时，使用 `/data/state/config.yaml`
- `./config.yaml` 不存在且 `/data` 不存在时，使用 `./state/config.yaml`
- 管理页面改过的设置会写回当前使用中的配置文件
- `PORT` 存在时，会覆盖配置文件里的 `web.listen`

## Caddy 子路径接入

如果统一走一个 Caddy 入口，并把管理页挂到 `/refresh/`，保留这个跳转：

```caddy
redir /refresh /refresh/ 308

handle_path /refresh/* {
    reverse_proxy token-refresh.zeabur.internal:9876
}
```

页面已经改成相对路径资源和 API，请保留 `/refresh/` 末尾的 `/`。
