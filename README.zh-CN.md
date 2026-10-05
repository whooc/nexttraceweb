<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

</div>

# NEXTTRACE WEB

<div align="center">

**中文** | [English](README.md)

</div>

NEXTTRACE项目派生的仓库，用于实现简易的NEXTTRACE WEB API服务端

<img width="1440" alt="截屏2023-06-12 00 24 06" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/798554e2-190e-4425-9527-3a11708dafd8">
<p align="center">
  <img width="443" alt="截屏2023-06-12 00 12 57" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/1eb4b6ce-3ed9-4728-be85-fbdabc5803bd">
  <img width="721" alt="截屏2023-06-12 00 26 22" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/a0563bfc-37a8-417a-89bf-3ab87ef44d6d">
</p>




请注意，本项目使用了websocket作为通信协议，因此请在配置反代时参考仓库内的代码(本仓库提供的Docker Image 已内置 Nginx 反代)。

Inspired by PING.PE

感谢PING.PE这么多年来的坚持，让我们能够在这个时候有一个这么好的项目可以参考

## How To Use

推荐使用Docker安装
```bash
docker pull tsosc/nexttraceweb
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 使用 http://127.0.0.1:30080 访问
```
若要使用其他地址和端口，请在docker run时加入参数
```bash
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 监听127.0.0.1:30080
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 80
# 监听所有IP的80端口
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb [::1]:30080
# 监听[::1]:30080
```

**本 fork 内置了登录页，且在配置至少一个账号之前不会对外提供任何服务。** 详见下方[登录认证](#登录认证)——否则容器对所有路由都返回 `503 auth_not_configured`。

## 界面语言

界面已支持英文和简体中文。页头的语言选择器默认为 **跟随系统**，即按浏览器的 `Accept-Language` 自动选择；也可以固定为 `English` 或 `中文`。选择结果保存在 `localStorage` 的 `uiLanguage` 中。

设置抽屉里的 **地理数据语言** 是另一回事——它会直接传给 `nexttrace`，只影响地理位置数据的语言，不影响界面语言。

## 二级路径部署

静态资源、`/api/devices` 接口以及 Socket.IO 的路径都基于当前页面所在目录做相对解析，因此可以部署在二级路径下。外层反代需要**剥离路径前缀**（注意 `location` 和 `proxy_pass` 都要带结尾斜杠），并为不带结尾斜杠的地址加上跳转：

```nginx
# 放在 http 块中，$connection_upgrade 不是 nginx 内置变量：
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# 放在 server 块中，把 https://example.com/tools/nexttrace/ 映射到容器根路径：
location = /tools/nexttrace {
    return 301 /tools/nexttrace/$is_args$args;
}

location /tools/nexttrace/ {
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass http://127.0.0.1:30080/;
}
```

两处结尾斜杠都很关键。漏掉 `proxy_pass` 上的那个，后端就会收到 `/tools/nexttrace/...`，没有对应路由。那条 301 用于兜住地址栏里漏掉结尾斜杠的用户：此时浏览器会把相对引用解析到上一级目录，资源会被请求到 `/tools/assets/...`，页面会失去样式。

## 运行时说明

- 健康检查接口：`GET /healthz`
- 容器现在会在 `gunicorn` 或 `nginx` 任一核心进程退出时整体退出，便于外部 supervisor 正常拉起，而不是留下“容器还活着、服务已经死了”的假活状态。
- `nexttrace_error` 现在是结构化载荷，至少包含 `code` 和 `message`；限流/容量拒绝还会带 `retry_after_seconds`。

## 登录认证

本 fork 增加了内置登录页。默认保护所有路由：页面本身、`/api/devices`、`/healthz`，静态资源除外；Socket.IO 握手会**独立再校验一次**会话，因为 HTTP 的 `before_request` 钩子覆盖不到 Engine.IO 的升级请求。

> **失败即关闭（fail-closed）。** 没有配置任何账号时，应用会拒绝所有受保护路由并返回 `503` 与 `auth_not_configured` 正文，而不是悄悄放行匿名流量。升级后如果一路 503，说明你还没配账号——这是预期状态，不是 bug。

### 1. 生成密码哈希

密码以 PBKDF2-SHA256 哈希存储，账号表里出现明文会被直接拒绝启动。用自带的命令行工具生成，明文不用落到任何文件里：

```bash
# 本地仓库
python auth.py hash '你的密码'

# 容器内
docker exec <容器名> python /app/auth.py hash '你的密码'
```

其他子命令：`python auth.py check <用户名>`（交互式校验密码）、`python auth.py users`（列出已配置账号）。

### 2. 提供账号

两个来源，按顺序查找：

**`NTWA_USERS_FILE`** —— JSON 文件路径（挂载密钥文件，裸机部署更合适）：

```json
{
  "alice": "pbkdf2:sha256:600000$03hLeQFFx28Rdv1G$462656e5...",
  "bob": "pbkdf2:sha256:600000$Qn7Kd2mLx91Tsv4B$9b3f1a7c..."
}
```

**`NTWA_USERS`** —— 同样的 JSON 内联，适合容器环境变量：

```bash
docker run --network host -d --privileged --name ntwa \
  -e NTWA_SECRET_KEY="$(openssl rand -hex 32)" \
  -e NTWA_USERS="{\"alice\":\"pbkdf2:sha256:600000\$03hLeQ...\"}" \
  tsosc/nexttraceweb 127.0.0.1:30080
```

直接生成到环境变量里：

```bash
export NTWA_USERS="{\"alice\":\"$(python auth.py hash '你的密码')\"}"
```

账号表按密钥对待，不要提交进仓库；`.env` 与账号文件都已在 `.gitignore` 中。

### 3. 相关配置项

| 变量 | 默认值 | 说明 |
|---|---|---|
| `NTWA_SECRET_KEY` | 每进程随机 | 会话签名密钥。**生产环境必须显式配置**——否则每次重启都会让所有会话失效，且多 worker 之间无法共享会话。 |
| `NTWA_SESSION_LIFETIME_SECONDS` | `43200`（12 小时） | 登录态有效期。 |
| `NTWA_MAX_LOGIN_ATTEMPTS` | `10` | 单 IP 在统计窗口内的失败次数上限，超过后锁定。 |
| `NTWA_MIN_LOGIN_INTERVAL_SECONDS` | `0.5` | 两次尝试之间的最小间隔。 |
| `NTWA_HEALTHZ_PUBLIC` | `false` | 设为 `true` 可让 `/healthz` 免登录访问——当编排系统的探针无法携带认证信息时需要。 |
| `NTWA_SESSION_COOKIE_SECURE` | `false` | 只有外层代理终结 HTTPS 时才设为 `true`。 |

`/logout`（GET 或 POST）会清除会话并跳回登录页。

### 登录页语言

登录页在服务端、任何 JavaScript 执行之前就确定了语言：先看 `ntwa_language` cookie，再看浏览器的 `Accept-Language`，最后回落到英文。登录成功会写入该 cookie，后续访问就跟随界面语言。这套机制与页面内那个客户端语言选择器相互独立。

## 外层鉴权示例

内置登录页可以与外层网关**叠加使用**。下面是最小 Nginx Basic Auth 反代示例——注意此配置下容器仍需要自己的账号，实际是两层防护：

```nginx
server {
    listen 443 ssl http2;
    server_name trace.example.com;

    auth_basic "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_pass http://127.0.0.1:30080;
    }
}
```
