# 使用钉钉免密码登录飞牛

### 准备工作：
1. 创建钉钉开放平台账号，创建一个应用，获取 `agent_id`, `client_id` 和 `client_secret` 。
    - 配置网页应用、安全设置的重定向URL、端内免登录地址。地址应当和环境变量的 BASE_URL 一致。
    - 权限管理中授权以下权限点：
        - open_app_api_base
        - qyapi_get_omp_sso_userinfo
        - qyapi_get_member
        - qyapi_hrm_read_user
        - Contact.User.Read
2. 将飞牛使用 nginx 反向代理，并添加以下 location 配置：
    ```config         
    location / {
        set $auth_redirect /auth/dingtalk/login;
        if ($request_uri ~* ^/p) {
            set $auth_redirect /auth/dingtalk/login?custom_redirect_uri=https://$http_host$request_uri;
        }
        if ($http_cookie !~* "fnos-long-token=") {   
            return 302 $auth_redirect;  
        }
        proxy_http_version 1.1;  
        proxy_set_header Upgrade $http_upgrade;  
        proxy_set_header Connection $connection_upgrade;  
        add_header X-Served-By $http_host;  
        proxy_set_header Host $http_host;  
        proxy_set_header X-Forwarded-Scheme https;  
        proxy_set_header X-Forwarded-Proto https;  
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  
        proxy_set_header X-Real-IP $remote_addr;  
        proxy_pass http://<你的飞牛NAS的IP地址>:5666;  
    }
    location /v {
        if ($http_cookie !~* "Trim-MC-token=") {   
            return 302 /v/auth/dingtalk/login;  
        }
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        add_header X-Served-By $http_host;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Scheme https;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://<你的飞牛NAS的IP地址>:5666/v;
    }
    # 阻止用户更改密码
    location /v/api/v1/user/passwd {
        return 302 /v;
    }
    location ~ ^/(v/)?auth/dingtalk/login {
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        add_header X-Served-By $http_host;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Scheme https;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://fn-dingtalk-auth:8080;
    }
    ```
3. 启动容器和 nginx 服务。
4. 在钉钉 智能人事 - 花名册 中，添加飞牛nas用户和飞牛nas密码两个字段，分别配置字段id到环境变量 `USER_FIELD_CODE` 和 `PWD_FIELD_CODE`。
5. 启动容器和nginx代理。