import asyncio
import logging
from typing import Literal
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query, Request
from fastapi.responses import RedirectResponse, HTMLResponse
import httpx
import uuid
import os
from colorama import Fore
from playwright.async_api import async_playwright
from urllib.parse import urlsplit, quote
import time

REDIRECT_QUEUE = {}
USERINFO_CACHE = {}

AGENT_ID = int(os.environ.get('AGENT_ID', "0"))
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
USER_FIELD_CODE = os.environ.get('USER_FIELD_CODE')
PWD_FIELD_CODE = os.environ.get('PWD_FIELD_CODE')
REMOTE_BROWSER_WS = os.environ.get('REMOTE_BROWSER_WS', "").rstrip("/")
REMOTE_BROWSER_CDP = os.environ.get('REMOTE_BROWSER_CDP', "").rstrip("/")
BASE_URL = os.environ.get('BASE_URL', "").rstrip("/")
LOGIN_URL = os.environ.get('LOGIN_URL', F"{BASE_URL}/login").rstrip("/")
TRIM_MC_ADMIN_USERNAME = os.environ.get('TRIM_MC_ADMIN_USERNAME', "")
TRIM_MC_ADMIN_PASSWORD = os.environ.get('TRIM_MC_ADMIN_PASSWORD', "")
TRIM_MC_USER_FIELD_CODE = os.environ.get('TRIM_MC_USER_FIELD_CODE', 'sys02-realName')
TRIM_MC_PWD_FIELD_CODE = os.environ.get('TRIM_MC_PWD_FIELD_CODE', 'sys02-certNo')

logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.BLUE}level={Fore.RESET}%(levelname)s '
           f'{Fore.BLUE}ts={Fore.RESET}%(asctime)s '
           f'{Fore.BLUE}caller={Fore.RESET}%(filename)s '
           f'{Fore.BLUE}func={Fore.RESET}%(funcName)s:%(lineno)d '
           f'{Fore.BLUE}msg={Fore.RESET}%(message)s',
    encoding='utf-8',
    datefmt='%Y-%m-%dT%H:%M:%S'
)


class WebBrowser:
    def __init__(self, browser: Literal["chromium", "firefox"] = "chromium",
                 remote_browser_ws: str = REMOTE_BROWSER_WS,
                 remote_browser_cdp: str = REMOTE_BROWSER_CDP):
        self.browser_type = browser
        self.remote_browser_ws = remote_browser_ws
        self.remote_browser_cdp = remote_browser_cdp
        self._browser = None
        self._playwright = None
        self._headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
        }
        self._lock = asyncio.Lock()

    async def initialize(self):
        """初始化浏览器连接（只创建浏览器实例，不创建页面）"""
        logging.info("正在初始化浏览器连接...")
        t = time.time()
        self._playwright = await async_playwright().start()

        if self.remote_browser_ws:
            self._browser = await self._playwright[self.browser_type].connect(self.remote_browser_ws)
        elif self.remote_browser_cdp:
            self._browser = await self._playwright[self.browser_type].connect_over_cdp(self.remote_browser_cdp)
        else:
            self._browser = await self._playwright[self.browser_type].launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-first-run',
                    '--disable-extensions',
                ]
            )
        logging.info(f"浏览器初始化完成，耗时 {time.time() - t:.2f} 秒")

    async def get_browser(self):
        """获取浏览器实例"""
        async with self._lock:
            if self._browser is None or not self._browser.is_connected():
                await self.initialize()
            return self._browser

    async def login(self, base_url, username, password):
        """
        每次登录都创建新的 Context，确保隔离性
        Context 之间完全隔离，不会共享任何状态
        """
        logging.info(f"用户 {username} 正在后台代理登录中...")
        t = time.time()

        browser = await self.get_browser()

        context = await browser.new_context(
            extra_http_headers=self._headers,
            ignore_https_errors=False,
            java_script_enabled=True,
            bypass_csp=False,
            storage_state=None,
        )

        try:
            browser_page = await context.new_page()
            logging.info(f"已为用户 {username} 创建独立的浏览器上下文，耗时{time.time() - t:.3f}s")

            login_url = LOGIN_URL or base_url + "/login"
            login_hostname = urlsplit(login_url).hostname

            await browser_page.goto(login_url)
            await browser_page.wait_for_selector(selector="#username", state="attached", timeout=5000)
            await browser_page.locator("#username").fill(username)
            await browser_page.locator("#password").fill(password)
            await browser_page.locator(".semi-checkbox-inner").first.click()
            await browser_page.locator(".semi-button-content").first.click()
            await browser_page.wait_for_timeout(500)

            state = await context.storage_state()
            cookie_dict = {
                c['name']: f"{c['name']}={c['value']}; path={c['path']}; sameSite={c['sameSite']}"
                for c in state.get("cookies", [])
            }
            local_storage_dict = {item["name"]: item["value"] for item in next(
                (origin["localStorage"] for origin in state.get("origins", []) if login_hostname in origin["origin"]),
                []
            )}

            logging.info(f"用户 {username} 登录完成，耗时{time.time() - t:.2f}s")
            return cookie_dict, local_storage_dict

        finally:
            await context.close()
            logging.info(f"已清理用户 {username} 的浏览器上下文")

    async def close(self):
        """关闭浏览器"""
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


web_browser = WebBrowser()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    管理应用生命周期
    - 启动时：初始化浏览器连接
    - 关闭时：清理浏览器资源
    """
    # 启动时执行
    logging.info("FastAPI 应用启动中...")
    try:
        await web_browser.initialize()
        logging.info("浏览器预热完成，应用启动成功")
    except Exception as e:
        logging.error(f"浏览器初始化失败: {e}")
        # 即使失败也继续运行，后续请求时会重试

    yield  # 应用运行期间

    # 关闭时执行
    logging.info("FastAPI 应用关闭中...")
    await web_browser.close()
    logging.info("应用已安全关闭")


app = FastAPI()


def get_auth_info(
        base_url, path, code, redirect_uri, state, origin_login_page,
        user_field_code, pwd_field_code, auth_cache_key
):
    user, pwd = None, None
    if not code or not state:
        logging.info("用户正在登录...")
        state = uuid.uuid4().hex
        REDIRECT_QUEUE[state] = redirect_uri
        return None, None, RedirectResponse(
            url=f"https://login.dingtalk.com/oauth2/auth?"
                f"redirect_uri={F'{base_url}{path}'}"
                f"&response_type=code"
                f"&client_id={CLIENT_ID}"
                f"&scope=openid"
                f"&state={state}"
                f"&prompt=consent",
            status_code=302
        )

    user_access_token = httpx.post(
        "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
        json={"clientId": CLIENT_ID, "clientSecret": CLIENT_SECRET, "code": code, "grantType": 'authorization_code'}
    ).json().get('accessToken')
    unionid = httpx.get(
        "https://api.dingtalk.com/v1.0/contact/users/me",
        headers={"x-acs-dingtalk-access-token": user_access_token}
    ).json().get('unionId')

    app_access_token = httpx.post(
        "https://api.dingtalk.com/v1.0/oauth2/accessToken",
        json={"appKey": CLIENT_ID, "appSecret": CLIENT_SECRET}
    ).json()['accessToken']

    t = time.time()

    if userinfo := USERINFO_CACHE.get(unionid):
        user_id = userinfo.get('userid')
        user_name = userinfo.get('name')
        logging.info(f"用户{user_name}<{user_id}>正在登录，已从缓存中获取用户信息，耗时{time.time() - t:.2f}s")
    else:
        response_userid = httpx.post(
            f"https://oapi.dingtalk.com/topapi/user/getbyunionid",
            params={"access_token": app_access_token},
            json={"unionid": unionid}
        )
        user_id = response_userid.json()['result']['userid']
        userinfo = httpx.post(
            f"https://oapi.dingtalk.com/topapi/v2/user/get",
            params={"access_token": app_access_token},
            json={"userid": user_id}
        ).json()['result']
        user_name = userinfo.get('name')
        logging.info(f"用户{user_name}<{user_id}>正在登录，已从钉钉花名册中获取用户信息，耗时{time.time() - t:.2f}s")

    t = time.time()
    if auth_info := userinfo.get(auth_cache_key):
        pass
    else:
        try:
            auth_info = httpx.post(
                f"https://api.dingtalk.com/v1.0/hrm/rosters/lists/query",
                headers={"x-acs-dingtalk-access-token": app_access_token},
                json={
                    "userIdList": [user_id],
                    "fieldFilterList": [user_field_code, pwd_field_code],
                    "appAgentId": AGENT_ID,
                    "text2SelectConvert": True
                }
            ).json()
            auth_info = auth_info['result'][0]['fieldDataList']
            if not auth_info:
                raise F"用户{user_name}<{user_id}>没有在钉钉花名册中配置登录信息。"
            if not isinstance(auth_info, list):
                raise F"获取用户{user_name}<{user_id}>的飞牛登录信息时 API 响应有误。"
            userinfo[auth_cache_key] = auth_info
            USERINFO_CACHE[unionid] = userinfo
        except Exception as e:
            logging.error(f"无法从钉钉花名册获取用户{user_name}<{user_id}>的飞牛登录信息。{e}")
            return None, None, origin_login_page

    for item in auth_info:
        if item['fieldCode'] == user_field_code:
            user = item['fieldValueList'][0]["value"]
        if item['fieldCode'] == pwd_field_code:
            pwd = item['fieldValueList'][0]["value"]
        logging.info(f"用户{user_name}<{user_id}>正在登录，获取用户密码耗时{time.time() - t:.2f}s")
    if not user or not pwd:
        logging.error(F"用户{user_name}<{user_id}>的用户名或密码信息为空。")
        return None, None, origin_login_page
    return user, pwd, None



# noinspection PyPep8Naming,DuplicatedCode,SpellCheckingInspection
@app.get("/auth/dingtalk/login", response_class=HTMLResponse)
async def login(
        code: str = Query(alias="code", default=None),
        redirect_uri: str = Query(alias="redirect_uri", default=None),
        state: str = Query(alias="state", default=None)
):
    base_url = BASE_URL
    origin_login_page = RedirectResponse(url=F"{base_url}/login")
    user, pwd, redirect = get_auth_info(
        base_url=base_url, path="/auth/dingtalk/login", code=code, redirect_uri=redirect_uri, state=state,
        origin_login_page=origin_login_page,
        user_field_code=USER_FIELD_CODE, pwd_field_code=PWD_FIELD_CODE, auth_cache_key="feiniu_auth_info"
    )
    if redirect:
        return redirect
    try:
        cookie_dict, local_storage_dict = await web_browser.login(base_url, user, pwd)
        logging.info(F"用户{user}代理登录成功，已提取鉴权信息。")
        if cookie_dict and local_storage_dict:
            redirect_uri = REDIRECT_QUEUE.pop(state, None) or BASE_URL
            js_code = f"""
            <script>
            document.cookie = "fnos-token=; expires=Thu, 01 Jan 1970 00:00:00 UTC";
            document.cookie = "fnos-long-token=; expires=Thu, 01 Jan 1970 00:00:00 UTC";
            document.cookie = "{cookie_dict.get('fnos-token', '')}";
            document.cookie = "{cookie_dict.get('fnos-long-token', '')}; max-age=2592000";
            localStorage.setItem('i18nextLng', '{local_storage_dict.get('i18nextLng')}');
            localStorage.setItem('trim_hostname_key', '{local_storage_dict.get('trim_hostname_key')}');
            localStorage.setItem('fnos-RSAPub', '{local_storage_dict.get('fnos-RSAPub').replace("\n", "\\n")}');
            localStorage.setItem('fnos-device', '{local_storage_dict.get('fnos-device')}');
            localStorage.setItem('fnos-Secret', '{local_storage_dict.get('fnos-Secret')}');
            setTimeout(function() {{ window.location.href = '{redirect_uri}'; }});
            </script>
            """
            response = HTMLResponse(content=js_code, media_type="text/html")
            return response
        else:
            logging.error(F"用户{user}的鉴权信息缺失。")
            return origin_login_page
    except Exception as e:
        logging.error(F"用户{user}的密码有误或 API 故障。{e}")
        return origin_login_page

@app.get("/v/auth/dingtalk/login", response_class=HTMLResponse)
async def v_login(
        code: str = Query(alias="code", default=None),
        redirect_url: str = Query(alias="redirect_url", default=None),
        state: str = Query(alias="state", default=None)
):
    base_url = BASE_URL
    origin_login_page = RedirectResponse(url=F"{base_url}/v/login")
    user, pwd, redirect = get_auth_info(
        base_url, "/v/auth/dingtalk/login", code, redirect_url, state, origin_login_page,
        TRIM_MC_USER_FIELD_CODE, TRIM_MC_PWD_FIELD_CODE, "trim_mc_auth_info"
    )
    if redirect:
        return redirect

    trim_mc_login_api = LOGIN_URL.replace("/login","/v/api/v1/login")
    trim_mc_create_api = LOGIN_URL.replace("/login","/v/api/v1/manager/user/create")
    trim_mc_template_api = LOGIN_URL.replace("/login","/v/api/v1/manager/template/permission")
    trim_mc_login_res = httpx.post(
        trim_mc_login_api,
        json={"username":user,"password":pwd,"app_name":"trimemedia-web"},
    ).json()
    if trim_mc_login_res.get("msg") == "Password Incorrect":
        logging.warning(F"用户{user}的密码有误或用户不存在，尝试创建用户。")
        admin_token = httpx.post(
            trim_mc_login_api,
            json={"username":TRIM_MC_ADMIN_USERNAME,"password":TRIM_MC_ADMIN_PASSWORD,"app_name":"trimemedia-web"},
        ).json().get("data", {}).get("token")
        template = httpx.get(
            trim_mc_template_api,
            headers={"cookie": f"Trim-MC-token={admin_token}", "authorization": admin_token}
        ).json().get("data")
        trim_mc_create_res = httpx.put(
            trim_mc_create_api,
            json={
                "username": user, "password": pwd, "is_admin": 0, "media_permission": template.get("media_permission"),
                "mediadb_list": [db.get("guid") for db in template.get("mediadb_list")]
            },
            headers={"cookie": f"Trim-MC-token={admin_token}", "authorization": admin_token}
        ).json()
        logging.error(trim_mc_create_res)
        if trim_mc_create_res.get("msg") == "Duplicate record":
            logging.error(F"用户{user}已经存在，无法创建用户，请联系管理员")
            return "无法登录，请联系管理员。"
        trim_mc_login_res = httpx.post(
            trim_mc_login_api,
            json={"username": user, "password": pwd, "app_name": "trimemedia-web"},
        ).json()
    trim_mc_token = trim_mc_login_res.get("data", {}).get("token")
    if trim_mc_token:
        js_code = f"""
        <script>
        document.cookie = "lastLoginUsername={quote(user)}; Path=/; sameSite=static";
        localStorage.setItem('lastLoginUsername', '"{user}"');
        document.cookie = "Trim-MC-token={trim_mc_token}; Path=/; sameSite=static";
        setTimeout(function() {{ window.location.href = '/v'; }});
        </script>
        """
        response = HTMLResponse(content=js_code, media_type="text/html")
        return response
    else:
        logging.error(F"登录失败。")
        return "无法登录，请联系管理员。"

if __name__ == "__main__":
    pass
    # 使用本地 chrome 浏览器测试
    # web_browser = WebBrowser(remote_browser_cdp="http://127.0.0.1:9222")
    # web_browser.login("", "", "")