import logging
from typing import Literal

from fastapi import FastAPI, Request, Query
from fastapi.responses import RedirectResponse, HTMLResponse
import httpx
import uuid
import os
from colorama import Fore
from playwright.sync_api import sync_playwright


USERINFO_CACHE = {}

JUMP_PATH_WHEN_LOGIN = os.environ.get('JUMP_PATH_WHEN_LOGIN', "/")
AGENT_ID = int(os.environ.get('AGENT_ID', "0"))
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
USER_FIELD_CODE = os.environ.get('USER_FIELD_CODE')
PWD_FIELD_CODE = os.environ.get('PWD_FIELD_CODE')
REMOTE_BROWSER_WS = os.environ.get('REMOTE_BROWSER_WS', "")
REMOTE_BROWSER_CDP = os.environ.get('REMOTE_BROWSER_CDP', "")

app = FastAPI()

logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.BLUE}level={Fore.RESET}%(levelname)s {Fore.BLUE}ts={Fore.RESET}%(asctime)s {Fore.BLUE}caller={Fore.RESET}%(filename)s {Fore.BLUE}func={Fore.RESET}%(funcName)s:%(lineno)d {Fore.BLUE}msg={Fore.RESET}%(message)s',
    encoding='utf-8',
    datefmt='%Y-%m-%dT%H:%M:%S'
)


class WebBrowser:
    def __init__(self, browser: Literal["chromium", "firefox"] = "chromium", remote_browser_ws: str = REMOTE_BROWSER_WS, remote_browser_cdp: str = REMOTE_BROWSER_CDP):
        self.browser_type = browser
        self.remote_browser_ws = remote_browser_ws
        self.remote_browser_cdp = remote_browser_cdp
        self._headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"}

    def login(self, base_url, username, password):

        with (sync_playwright() as playwright):
            if self.remote_browser_ws:
                browser = playwright[self.browser_type].connect(self.remote_browser_ws)
            elif self.remote_browser_cdp:
                browser = playwright[self.browser_type].connect_over_cdp(self.remote_browser_cdp)
            else:
                browser = playwright[self.browser_type].launch(headless=True)

            browser_page = browser.new_page()
            browser_page.set_extra_http_headers(self._headers)

            browser_page.goto(base_url)
            browser_page.wait_for_selector(selector="#username", state="attached", timeout=1000)
            browser_page.locator("#username").fill(username)
            browser_page.locator("#password").fill(password)
            browser_page.locator(".semi-checkbox-inner").first.click()
            browser_page.locator(".semi-button-content").first.click()
            browser_page.wait_for_timeout(500)

            state = browser_page.context.storage_state()
            cookie_dict = {
                c['name'] : F"{c['name']}={c['value']}; domain={c['domain']}; path={c['path']}; expires={c['expires']}; httpOnly={c['httpOnly']}; secure={c['secure']}; sameSite={c['sameSite']}"
                for c in state.get("cookies", [])
            }
            local_storage_dict =  {item["name"]: item["value"] for item in next(
                (origin["localStorage"] for origin in state.get("origins", []) if origin["origin"] in base_url),[]
            )}
        return cookie_dict, local_storage_dict

web_browser = WebBrowser()

# noinspection PyPep8Naming,DuplicatedCode,SpellCheckingInspection
@app.get("/auth/dingtalk/login", response_class=HTMLResponse)
async def login(request: Request, code: str = Query(alias="code", default=None)):
    base_url = str(request.base_url).rstrip("/")
    origin_login_page = RedirectResponse(url=F"{base_url}/login")

    if not code:
        logging.info("用户正在登录...")
        redirect_uri = F'{base_url}/auth/dingtalk/login'
        return RedirectResponse(
            url=f"https://login.dingtalk.com/oauth2/auth?"
                f"redirect_uri={redirect_uri}"
                f"&response_type=code"
                f"&client_id={CLIENT_ID}"
                f"&scope=openid"
                f"&state={uuid.uuid4().hex}"
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

    if userinfo:=USERINFO_CACHE.get(unionid):
        userid = userinfo.get('userid')
    else:
        response_userid = httpx.post(
            f"https://oapi.dingtalk.com/topapi/user/getbyunionid",
            params={"access_token": app_access_token},
            json={"unionid": unionid}
        )
        userid = response_userid.json()['result']['userid']
        userinfo = httpx.post(
            f"https://oapi.dingtalk.com/topapi/v2/user/get",
            params={"access_token": app_access_token},
            json={"userid": userid}
        ).json()['result']
        USERINFO_CACHE[unionid] = userinfo

    user = userinfo.get('name')

    logging.info(f"用户{user}<{userid}>正在登录")

    try:
        feiniu_auth_info = httpx.post(
            f"https://api.dingtalk.com/v1.0/hrm/rosters/lists/query",
            headers={"x-acs-dingtalk-access-token": app_access_token},
            json={
                "userIdList": [userid],
                "fieldFilterList": [USER_FIELD_CODE, PWD_FIELD_CODE],
                "appAgentId": AGENT_ID,
                "text2SelectConvert": True
            }
        ).json()
        feiniu_auth_info = feiniu_auth_info['result'][0]['fieldDataList']
        if not feiniu_auth_info:
            raise  F"用户{user}<{userid}>没有在钉钉花名册中配置飞牛登录信息。"
        if not isinstance(feiniu_auth_info, list):
            raise  F"获取用户{user}<{userid}>的飞牛登录信息时 API 响应有误。"
    except Exception as e:
        logging.error(f"无法从钉钉花名册获取用户{user}<{userid}>的飞牛登录信息。{e}")
        return origin_login_page

    feiniu_user, feiniu_pwd = None, None
    for item in feiniu_auth_info:
        if item['fieldCode'] == USER_FIELD_CODE:
            feiniu_user = item['fieldValueList'][0]["value"]
        if item['fieldCode'] == PWD_FIELD_CODE:
            feiniu_pwd = item['fieldValueList'][0]["value"]
    if not feiniu_user or not feiniu_pwd:
        logging.error(F"用户{user}<{userid}>的用户名或密码信息为空。")
        return origin_login_page

    # 当无法取得 token 时，切换至原始登录页面。
    try:
        cookie_dict, local_storage_dict = web_browser.login(base_url, feiniu_user, feiniu_pwd)
        if cookie_dict and local_storage_dict:
            js_code = f"""
            <script>
            document.cookie = "{cookie_dict.get('fnos-token', '')}";
            document.cookie = "{cookie_dict.get('fnos-long-token', '')}";
            localStorage.setItem('i18nextLng', '{local_storage_dict.get('i18nextLng')}');
            localStorage.setItem('trim_hostname_key', '{local_storage_dict.get('trim_hostname_key')}');
            localStorage.setItem('fnos-RSAPub', '{local_storage_dict.get('fnos-RSAPub')}');
            localStorage.setItem('fnos-device', '{local_storage_dict.get('fnos-device')}');
            localStorage.setItem('fnos-Secret', '{local_storage_dict.get('fnos-Secret')}');
            setTimeout(function() {{ window.location.href = '{JUMP_PATH_WHEN_LOGIN}'; }}, 200);
            </script>
            """
            response = HTMLResponse(content=js_code, media_type="text/html")
            return response
        else:
            logging.error(F"用户 {userid} {userinfo.get('name')} 的用户名和密码信息有误或 API 故障。")
            return origin_login_page
    except Exception as e:
        logging.error(F"用户 {userid} {userinfo.get('name')} 的用户名和密码信息有误或 API 故障。{e}")
        return origin_login_page

if __name__ == "__main__":
    # 测试
    web_browser = WebBrowser(remote_browser_cdp="http://127.0.0.1:9222")
    web_browser.login("", "", "")