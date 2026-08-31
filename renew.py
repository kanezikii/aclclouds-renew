#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import time
import base64
import requests
from datetime import datetime, timedelta, timezone
from seleniumbase import SB
from selenium.webdriver.common.by import By
from zoneinfo import ZoneInfo

# ===================== 基础配置 =====================
TG_CHAT_ID = os.getenv('TG_CHAT_ID') or ""
TG_BOT_TOKEN = os.getenv('TG_BOT_TOKEN') or ""
GH_PAT = os.getenv('GH_PAT') or ""
GH_OWNER = os.getenv('GH_OWNER') or ""
GH_REPO = os.getenv('GH_REPO') or ""

LOGIN_PATH = '/auth/login'
BASE_URL = os.getenv('ACL_BASE_URL') or 'https://aclclouds.com'
DASH_URL = 'https://dash.aclclouds.com'
LOGIN_URL = f'{BASE_URL}{LOGIN_PATH}'
LOGIN_URLS = [
    f'{BASE_URL}{LOGIN_PATH}',
    f'{DASH_URL}{LOGIN_PATH}',
]
DEFAULT_SERVER_URL_1 = "https://aclclouds.com/server/ff26a127"
DEFAULT_SERVER_URL_2 = "https://aclclouds.com/server/7dd74194"


def beijing_time_str():
    try:
        return datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')


def send_telegram(message):
    if TG_BOT_TOKEN and TG_CHAT_ID:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        data = {'chat_id': TG_CHAT_ID, 'text': message}
        try:
            requests.post(url, data=data, timeout=10)
            print(f"Telegram sent: {message[:80]}...")
        except Exception as e:
            print(f"Failed to send Telegram: {e}")
    else:
        print(f"[Telegram disabled] {message}")


def get_current_ip(proxy_server: str = "") -> str:
    proxies = None
    if proxy_server:
        proxies = {"http": proxy_server, "https": proxy_server}
    try:
        response = requests.get("https://api.ip.sb/ip", proxies=proxies, timeout=15)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        return f"IP获取失败: {e}"


def mask_email(email):
    if not email or '@' not in email:
        return email or ''
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        masked_local = local[0] + '****' if local else '****'
    elif len(local) <= 4:
        masked_local = f"{local[0]}****{local[-1]}"
    else:
        masked_local = f"{local[:2]}****{local[-2:]}"
    return f"{masked_local}@{domain}"


def env_flag(name):
    val = os.getenv(name)
    return "有" if val else "无"


# ===================== Cookie 相关 =====================
def parse_cookie_string(cookie_string):
    cookies = {}
    if not cookie_string:
        return cookies
    for item in cookie_string.split(";"):
        item = item.strip()
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def build_cookie_string(cookies):
    result = []
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value:
            result.append(f"{name}={value}")
    return "; ".join(result)


def extract_acl_cookie(sb):
    keep_names = (
        "XSRF-TOKEN",
        "__Host-aclclouds_session",
        "aclclouds_session",
    )
    try:
        result = sb.execute_cdp_cmd("Network.getAllCookies", {})
        cookies = result.get("cookies", [])
        keep = []
        for c in cookies:
            name = c.get("name", "")
            if name in keep_names or name.startswith("remember_web_") or name.startswith("__Host-aclclouds"):
                keep.append({"name": name, "value": c.get("value", "")})
        if keep:
            return build_cookie_string(keep)
    except Exception as e:
        print(f"CDP获取Cookie失败: {e}")

    try:
        cookies = sb.driver.get_cookies()
        keep = []
        for c in cookies:
            name = c.get("name", "")
            if name in keep_names or name.startswith("remember_web_") or name.startswith("__Host-aclclouds"):
                keep.append(c)
        return build_cookie_string(keep)
    except Exception as e:
        print(f"driver.get_cookies失败: {e}")
        return ""


def github_encrypt_secret(public_key, secret_value):
    try:
        from nacl.public import PublicKey, SealedBox
        public_key_bytes = base64.b64decode(public_key)
        sealed_box = SealedBox(PublicKey(public_key_bytes))
        encrypted = sealed_box.encrypt(secret_value.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"加密失败: {e}")
        return None


def update_github_secret(secret_name, secret_value):
    if not (GH_PAT and GH_OWNER and GH_REPO):
        print("缺少 GH_PAT / GH_OWNER / GH_REPO，跳过 Secret 更新")
        return False
    headers = {
        "Authorization": f"Bearer {GH_PAT}",
        "Accept": "application/vnd.github+json"
    }
    try:
        r = requests.get(
            f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/public-key",
            headers=headers, timeout=15
        )
        r.raise_for_status()
        key_data = r.json()
        encrypted_value = github_encrypt_secret(key_data["key"], secret_value)
        if not encrypted_value:
            return False
        result = requests.put(
            f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/{secret_name}",
            headers=headers,
            json={"encrypted_value": encrypted_value, "key_id": key_data["key_id"]},
            timeout=15,
        )
        if result.status_code in [201, 204]:
            print(f"✅ Github Secret [{secret_name}] 更新成功")
            return True
        print(f"Github Secret 更新返回状态码: {result.status_code}")
    except Exception as e:
        print(f"Github更新异常: {e}")
    return False


def save_new_cookie(sb, secret_name):
    try:
        cookie = extract_acl_cookie(sb)
        if not cookie:
            print("⚠️ 未能提取到有效Cookie，跳过更新")
            return False
        print("最新Cookie:")
        print(cookie[:180] + "..." if len(cookie) > 180 else cookie)
        return update_github_secret(secret_name, cookie)
    except Exception as e:
        print(f"保存Cookie时发生异常: {e}")
        return False


# ===================== 工具函数 =====================
def is_logged_in(sb):
    current_url = sb.get_current_url()
    return ('aclclouds.com' in current_url) and (LOGIN_PATH not in current_url)


def wait_for_url_change(sb, original_url, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if sb.get_current_url() != original_url:
            return True
        sb.sleep(0.5)
    raise Exception(f"等待 URL 变化超时 ({timeout}秒)")


def scroll_to_selector(sb, selector):
    try:
        sb.scroll_to(selector)
        sb.sleep(0.2)
    except Exception:
        pass


def safe_click_element(sb, element, label=""):
    try:
        sb.driver.execute_script(
            'arguments[0].scrollIntoView({block: "center", inline: "center"});',
            element,
        )
        sb.sleep(0.4)
        try:
            element.click()
            return True
        except Exception:
            pass
        sb.driver.execute_script('arguments[0].click();', element)
        sb.sleep(0.4)
        return True
    except Exception as e:
        print(f"{label} 点击失败: {e}")
        return False


def element_text(element):
    try:
        return (element.text or "").strip()
    except Exception:
        return ''


def unique_elements(elements):
    unique, seen = [], set()
    for element in elements:
        eid = getattr(element, 'id', None)
        if eid and eid in seen:
            continue
        if eid:
            seen.add(eid)
        unique.append(element)
    return unique


def reset_browser_session(sb):
    """切换账号前清掉上一账号登录态。"""
    try:
        sb.driver.delete_all_cookies()
    except Exception:
        pass
    try:
        sb.open("about:blank")
        sb.sleep(1)
    except Exception:
        pass


# ===================== 登录相关 =====================
def login_by_cookie(sb, cookie_str):
    if not cookie_str:
        print("没有 Cookie，跳过 Cookie 登录")
        return False
    print("尝试 Cookie 登录...")
    try:
        sb.uc_open_with_reconnect(LOGIN_URLS[0], reconnect_time=5)
        sb.sleep(2)
        sb.driver.delete_all_cookies()
        sb.sleep(1)

        cookies = parse_cookie_string(cookie_str)
        print(f"准备写入 {len(cookies)} 个Cookie")
        domains = ["aclclouds.com", "dash.aclclouds.com"]
        for name, value in cookies.items():
            for domain in domains:
                try:
                    if name.startswith("__Host-"):
                        params = {
                            "name": name,
                            "value": value,
                            "url": f"https://{domain}/",
                            "path": "/",
                            "secure": True
                        }
                    else:
                        params = {
                            "name": name,
                            "value": value,
                            "domain": domain,
                            "path": "/",
                            "secure": True
                        }
                    sb.execute_cdp_cmd("Network.setCookie", params)
                    print(f"写入Cookie (CDP): {name} @ {domain}")
                except Exception as e:
                    print(f"CDP写入失败 {name}@{domain}: {e}")

        sb.open(f"{BASE_URL}/dashboard")
        sb.sleep(6)
        if is_logged_in(sb) and LOGIN_PATH not in sb.get_current_url():
            print("✅ Cookie 登录成功")
            return True
        sb.refresh()
        sb.sleep(4)
        if is_logged_in(sb) and LOGIN_PATH not in sb.get_current_url():
            print("✅ Cookie 登录成功（刷新后）")
            return True
        print("Cookie 登录失败")
        return False
    except Exception as e:
        print(f"Cookie 登录异常: {e}")
        return False


def js_set_input_value(sb, selector, value):
    sb.execute_script('''
        const el = document.querySelector(arguments[0]);
        if (!el) return false;
        el.focus();
        el.value = arguments[1];
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        el.dispatchEvent(new Event('blur', { bubbles: true }));
        return true;
    ''', selector, value)


def fill_input(sb, selector, value, label, timeout=15):
    try:
        sb.wait_for_element_visible(selector, timeout=timeout)
        scroll_to_selector(sb, selector)
        sb.click(selector)
        sb.clear(selector)
        sb.type(selector, value)
        entered = sb.get_value(selector)
        if entered != value:
            js_set_input_value(sb, selector, value)
        return True
    except Exception as e:
        print(f"填写{label}失败: {e}")
        return False


def click_captcha_checkbox(sb, label='验证码', timeout=10):
    selectors = [
        'div.auth-captcha-inner[role="checkbox"]',
        '//div[contains(., "Je ne suis pas un robot")]//*[@role="checkbox"]',
        '//div[contains(., "I am not a robot")]//*[@role="checkbox"]',
        '//div[contains(., "Anti-bot")]//*[@role="checkbox"]',
        'div.auth-captcha-checkbox',
    ]
    clicked = False
    for sel in selectors:
        try:
            sb.wait_for_element_visible(sel, timeout=timeout)
            scroll_to_selector(sb, sel)
            sb.uc_click(sel)
            sb.sleep(1.5)
            clicked = True
            print(f"{label} 已点击复选框")
            break
        except Exception:
            continue
    if not clicked:
        print(f"{label} 点击复选框失败")
        return False
    sb.sleep(3)
    return handle_captcha_challenge(sb, label, timeout=20)


def handle_captcha_challenge(sb, label='验证码', timeout=20):
    start = time.time()
    challenge_selectors = [
        '.auth-captcha-challenge',
        '//*[contains(@class, "captcha") and contains(@class, "challenge")]',
        '//*[contains(@aria-label, "Click on ") or contains(@aria-label, "Select ")]',
    ]

    def get_challenge():
        for sel in challenge_selectors:
            try:
                if sel.startswith('/'):
                    for el in sb.driver.find_elements(By.XPATH, sel):
                        if el.is_displayed():
                            return el
                else:
                    for el in sb.driver.find_elements(By.CSS_SELECTOR, sel):
                        if el.is_displayed():
                            return el
            except Exception:
                continue
        return None

    challenge = None
    while time.time() - start < 8:
        challenge = get_challenge()
        if challenge:
            print(f"{label} 检测到图形验证码挑战")
            break
        try:
            cb = sb.driver.find_element(By.CSS_SELECTOR, 'div.auth-captcha-inner[role="checkbox"]')
            if cb.get_attribute('aria-checked') == 'true':
                print(f"{label} 验证已通过")
                return True
        except Exception:
            pass
        sb.sleep(0.4)

    if not challenge:
        return True

    target = ''
    try:
        prompt = challenge.find_element(By.CSS_SELECTOR, '.auth-captcha-prompt strong')
        target = prompt.text.strip()
    except Exception:
        pass
    if not target:
        aria = challenge.get_attribute('aria-label') or ''
        if 'Click on ' in aria:
            target = aria.split('Click on ')[-1].strip()
    print(f"{label} 目标文本: {target or '未识别'}")

    def get_options(ch):
        for sel in ['button.auth-captcha-option', '.auth-captcha-option', 'button']:
            try:
                opts = ch.find_elements(By.CSS_SELECTOR, sel)
                visible = [o for o in opts if o.is_displayed()]
                if visible:
                    return visible
            except Exception:
                continue
        return []

    for attempt in range(8):
        challenge = get_challenge()
        if not challenge:
            print(f"{label} 挑战已消失，验证完成")
            return True
        options = get_options(challenge)
        if not options:
            sb.sleep(0.8)
            continue

        candidate = None
        if target:
            for opt in options:
                txt = (opt.text or '').strip().lower()
                if target.lower() in txt:
                    candidate = opt
                    break
        if not candidate and options:
            candidate = options[0]

        print(f"{label} 点击选项 #{attempt+1} (目标: {target}) ...")
        if target:
            js_result = sb.execute_script('''
                const target = (arguments[0] || "").toLowerCase();
                const buttons = document.querySelectorAll("button.auth-captcha-option, .auth-captcha-option");
                for (const btn of buttons) {
                    const text = (btn.innerText || btn.textContent || "").trim().toLowerCase();
                    if (text && (text === target || text.includes(target) || target.includes(text))) {
                        btn.scrollIntoView({block: "center"});
                        btn.click();
                        return "clicked:" + text;
                    }
                }
                return "not-found:" + buttons.length;
            ''', target)
            print(f"{label} JS匹配结果: {js_result}")
            if not str(js_result).startswith("clicked:") and candidate:
                safe_click_element(sb, candidate, label)
        elif candidate:
            safe_click_element(sb, candidate, label)
        sb.sleep(2)

        try:
            cb = sb.driver.find_element(By.CSS_SELECTOR, 'div.auth-captcha-inner[role="checkbox"]')
            if cb.get_attribute('aria-checked') == 'true':
                print(f"{label} 验证通过")
                return True
        except Exception:
            pass
        if not get_challenge():
            return True
    print(f"{label} 验证失败")
    return False


def login(sb, email, password):
    print("开始密码登录流程...")
    if not fill_input(sb, '#username', email, '邮箱'):
        for sel in ['input[name="email"]', 'input[type="email"]', 'input[placeholder*="Email"]']:
            if fill_input(sb, sel, email, '邮箱'):
                break
    if not fill_input(sb, '#password', password, '密码'):
        for sel in ['input[name="password"]', 'input[type="password"]']:
            if fill_input(sb, sel, password, '密码'):
                break

    captcha_ok = click_captcha_checkbox(sb, '登录验证码')
    if not captcha_ok:
        print("⚠️ 登录验证码未完成，仍尝试点击登录按钮")

    sb.sleep(1)
    login_page_url = sb.get_current_url()
    submit_selectors = [
        'button[type="submit"]',
        '//button[contains(text(), "Se connecter")]',
        '//button[contains(text(), "Sign in")]',
        '//button[contains(text(), "Log in")]',
        '//button[contains(text(), "Connexion")]',
        'div.auth-submit-btn',
    ]

    clicked = False
    for sel in submit_selectors:
        try:
            if sb.is_element_visible(sel):
                sb.click(sel)
                print(f"已点击登录按钮: {sel}")
                clicked = True
                break
        except Exception:
            continue

    if not clicked:
        print("使用 JS 强制点击登录按钮")
        sb.execute_script('''
            const btns = document.querySelectorAll('button, div[role="button"]');
            for (let b of btns) {
                const t = (b.innerText || "").toLowerCase();
                if (t.includes("se connecter") || t.includes("sign in") || t.includes("log in") || t.includes("connexion")) {
                    b.click();
                    return true;
                }
            }
            return false;
        ''')

    try:
        wait_for_url_change(sb, login_page_url, timeout=25)
        if LOGIN_PATH not in sb.get_current_url():
            print("✅ 密码登录成功！")
            return True
        print("❌ 密码登录失败")
        return False
    except Exception as e:
        print(f"登录等待异常: {e}")
        return LOGIN_PATH not in sb.get_current_url()


# ===================== 服务页读取与续期 =====================
def find_renew_buttons(sb):
    xpaths = [
        '//button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        '//button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
        '//a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        '//a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
    ]
    buttons = []
    for xp in xpaths:
        try:
            buttons.extend(sb.driver.find_elements(By.XPATH, xp))
        except Exception:
            continue
    visible = []
    for btn in unique_elements(buttons):
        try:
            if not btn.is_displayed():
                continue
            txt = element_text(btn).lower()
            if txt in ('renew', 'renouveler') or txt.startswith('renew') or txt.startswith('renouveler'):
                visible.append(btn)
        except Exception:
            continue
    return visible


def page_body(sb):
    try:
        return sb.driver.find_element(By.TAG_NAME, 'body').text
    except Exception:
        return ""


def is_error_page(body):
    low = (body or "").lower()
    return any(k in low for k in [
        "something went wrong",
        "does not exist on this server",
        "requested resource does not exist",
    ])


def is_valid_service_page(body):
    if not body or is_error_page(body):
        return False
    low = body.lower()
    return any(k in low for k in [
        "time remaining", "temps restant", "expires in",
        "start", "restart", "stop", "free plan", "online", "offline"
    ])


def open_dashboard_session(sb):
    for url in [f"{BASE_URL}/dashboard", f"{DASH_URL}/dashboard"]:
        try:
            print(f"打开 Dashboard: {url}")
            sb.open(url)
            sb.wait_for_ready_state_complete()
            sb.sleep(4)
            body = page_body(sb)
            print(f"Dashboard URL: {sb.get_current_url()}")
            if not is_error_page(body) and ("welcome" in body.lower() or "dashboard" in body.lower() or "my services" in body.lower()):
                return True
        except Exception as e:
            print(f"打开 Dashboard 失败: {e}")
    return False


def click_dashboard_service(sb, server_url):
    sid = ""
    m = re.search(r"/server/([A-Za-z0-9_-]+)", server_url or "")
    if m:
        sid = m.group(1)
    if not sid:
        return False
    try:
        links = sb.driver.find_elements(By.XPATH, f'//a[contains(@href, "{sid}")]')
        for el in links:
            if el.is_displayed():
                print(f"点击 Dashboard 中的服务入口: {sid}")
                safe_click_element(sb, el, f"服务入口 {sid}")
                sb.sleep(5)
                return is_valid_service_page(page_body(sb))
    except Exception as e:
        print(f"点击服务入口失败: {e}")
    return False


def find_server_links(sb):
    try:
        return unique_elements(sb.driver.find_elements(By.XPATH, '//a[contains(@href, "/server/")]'))
    except Exception:
        return []


def open_service_page(sb, server_url):
    open_dashboard_session(sb)

    if click_dashboard_service(sb, server_url):
        return True, page_body(sb)

    for link in find_server_links(sb):
        href = ""
        try:
            href = link.get_attribute("href") or ""
        except Exception:
            continue
        if "/server/" not in href:
            continue
        print(f"从 Dashboard 点击服务链接: {href}")
        if safe_click_element(sb, link, "服务链接"):
            sb.sleep(5)
            body = page_body(sb)
            print(f"进入后URL: {sb.get_current_url()}")
            print(body[:400])
            if is_valid_service_page(body):
                return True, body

    if server_url:
        print(f"最后尝试直接打开: {server_url}")
        sb.open(server_url)
        sb.wait_for_ready_state_complete()
        sb.sleep(5)
        body = page_body(sb)
        print(body[:400])
        if is_valid_service_page(body):
            return True, body

    return False, page_body(sb)


def read_service_info(sb):
    body = page_body(sb)
    remaining = "未知"
    try:
        els = sb.driver.find_elements(
            By.XPATH,
            '//*[contains(text(), "Time remaining") or contains(text(), "Temps restant") or contains(text(), "Expires in")]'
        )
        for el in els:
            txt = element_text(el)
            m = re.search(r'(?:Time remaining|Temps restant|Expires in)\s*:?\s*([0-9]+\s*[djh][^\n]*)', txt, re.I)
            if m:
                remaining = m.group(1).strip()
                break
    except Exception:
        pass

    if remaining == "未知":
        for p in [
            r'Time remaining\s*:?\s*([0-9]+\s*[djh][^\n]*)',
            r'Temps restant\s*:?\s*([0-9]+\s*[djh][^\n]*)',
            r'Expires in\s*:?\s*([0-9]+\s*[djh][^\n]*)',
        ]:
            m = re.search(p, body, re.I)
            if m:
                remaining = m.group(1).strip()
                break

    name = "未知服务"
    for sel in ['h1.server-name', '.server-name']:
        try:
            for el in sb.driver.find_elements(By.CSS_SELECTOR, sel):
                t = element_text(el)
                if t and 1 <= len(t) <= 40:
                    name = t
                    break
            if name != "未知服务":
                break
        except Exception:
            continue
    return name, remaining, body


def handle_renew_antibot(sb, project_name):
    print(f"[{project_name}] 检查是否出现续期图形验证码...")
    sb.sleep(2.5)
    has_captcha = False
    check_selectors = [
        'div.auth-captcha-inner[role="checkbox"]',
        '//div[contains(., "Je ne suis pas un robot")]',
        '//div[contains(., "I am not a robot")]',
        '//div[contains(., "Anti-bot confirmation")]',
        '//div[contains(., "Confirm you are human")]',
        '.auth-captcha-challenge',
    ]
    for sel in check_selectors:
        try:
            if sb.is_element_visible(sel):
                has_captcha = True
                break
        except Exception:
            continue
    if not has_captcha:
        print(f"[{project_name}] 未检测到验证码弹窗")
        return False
    print(f"[{project_name}] 开始执行完整图形验证码流程...")
    success = click_captcha_checkbox(sb, label=f"续期验证码-{project_name}", timeout=12)
    print(f"[{project_name}] 续期验证码{'通过' if success else '未通过'}")
    sb.sleep(2)
    return success


def process_account(sb, account):
    email = account["email"]
    password = account["password"]
    cookie = account["cookie"]
    secret_name = account["secret_name"]
    server_url = account["server_url"]

    print(f"\n{'='*20} 开始处理服务页: {server_url} {'='*20}")
    print(f"邮箱配置: {'有' if email else '无'} / 密码配置: {'有' if password else '无'} / Cookie配置: {'有' if cookie else '无'}")

    service_name = "未知服务"
    cookie_status = "未更新"

    reset_browser_session(sb)

    logged_in = False
    if cookie:
        logged_in = login_by_cookie(sb, cookie)

    if not logged_in:
        if not email or not password:
            missing = []
            if not cookie:
                missing.append("Cookie")
            if not email:
                missing.append("EMAIL")
            if not password:
                missing.append("PASSWORD")
            msg = "❌ 登录失败（缺少: " + "/".join(missing) + "）"
            print(msg)
            return service_name, email, cookie_status, msg
        for login_url in LOGIN_URLS:
            print(f"尝试密码登录页面: {login_url}")
            sb.open(login_url)
            sb.wait_for_ready_state_complete()
            time.sleep(2)
            logged_in = login(sb, email, password)
            if logged_in:
                break

    if not logged_in:
        return service_name, email, cookie_status, "❌ 登录失败（Cookie + 密码均失败）"

    print(f"登录成功，更新 Cookie → {secret_name}")
    cookie_updated = save_new_cookie(sb, secret_name)
    cookie_status = "✅ 更新成功" if cookie_updated else "❌ 更新失败"

    if not server_url:
        return service_name, email, cookie_status, "❌ 未配置续期页面 SERVER_URL"

    opened, body = open_service_page(sb, server_url)
    service_name, remaining, body = read_service_info(sb)
    print(f"服务名: {service_name}")
    print(f"剩余时间: {remaining}")

    if is_error_page(body) or not opened:
        print("服务页异常，回退到 Dashboard Upcoming renewals")
        open_dashboard_session(sb)
        renew_btns = find_renew_buttons(sb)
        service_name, remaining, body = read_service_info(sb)
        if not renew_btns:
            return service_name, email, cookie_status, f"⏳ 未到续期时间\n剩余时间: {remaining}"
        clicked = safe_click_element(sb, renew_btns[0], f"{service_name} Renew")
        if not clicked:
            return service_name, email, cookie_status, f"❌ 点击 Renew 失败\n剩余时间: {remaining}"
        handle_renew_antibot(sb, service_name)
        return service_name, email, cookie_status, f"✅ 已在 Dashboard 点击 Renew\n原剩余: {remaining}"

    renew_btns = find_renew_buttons(sb)
    if not renew_btns:
        result_text = f"⏳ 未到续期时间\n剩余时间: {remaining}"
        print(f"[{service_name}] 没有 Renew 按钮，跳过")
        return service_name, email, cookie_status, result_text

    print(f"[{service_name}] 发现 Renew 按钮，开始续期")
    clicked = safe_click_element(sb, renew_btns[0], f"{service_name} Renew")
    if not clicked:
        return service_name, email, cookie_status, f"❌ 点击 Renew 失败\n剩余时间: {remaining}"

    handle_renew_antibot(sb, service_name)
    sb.sleep(3)
    sb.refresh()
    sb.sleep(4)
    new_name, new_remaining, _ = read_service_info(sb)
    if new_name and new_name != "未知服务":
        service_name = new_name
    if new_remaining != remaining and new_remaining != "未知":
        result_text = f"✅ 续期成功\n原剩余: {remaining}\n新剩余: {new_remaining}"
    elif not find_renew_buttons(sb) and new_remaining:
        result_text = f"✅ 续期完成（按钮已消失）\n剩余时间: {new_remaining}"
    else:
        result_text = f"❌ 续期未确认\n剩余时间: {new_remaining or remaining}"
    return service_name, email, cookie_status, result_text


def main():
    IS_PROXY = os.environ.get("IS_PROXY", "false").lower() == "true"
    PROXY_SERVER = os.getenv('S5_PROXY') or os.getenv('PROXY_SERVER') or "socks5://127.0.0.1:1080"

    print("=" * 50)
    print("ACLClouds 自动续期启动（按服务页）")
    print("运行时间:", beijing_time_str())
    print("=" * 50)
    print("环境变量检查（只显示有/无，不打印内容）:")
    print(f"EMAIL={env_flag('EMAIL')} PASSWORD={env_flag('PASSWORD')} ACL_COOKIE={env_flag('ACL_COOKIE')} SERVER_URL={env_flag('SERVER_URL')}")
    print(f"EMAIL_2={env_flag('EMAIL_2')} PASSWORD_2={env_flag('PASSWORD_2')} ACL_COOKIE_2={env_flag('ACL_COOKIE_2')} SERVER_URL_2={env_flag('SERVER_URL_2')}")

    accounts = []
    if os.getenv("EMAIL") or os.getenv("ACL_COOKIE") or os.getenv("PASSWORD"):
        accounts.append({
            "email": os.getenv("EMAIL") or "",
            "password": os.getenv("PASSWORD") or "",
            "cookie": os.getenv("ACL_COOKIE") or "",
            "secret_name": "ACL_COOKIE",
            "server_url": os.getenv("SERVER_URL") or os.getenv("SERVER_URL_1") or DEFAULT_SERVER_URL_1,
        })
    if os.getenv("EMAIL_2") or os.getenv("ACL_COOKIE_2") or os.getenv("PASSWORD_2"):
        accounts.append({
            "email": os.getenv("EMAIL_2") or "",
            "password": os.getenv("PASSWORD_2") or "",
            "cookie": os.getenv("ACL_COOKIE_2") or "",
            "secret_name": "ACL_COOKIE_2",
            "server_url": os.getenv("SERVER_URL_2") or DEFAULT_SERVER_URL_2,
        })

    if not accounts:
        print("❌ 没有配置任何账号")
        send_telegram("❌ 没有配置任何账号，请检查 Secrets")
        return

    print(f"共加载 {len(accounts)} 个服务")
    for i, acc in enumerate(accounts, 1):
        print(f"服务{i} URL: {acc.get('server_url') or '(空)'} 邮箱: {mask_email(acc.get('email', ''))}")

    sb_options = {'uc': True, 'headless': False}
    if IS_PROXY:
        sb_options['proxy'] = PROXY_SERVER
        print(f"代理: {PROXY_SERVER}")

    all_summaries = []
    with SB(**sb_options) as sb:
        try:
            print("当前出口IP:", get_current_ip(PROXY_SERVER if IS_PROXY else ""))
            sb.set_window_size(1366, 768)
            for account in accounts:
                try:
                    service_name, email, cookie_status, result_text = process_account(sb, account)
                    all_summaries.append({
                        "service_name": service_name,
                        "email": email,
                        "cookie_status": cookie_status,
                        "result": result_text,
                    })
                except Exception as e:
                    print(f"服务处理异常: {e}")
                    all_summaries.append({
                        "service_name": "未知服务",
                        "email": account.get("email", ""),
                        "cookie_status": "异常",
                        "result": f"❌ 处理异常: {str(e)}",
                    })

            final_lines = [
                "💗主人，ACLClouds 自动续期汇总",
                f"⏱️ 运行时间: {beijing_time_str()}",
                f"共处理 {len(all_summaries)} 个服务",
                ""
            ]
            for acc in all_summaries:
                final_lines.append("────────────")
                final_lines.append(f"📌 服务名: {acc['service_name']}")
                final_lines.append(f"登录账户: {mask_email(acc.get('email', ''))}")
                final_lines.append(f"🍪 Cookie状态: {acc['cookie_status']}")
                final_lines.append(acc['result'])
                final_lines.append("")
            final_lines.append("母狗任务全部完成💗")
            send_telegram("\n".join(final_lines))
            print("全部服务处理完成，已发送一条总汇总")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ 脚本异常\n{str(e)}")


if __name__ == '__main__':
    main()
