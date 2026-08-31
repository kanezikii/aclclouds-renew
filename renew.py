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
LOGIN_URL = f'{DASH_URL}{LOGIN_PATH}'
DASHBOARD_URLS = [
    f'{BASE_URL}/dashboard',
    f'{DASH_URL}/dashboard',
    f'{BASE_URL}/dashboard/projects',
    f'{DASH_URL}/dashboard/projects',
]


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


# ===================== 登录相关 =====================
def login_by_cookie(sb, cookie_str):
    if not cookie_str:
        print("没有 Cookie，跳过 Cookie 登录")
        return False
    print("尝试 Cookie 登录...")
    try:
        sb.uc_open_with_reconnect(LOGIN_URL, reconnect_time=5)
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

        sb.open(DASHBOARD_URLS[0])
        sb.sleep(6)
        if is_logged_in(sb):
            print("✅ Cookie 登录成功")
            return True
        sb.refresh()
        sb.sleep(4)
        if is_logged_in(sb):
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
        if not candidate:
            candidate = options[0]

        print(f"{label} 点击选项 #{attempt+1} ...")
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


# ===================== Upcoming renewals =====================
def open_dashboard(sb):
    """优先打开首页 Dashboard，而不是旧的 /dashboard/projects"""
    for url in DASHBOARD_URLS:
        try:
            print(f"打开页面: {url}")
            sb.open(url)
            sb.wait_for_ready_state_complete()
            sb.sleep(4)
            body = ""
            try:
                body = sb.driver.find_element(By.TAG_NAME, 'body').text
            except Exception:
                pass
            print(f"当前URL: {sb.get_current_url()}")
            if any(k in body.lower() for k in [
                'upcoming renewals', 'renouvellement', 'renew', 'renouveler',
                'welcome', 'my services', 'mes services', 'dashboard'
            ]):
                return True
        except Exception as e:
            print(f"打开 {url} 失败: {e}")
    return False


def find_upcoming_section(sb):
    xpaths = [
        '//*[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "upcoming renewals")]',
        '//*[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouvellement")]',
        '//*[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "prochains renouvellements")]',
    ]
    for xp in xpaths:
        try:
            els = sb.driver.find_elements(By.XPATH, xp)
            for el in els:
                if not el.is_displayed():
                    continue
                # 向上找一块包含表格/按钮的容器
                container = sb.driver.execute_script('''
                    let n = arguments[0];
                    for (let i = 0; n && i < 8; i++, n = n.parentElement) {
                        const text = (n.innerText || "");
                        if (n.querySelector && (n.querySelector("table") || /renew|renouveler|manage|gérer/i.test(text))) {
                            return n;
                        }
                    }
                    return arguments[0];
                ''', el)
                return container
        except Exception:
            continue
    return None


def parse_renewal_rows(sb):
    """从 Upcoming renewals 模块读取需要续期的行。"""
    items = []
    section = find_upcoming_section(sb)

    # 优先在模块内找 Renew 按钮
    search_roots = []
    if section is not None:
        search_roots.append(section)
    search_roots.append(sb.driver)

    seen = set()
    for root in search_roots:
        buttons = []
        xpaths = [
            './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
            './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
            './/a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
            './/a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
        ]
        for xp in xpaths:
            try:
                buttons.extend(root.find_elements(By.XPATH, xp))
            except Exception:
                continue

        for btn in unique_elements(buttons):
            try:
                if not btn.is_displayed():
                    continue
                txt = element_text(btn).lower()
                if txt not in ('renew', 'renouveler') and 'renew' not in txt and 'renouveler' not in txt:
                    continue
                row = sb.driver.execute_script('''
                    let n = arguments[0];
                    for (let i = 0; n && i < 8; i++, n = n.parentElement) {
                        if (n.tagName === "TR") return n;
                        const cls = (n.className || "").toString().toLowerCase();
                        if (/row|item|card/.test(cls) && (n.innerText || "").length > 8) return n;
                    }
                    return arguments[0].parentElement;
                ''', btn)
                row_text = element_text(row)
                if row_text in seen:
                    continue
                seen.add(row_text)

                name = extract_project_name_from_row(row_text)
                expiry = extract_expiry_from_row(row_text)
                items.append({
                    "name": name,
                    "expiry": expiry,
                    "row_text": row_text[:200],
                    "button": btn,
                })
            except Exception as e:
                print(f"解析续期行失败: {e}")

        if items:
            break

    return items


def extract_project_name_from_row(text):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    skip = {
        'id', 'model', 'renewal', 'status', 'actions', 'renew', 'renouveler',
        'manage', 'gérer', 'active', 'upcoming renewals', 'available'
    }
    for line in lines:
        low = line.lower()
        if low in skip:
            continue
        if re.fullmatch(r'[0-9a-f]{6,}', low):
            continue
        if re.search(r'available|expires|temps restant|sep |jan |feb |mar |apr |may |jun |jul |aug |oct |nov |dec |\d{4}', low):
            continue
        if len(line) <= 40:
            return line
    return lines[0] if lines else "未知项目"


def extract_expiry_from_row(text):
    m = re.search(r'(Available|Expires in|Temps restant)\s*:?\s*([0-9]+\s*[djh]\s*[0-9]*\s*h?)', text, re.I)
    if m:
        return m.group(0).strip()
    m = re.search(r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}', text, re.I)
    if m:
        return m.group(0)
    m = re.search(r'\d{4}[-/]\d{1,2}[-/]\d{1,2}', text)
    if m:
        return m.group(0)
    return text.splitlines()[0][:40] if text else "未知"


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
                print(f"[{project_name}] 检测到验证码元素")
                break
        except Exception:
            continue

    if not has_captcha:
        print(f"[{project_name}] 未检测到验证码弹窗")
        return False

    print(f"[{project_name}] 开始执行完整图形验证码流程（与登录相同）...")
    success = click_captcha_checkbox(sb, label=f"续期验证码-{project_name}", timeout=12)
    print(f"[{project_name}] 续期验证码{'通过' if success else '未通过'}")
    sb.sleep(2)
    return success


def wait_renew_row_gone(sb, project_name, timeout=20):
    start = time.time()
    while time.time() - start < timeout:
        items = parse_renewal_rows(sb)
        names = [i["name"].lower() for i in items]
        if project_name.lower() not in names:
            return True
        # 若该行已没有 Renew 按钮，也视为成功
        still_has_btn = any(i["name"].lower() == project_name.lower() for i in items)
        if not still_has_btn:
            return True
        sb.sleep(1.2)
    return False


def process_account(sb, account):
    name = account["name"]
    email = account["email"]
    password = account["password"]
    cookie = account["cookie"]
    secret_name = account["secret_name"]

    print(f"\n{'='*20} 开始处理账号: {name} {'='*20}")
    print(f"邮箱: {mask_email(email)}")

    results = []
    cookie_status = "未更新"

    logged_in = False
    if cookie:
        logged_in = login_by_cookie(sb, cookie)

    if not logged_in:
        if not email or not password:
            results.append("❌ 登录失败（无 Cookie 且无邮箱密码）")
            return name, email, cookie_status, results
        sb.open(LOGIN_URL)
        sb.wait_for_ready_state_complete()
        time.sleep(2)
        logged_in = login(sb, email, password)

    if not logged_in:
        results.append("❌ 登录失败（Cookie + 密码均失败）")
        return name, email, cookie_status, results

    print(f"账号 {name} 登录成功，更新 Cookie → {secret_name}")
    cookie_updated = save_new_cookie(sb, secret_name)
    cookie_status = "✅ 更新成功" if cookie_updated else "❌ 更新失败"

    opened = open_dashboard(sb)
    if not opened:
        results.append("❌ 未能打开 Dashboard")
        return name, email, cookie_status, results

    try:
        body_preview = sb.driver.find_element(By.TAG_NAME, 'body').text[:800]
        print("页面文本摘要:")
        print(body_preview)
    except Exception:
        pass

    items = parse_renewal_rows(sb)
    print(f"Upcoming renewals 中发现 {len(items)} 个可续期项目")

    if not items:
        results.append("⏳ Upcoming renewals 为空，当前没有需要续期的项目")
        return name, email, cookie_status, results

    for item in items:
        project_name = item["name"]
        old_expiry = item["expiry"]
        print(f"[{project_name}] 当前状态: {old_expiry}")
        try:
            clicked = safe_click_element(sb, item["button"], f"{project_name} Renew")
            if not clicked:
                results.append(f"❌ {project_name} 点击 Renew 失败\n   当前: {old_expiry}")
                continue
            print(f"[{project_name}] 已点击 Renew")
            handle_renew_antibot(sb, project_name)
            sb.sleep(3)
            gone = wait_renew_row_gone(sb, project_name, timeout=18)
            if gone:
                results.append(f"✅ {project_name} 续期成功\n   原状态: {old_expiry}")
            else:
                results.append(f"❌ {project_name} 续期未确认\n   当前: {old_expiry}")
        except Exception as e:
            results.append(f"⚠️ {project_name} 处理异常: {e}")

    return name, email, cookie_status, results


def main():
    IS_PROXY = os.environ.get("IS_PROXY", "false").lower() == "true"
    PROXY_SERVER = os.getenv('S5_PROXY') or os.getenv('PROXY_SERVER') or "socks5://127.0.0.1:1080"

    print("=" * 50)
    print("ACLClouds 自动续期启动（多账号 / Upcoming renewals）")
    print("运行时间:", beijing_time_str())
    print("=" * 50)

    accounts = []
    if os.getenv("EMAIL") or os.getenv("ACL_COOKIE"):
        accounts.append({
            "name": "账号1",
            "email": os.getenv("EMAIL") or "",
            "password": os.getenv("PASSWORD") or "",
            "cookie": os.getenv("ACL_COOKIE") or "",
            "secret_name": "ACL_COOKIE",
        })
    if os.getenv("EMAIL_2") or os.getenv("ACL_COOKIE_2"):
        accounts.append({
            "name": "账号2",
            "email": os.getenv("EMAIL_2") or "",
            "password": os.getenv("PASSWORD_2") or "",
            "cookie": os.getenv("ACL_COOKIE_2") or "",
            "secret_name": "ACL_COOKIE_2",
        })

    if not accounts:
        print("❌ 没有配置任何账号")
        send_telegram("❌ 没有配置任何账号，请检查 Secrets")
        return

    print(f"共加载 {len(accounts)} 个账号")

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
                    acc_name, email, cookie_status, results = process_account(sb, account)
                    all_summaries.append({
                        "name": acc_name,
                        "email": email,
                        "cookie_status": cookie_status,
                        "results": results
                    })
                except Exception as e:
                    print(f"账号 {account['name']} 异常: {e}")
                    all_summaries.append({
                        "name": account["name"],
                        "email": account.get("email", ""),
                        "cookie_status": "异常",
                        "results": [f"❌ 处理异常: {str(e)}"]
                    })

            final_lines = [
                "🇫🇷 ACLClouds 自动续期总汇总",
                f"⏱️ 运行时间: {beijing_time_str()}",
                f"共处理 {len(all_summaries)} 个账号",
                ""
            ]
            for acc in all_summaries:
                final_lines.append("────────────")
                final_lines.append(f"📌 账号: {acc['name']}")
                final_lines.append(f"登录账户: {mask_email(acc['email'])}")
                final_lines.append(f"🍪 Cookie状态: {acc['cookie_status']}")
                final_lines.append("")
                if acc['results']:
                    for i, r in enumerate(acc['results'], 1):
                        final_lines.append(f"{i}. {r}")
                else:
                    final_lines.append("无项目结果")
                final_lines.append("")
            final_lines.append("✅ 全部账号任务完成")
            send_telegram("\n".join(final_lines))
            print("全部账号处理完成，已发送一条总汇总")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ 脚本异常\n{str(e)}")


if __name__ == '__main__':
    main()
