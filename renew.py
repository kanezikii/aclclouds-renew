#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import time
import base64
import requests
from datetime import datetime, timedelta, timezone
from seleniumbase import SB
from selenium.common.exceptions import ElementClickInterceptedException, WebDriverException, StaleElementReferenceException
from selenium.webdriver.common.by import By
from zoneinfo import ZoneInfo

# ===================== 基础配置 =====================
TG_CHAT_ID = os.getenv('TG_CHAT_ID') or ""
TG_BOT_TOKEN = os.getenv('TG_BOT_TOKEN') or ""
GH_PAT = os.getenv('GH_PAT') or ""
GH_OWNER = os.getenv('GH_OWNER') or ""
GH_REPO = os.getenv('GH_REPO') or ""

LOGIN_PATH = '/auth/login'
BASE_URL = 'https://dash.aclclouds.com'
LOGIN_URL = f'{BASE_URL}{LOGIN_PATH}'
PROJECTS_URL = f'{BASE_URL}/dashboard/projects'

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
    try:
        result = sb.execute_cdp_cmd("Network.getAllCookies", {})
        cookies = result.get("cookies", [])
        keep = []
        for c in cookies:
            name = c.get("name", "")
            if (name == "XSRF-TOKEN" or name.startswith("remember_web_") or
                name == "__Host-aclclouds_session" or name == "aclclouds_session" or
                name.startswith("__Host-aclclouds")):
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
            if (name == "XSRF-TOKEN" or name.startswith("remember_web_") or
                name == "__Host-aclclouds_session" or name == "aclclouds_session" or
                name.startswith("__Host-aclclouds")):
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
        else:
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
    return BASE_URL in current_url and LOGIN_PATH not in current_url

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
        sb.sleep(0.5)
        try:
            element.click()
            return True
        except Exception:
            pass
        sb.driver.execute_script('arguments[0].click();', element)
        sb.sleep(0.5)
        return True
    except Exception as e:
        print(f"{label} 点击失败: {e}")
        return False

def element_text(element):
    try:
        return element.text.strip()
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

def find_elements(root, selector):
    by = By.XPATH if selector.startswith(('/', './/')) else By.CSS_SELECTOR
    try:
        return root.find_elements(by, selector)
    except Exception:
        return []

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
        for name, value in cookies.items():
            try:
                if name.startswith("__Host-"):
                    params = {"name": name, "value": value, "url": "https://dash.aclclouds.com/", "path": "/", "secure": True}
                else:
                    params = {"name": name, "value": value, "domain": "dash.aclclouds.com", "path": "/", "secure": True}
                sb.execute_cdp_cmd("Network.setCookie", params)
                print(f"写入Cookie (CDP): {name}")
            except Exception as e:
                print(f"CDP写入失败 {name}: {e}")

        sb.open(PROJECTS_URL)
        sb.sleep(8)
        if is_logged_in(sb):
            print("✅ Cookie 登录成功")
            return True
        sb.refresh()
        sb.sleep(5)
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
    used_selector = None
    for sel in selectors:
        try:
            sb.wait_for_element_visible(sel, timeout=timeout)
            scroll_to_selector(sb, sel)
            sb.uc_click(sel)
            sb.sleep(1.5)
            used_selector = sel
            clicked = True
            print(f"{label} 已点击复选框")
            break
        except Exception:
            continue
    if not clicked:
        print(f"{label} 点击复选框失败")
        return False

    sb.sleep(3)
    if handle_captcha_challenge(sb, label, timeout=20):
        return True
    return False

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

    # 提取目标
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
    """密码登录（支持法语 Se connecter）"""
    print("开始密码登录流程...")
    if not fill_input(sb, '#username', email, '邮箱'):
        # 尝试其他选择器
        for sel in ['input[name="email"]', 'input[type="email"]', 'input[placeholder*="Email"]']:
            if fill_input(sb, sel, email, '邮箱'):
                break
    if not fill_input(sb, '#password', password, '密码'):
        for sel in ['input[name="password"]', 'input[type="password"]']:
            if fill_input(sb, sel, password, '密码'):
                break

    # 处理验证码
    captcha_ok = click_captcha_checkbox(sb, '登录验证码')
    if not captcha_ok:
        print("⚠️ 登录验证码未完成，仍尝试点击登录按钮")

    sb.sleep(1)
    login_page_url = sb.get_current_url()

    # 支持法语和英语登录按钮
    submit_selectors = [
        'button[type="submit"]',
        '//button[contains(text(), "Se connecter")]',
        '//button[contains(text(), "Sign in")]',
        '//button[contains(text(), "Log in")]',
        '//button[contains(text(), "Connexion")]',
        'div.auth-submit-btn',
        '//button[contains(@class, "btn")]',
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
        else:
            print("❌ 密码登录失败")
            return False
    except Exception as e:
        print(f"登录等待异常: {e}")
        return LOGIN_PATH not in sb.get_current_url()

# ===================== 项目与续期 =====================
def find_renew_buttons(root):
    selectors = [
        '.projects-renew-btn',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "reactivate")]',
        './/*[@role="button" and (contains(., "Renew") or contains(., "Renouveler"))]',
    ]
    buttons = []
    for sel in selectors:
        try:
            buttons.extend(find_elements(root, sel))
        except Exception:
            continue
    return unique_elements([b for b in buttons if element_text(b) or b.is_displayed()])

def find_project_cards(sb):
    candidate_selectors = [
        '.projects-card',
        '[class*="projects-card"]',
        '[class*="project"][class*="card"]',
        'article',
        '[class*="card"]',
    ]
    cards = []
    for sel in candidate_selectors:
        try:
            for card in sb.driver.find_elements(By.CSS_SELECTOR, sel):
                text = element_text(card).lower()
                if any(k in text for k in ['expire', 'expires', 'temps restant', 'renew', 'renouveler', '到期', '过期']):
                    cards.append(card)
        except Exception:
            continue
    return unique_elements(cards)

def extract_duration_like(text):
    if not text:
        return ''
    match = re.search(r'(?:expires?\s+in\s*|temps restant\s*:?\s*|剩余|还有)?\s*\d+\s*(?:d|day|days|j|天|日)\s*\d*\s*(?:h|hour|hours|小时)?', text, re.I)
    if match:
        return match.group(0).strip()
    match = re.search(r'\d+\s*(?:h|hour|hours|小时)', text, re.I)
    if match:
        return match.group(0).strip()
    return ''

def get_project_name(card, idx):
    for sel in ['.projects-card-title', 'h1', 'h2', 'h3', 'h4', '[class*="title"]', 'strong']:
        try:
            for el in card.find_elements(By.CSS_SELECTOR, sel):
                t = element_text(el)
                if t and len(t) <= 80 and 'renew' not in t.lower() and 'expire' not in t.lower():
                    return t
        except Exception:
            continue
    for line in element_text(card).splitlines():
        line = line.strip()
        if line and len(line) <= 80 and not extract_duration_like(line):
            return line
    return f"项目 #{idx}"

def get_project_expiry(card):
    text = element_text(card)
    duration = extract_duration_like(text)
    if duration:
        return duration
    match = re.search(r'\d{4}[-/]\d{1,2}[-/]\d{1,2}', text)
    if match:
        return match.group(0)
    return '未知'

def get_renew_note(card):
    text = element_text(card)
    for pattern in [r'Renewal\s+will\s+be\s+available[^\n]*', r'Le renouvellement sera disponible[^\n]*', r'可续期[^\n]*']:
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(0).strip()
    return '未到续期时间'

def get_action_button_label(button):
    text = element_text(button).lower()
    if 'reactivate' in text or 'réactiver' in text:
        return 'Reactivate'
    return 'Renew'

def wait_for_renew_result(sb, idx, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            cards = find_project_cards(sb)
            if idx <= len(cards):
                card = cards[idx-1]
                note = get_renew_note(card)
                buttons = find_renew_buttons(card)
                if note and not buttons:
                    return True, get_project_expiry(card), note
        except Exception:
            pass
        sb.sleep(1.2)
    cards = find_project_cards(sb)
    expiry = get_project_expiry(cards[idx-1]) if cards and idx <= len(cards) else '未知'
    return False, expiry, ''

def handle_renew_antibot(sb, project_name):
    try:
        if sb.is_element_visible('//div[contains(., "Anti-bot") or contains(., "Je ne suis pas un robot")]'):
            print(f"[{project_name}] 检测到续期人机验证")
            return click_captcha_checkbox(sb, '续期验证码')
    except Exception:
        pass
    return False

def build_account_summary(account_name, email, cookie_status, results):
    lines = [
        "🇫🇷 ACLClouds 自动续期汇总",
        f"账号: {account_name}",
        f"登录账户: {mask_email(email)}",
        f"🍪 Cookie状态: {cookie_status}",
        f"⏱️ 运行时间: {beijing_time_str()}",
        "",
    ]
    if not results:
        lines.append("未发现可处理的项目")
    else:
        lines.append("📋 项目结果:")
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r}")
    lines.append("")
    lines.append("✅ 本账号任务完成")
    return "\n".join(lines)

def process_account(sb, account):
    """处理单个账号，返回结果列表（不发送Telegram）"""
    name = account["name"]
    email = account["email"]
    password = account["password"]
    cookie = account["cookie"]
    secret_name = account["secret_name"]

    print(f"\n{'='*20} 开始处理账号: {name} {'='*20}")
    print(f"邮箱: {mask_email(email)}")

    results = []
    cookie_status = "未更新"
    login_success = False

    # 登录
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

    login_success = True
    print(f"账号 {name} 登录成功，更新 Cookie → {secret_name}")
    cookie_updated = save_new_cookie(sb, secret_name)
    cookie_status = "✅ 更新成功" if cookie_updated else "❌ 更新失败"

    # 进入项目页
    sb.open(PROJECTS_URL)
    sb.wait_for_ready_state_complete()
    time.sleep(4)

    cards = find_project_cards(sb)
    if not cards:
        results.append("未找到任何项目")
        return name, email, cookie_status, results

    print(f"找到 {len(cards)} 个项目")
    for idx, card in enumerate(cards, 1):
        try:
            project_name = get_project_name(card, idx)
            old_expiry = get_project_expiry(card)
            print(f"[{project_name}] 当前过期: {old_expiry}")

            # 过滤明显不是项目的卡片
            if project_name.lower() in ['ram', 'storage', 'stockage', 'expires in', 'temps restant', '未知']:
                continue
            if len(project_name) < 2:
                continue

            renew_btns = find_renew_buttons(card)
            if renew_btns:
                action = get_action_button_label(renew_btns[0])
                safe_click_element(sb, renew_btns[0], f"{project_name} {action}")
                print(f"[{project_name}] 点击 {action}")
                handle_renew_antibot(sb, project_name)
                success, new_expiry, note = wait_for_renew_result(sb, idx, timeout=25)
                if success:
                    results.append(f"✅ {project_name} 续期成功\n   原到期: {old_expiry} → 新到期: {new_expiry}")
                else:
                    results.append(f"❌ {project_name} 续期未确认\n   当前到期: {old_expiry}")
            else:
                note = get_renew_note(card)
                results.append(f"⏳ {project_name} 未到续期时间\n   当前到期: {old_expiry}")
        except Exception as e:
            results.append(f"⚠️ 项目处理异常: {e}")

    return name, email, cookie_status, results


def main():
    IS_PROXY = os.environ.get("IS_PROXY", "false").lower() == "true"
    PROXY_SERVER = os.getenv('S5_PROXY') or os.getenv('PROXY_SERVER') or "socks5://127.0.0.1:1080"

    print("=" * 50)
    print("ACLClouds 自动续期启动（多账号）")
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

    all_summaries = []  # 收集所有账号结果

    with SB(**sb_options) as sb:
        try:
            print("当前出口IP:", get_current_ip(PROXY_SERVER if IS_PROXY else ""))
            sb.set_window_size(1366, 768)

            for account in accounts:
                try:
                    name, email, cookie_status, results = process_account(sb, account)
                    all_summaries.append({
                        "name": name,
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

            # ========== 只在这里发送一条总汇总消息 ==========
            final_lines = [
                "🇫🇷 ACLClouds 自动续期总汇总",
                f"⏱️ 运行时间: {beijing_time_str()}",
                f"共处理 {len(all_summaries)} 个账号",
                ""
            ]

            for acc in all_summaries:
                final_lines.append(f"────────────")
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
