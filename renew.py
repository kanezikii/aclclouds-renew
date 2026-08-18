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
            print(f"Telegram sent: {message[:60]}...")
        except Exception as e:
            print(f"Failed to send Telegram: {e}")
    else:
        print(f"[Telegram disabled] {message}")

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
            if (
                name == "XSRF-TOKEN"
                or name.startswith("remember_web_")
                or name == "__Host-aclclouds_session"
                or name == "aclclouds_session"
                or name.startswith("__Host-aclclouds")
            ):
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
            if (
                name == "XSRF-TOKEN"
                or name.startswith("remember_web_")
                or name == "__Host-aclclouds_session"
                or name == "aclclouds_session"
                or name.startswith("__Host-aclclouds")
            ):
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

# ===================== 登录相关 =====================
def is_logged_in(sb):
    current_url = sb.get_current_url()
    return BASE_URL in current_url and LOGIN_PATH not in current_url

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
                    params = {
                        "name": name,
                        "value": value,
                        "url": "https://dash.aclclouds.com/",
                        "path": "/",
                        "secure": True
                    }
                else:
                    params = {
                        "name": name,
                        "value": value,
                        "domain": "dash.aclclouds.com",
                        "path": "/",
                        "secure": True
                    }
                sb.execute_cdp_cmd("Network.setCookie", params)
                print(f"写入Cookie (CDP): {name}")
            except Exception as e:
                print(f"CDP写入失败 {name}: {e}")

        print("直接访问项目页验证登录状态...")
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

def wait_for_url_change(sb, original_url, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        current_url = sb.get_current_url()
        if current_url != original_url:
            return True
        sb.sleep(0.5)
    raise Exception(f"等待 URL 变化超时 ({timeout}秒)，当前仍为: {original_url}")

def scroll_to_selector(sb, selector):
    sb.scroll_to(selector)
    sb.sleep(0.2)

def safe_click_element(sb, element, label):
    try:
        sb.driver.execute_script(
            'arguments[0].scrollIntoView({block: "center", inline: "center"});',
            element,
        )
        sb.sleep(0.5)
        try:
            element.click()
            return True
        except (ElementClickInterceptedException, WebDriverException, StaleElementReferenceException) as e:
            print(f"{label} 普通点击失败，改用 JavaScript 点击: {e}")
        sb.driver.execute_script('arguments[0].click();', element)
        sb.sleep(0.5)
        return True
    except StaleElementReferenceException:
        print(f"{label} 元素已失效，点击前需要重新定位")
        return False

def element_text(element):
    try:
        return element.text.strip()
    except Exception:
        return ''

def unique_elements(elements):
    unique = []
    seen = set()
    for element in elements:
        element_id = getattr(element, 'id', None)
        if element_id and element_id in seen:
            continue
        if element_id:
            seen.add(element_id)
        unique.append(element)
    return unique

def element_contains(parent, child):
    if parent == child:
        return True
    try:
        return parent.find_elements(By.XPATH, './/*').count(child) > 0
    except Exception:
        return False

def dedupe_project_cards(cards):
    cards = unique_elements(cards)
    if not cards:
        return []
    keep = []
    for card in cards:
        card_text = element_text(card)
        if len(card_text) < 3:
            continue
        duplicate = False
        for kept in list(keep):
            kept_text = element_text(kept)
            if element_contains(kept, card):
                duplicate = True
                break
            if element_contains(card, kept):
                if len(card_text) > len(kept_text):
                    keep.remove(kept)
                else:
                    duplicate = True
                break
        if not duplicate:
            keep.append(card)
    deduped = []
    seen_signatures = set()
    for card in keep:
        text = element_text(card)
        name = ''
        for line in text.splitlines():
            line = line.strip()
            if line and not re.search(r'expires|renewal|renew|reactivate|suspended|expiry|expire|valid|续期|重新激活|恢复|暂停|过期|到期', line, re.I):
                name = line
                break
        signature = (name.lower(), get_project_expiry(card).lower())
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        deduped.append(card)
    return deduped

def find_elements(root, selector):
    by = By.XPATH if selector.startswith(('/', './/')) else By.CSS_SELECTOR
    return root.find_elements(by, selector)

def find_renew_buttons(root):
    selectors = [
        '.projects-renew-btn',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "reactivate")]',
        './/*[(@role="button" or self::a) and contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        './/*[(@role="button" or self::a) and contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "reactivate")]',
    ]
    buttons = []
    for selector in selectors:
        try:
            buttons.extend(find_elements(root, selector))
        except Exception:
            continue
    return unique_elements([button for button in buttons if element_text(button) or button.is_displayed()])

def find_card_container_from_child(sb, child):
    return sb.driver.execute_script(
        '''
        const start = arguments[0];
        let node = start;
        for (let i = 0; node && i < 10; i += 1, node = node.parentElement) {
          const text = (node.innerText || '').trim();
          const cls = (node.className || '').toString().toLowerCase();
          const looksLikeProject = /renew|reactivate|suspended|expiry|expire|expires|valid|续期|重新激活|恢复|暂停|过期|到期/i.test(text);
          const looksLikeCard = /card|project|service|server|item|row/.test(cls);
          if (node !== start && text.length > 20 && (looksLikeProject || looksLikeCard)) {
            return node;
          }
        }
        return start.parentElement || start;
        ''',
        child,
    )

def find_project_cards(sb):
    candidate_selectors = [
        '.projects-card',
        '[class*="projects-card"]',
        '[class*="project"][class*="card"]',
        '[class*="Project"][class*="Card"]',
        '[class*="service"][class*="card"]',
        '[class*="server"][class*="card"]',
        'article',
    ]
    cards = []
    for selector in candidate_selectors:
        try:
            for card in sb.driver.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(card).lower()
                if any(keyword in text for keyword in ['renew', 'reactivate', 'suspended', 'expiry', 'expire', 'valid', '续期', '重新激活', '恢复', '暂停', '过期', '到期']):
                    cards.append(card)
        except Exception:
            continue
    if cards:
        return dedupe_project_cards(cards)
    for button in find_renew_buttons(sb.driver):
        try:
            cards.append(find_card_container_from_child(sb, button))
        except Exception:
            continue
    if cards:
        return dedupe_project_cards(cards)
    expiry_xpath = (
        '//*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "expiry") '
        'or contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "expire") '
        'or contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "valid") '
        'or contains(normalize-space(.), "过期") or contains(normalize-space(.), "到期")]'
    )
    for elem in sb.driver.find_elements(By.XPATH, expiry_xpath):
        try:
            cards.append(find_card_container_from_child(sb, elem))
        except Exception:
            continue
    return dedupe_project_cards(cards)

def extract_date_like(text):
    if not text:
        return ''
    patterns = [
        r'\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?',
        r'\d{1,2}[-/]\d{1,2}[-/]\d{4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return ''

def extract_duration_like(text):
    if not text:
        return ''
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        if re.search(r'expires\s+in|剩余|还有|temps restant', line, re.I) and idx + 1 < len(lines):
            return f"{line} {lines[idx + 1]}"
    match = re.search(
        r'(?:expires\s+in\s*|temps restant\s*:?\s*)?\d+\s*(?:d|day|days|j|天|日)\s*\d*\s*(?:h|hour|hours|小时)?',
        text,
        re.I,
    )
    if match:
        return match.group(0).strip()
    match = re.search(r'\d+\s*(?:h|hour|hours|小时)', text, re.I)
    if match:
        return match.group(0).strip()
    return ''

def get_project_name(card, idx):
    selectors = [
        '.projects-card-title',
        'h1', 'h2', 'h3', 'h4',
        '[class*="title"]',
        '[class*="name"]',
    ]
    for selector in selectors:
        try:
            for elem in card.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(elem)
                if text and len(text) <= 80 and 'renew' not in text.lower() and 'expiry' not in text.lower() and not extract_duration_like(text):
                    return text
        except Exception:
            continue
    for line in element_text(card).splitlines():
        line = line.strip()
        if line and len(line) <= 80 and not extract_duration_like(line) and not re.search(r'renew|reactivate|suspended|expiry|expire|valid|续期|重新激活|恢复|暂停|过期|到期|temps restant', line, re.I):
            return line
    return f"项目 #{idx}"

def get_project_expiry(card):
    selectors = [
        '.projects-expiry-value',
        '[class*="expiry"]',
        '[class*="expire"]',
        '[class*="Expires"]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "expiry")]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "expire")]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "valid")]',
        './/*[contains(normalize-space(.), "过期") or contains(normalize-space(.), "到期") or contains(normalize-space(.), "Temps restant")]',
    ]
    for selector in selectors:
        try:
            for elem in find_elements(card, selector):
                text = element_text(elem)
                date_text = extract_date_like(text)
                if date_text:
                    return date_text
                duration_text = extract_duration_like(text)
                if duration_text:
                    return duration_text
                if text and len(text) <= 120:
                    return text
        except Exception:
            continue
    card_text = element_text(card)
    return extract_date_like(card_text) or extract_duration_like(card_text) or '未知'

def get_renewal_available_note(card):
    text = element_text(card)
    patterns = [
        r'Renewal\s+will\s+be\s+available[^\n]*',
        r'Le renouvellement sera disponible[^\n]*',
        r'可续期[^\n]*',
        r'续期[^\n]*前[^\n]*',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(0).strip()
    return ''

def get_card_by_index(sb, idx):
    cards = find_project_cards(sb)
    if idx <= len(cards):
        return cards[idx - 1]
    return None

def wait_for_renew_result(sb, idx, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            success_modals = sb.driver.find_elements(
                By.XPATH,
                '//div[contains(@class, "modal") and contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "successfully")]',
            )
            if any(modal.is_displayed() for modal in success_modals):
                card = get_card_by_index(sb, idx)
                return True, get_project_expiry(card) if card else '未知', 'success modal'
            card = get_card_by_index(sb, idx)
            if card:
                renewal_note = get_renewal_available_note(card)
                renew_buttons = find_renew_buttons(card)
                if renewal_note and not renew_buttons:
                    return True, get_project_expiry(card), renewal_note
        except Exception as e:
            print(f"检查续期结果时暂时失败: {e}")
        sb.sleep(1)
    card = get_card_by_index(sb, idx)
    note = get_renewal_available_note(card) if card else ''
    expiry = get_project_expiry(card) if card else '未知'
    return False, expiry, note

def get_renew_note(card):
    selectors = [
        '.projects-renew-note',
        '[class*="renew-note"]',
        '[class*="note"]',
        '[class*="tip"]',
    ]
    for selector in selectors:
        try:
            for elem in card.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(elem)
                if text:
                    return text
        except Exception:
            continue
    return '未到续期时间'

def get_action_button_label(button):
    text = element_text(button)
    lowered = text.lower()
    if 'reactivate' in lowered or '重新激活' in text or '恢复' in text:
        return 'Reactivate'
    return 'Renew'

def log_projects_page_diagnostics(sb):
    current_url = sb.get_current_url()
    title = sb.get_title()
    body_text = ''
    try:
        body_text = sb.driver.find_element(By.TAG_NAME, 'body').text.strip()
    except Exception:
        pass
    print(f"项目页诊断 URL: {current_url}")
    print(f"项目页诊断标题: {title}")
    print(f"项目页可见文本摘要: {body_text[:1200]}")

def has_renew_antibot_modal(sb):
    selectors = [
        '//div[contains(., "Anti-bot confirmation")]',
        '//div[contains(., "Confirm you are human")]',
        '//div[contains(., "I am not a robot")]',
    ]
    for selector in selectors:
        try:
            if any(elem.is_displayed() for elem in sb.driver.find_elements(By.XPATH, selector)):
                return True
        except Exception:
            continue
    return False

def click_captcha_checkbox(sb, label='验证码', timeout=10):
    """点击 ACLClouds 页面上的人机验证复选框，并处理图形验证码挑战。"""
    selectors = [
        'div.auth-captcha-inner[role="checkbox"]',
        '//div[contains(., "Anti-bot confirmation")]//*[@role="checkbox"]',
        '//div[contains(., "I am not a robot")]//*[@role="checkbox"]',
        '//div[contains(@class, "modal") and contains(., "Secured by ACLClouds")]//*[@role="checkbox"]',
        'div.auth-captcha-checkbox',
    ]
    last_error = None
    clicked = False
    selector = None
    for candidate in selectors:
        try:
            sb.wait_for_element_visible(candidate, timeout=timeout)
            scroll_to_selector(sb, candidate)
            sb.uc_click(candidate)
            sb.sleep(1.5)
            selector = candidate
            clicked = True
            print(f"{label} 已点击复选框")
            break
        except Exception as e:
            last_error = e
            continue

    if not clicked:
        print(f"{label} 点击复选框失败: {last_error}")
        return False

    sb.sleep(3)
    captcha_ok = handle_captcha_challenge(sb, label, timeout=25)
    if not captcha_ok:
        print(f"{label} 验证流程未完成")
        return False

    # 最终确认复选框状态
    try:
        checked = sb.get_attribute(selector, 'aria-checked')
        if checked == 'true':
            print(f"{label} 验证通过")
            return True
        else:
            print(f"{label} 验证未完成，当前状态: {checked}")
            return False
    except Exception:
        # 有些情况下挑战消失就视为成功
        if not has_renew_antibot_modal(sb):
            print(f"{label} 弹窗已消失，视为验证通过")
            return True
        return False


def handle_captcha_challenge(sb, label='验证码', timeout=25):
    """处理图形验证码挑战（登录和续期通用）"""
    start_time = time.time()

    challenge_selectors = [
        '.auth-captcha-challenge',
        '.auth-capcha-challenge',
        '//*[contains(@class, "captcha") and contains(@class, "challenge")]',
        '//*[contains(@aria-label, "Click on ") or contains(@aria-label, "Select ")]',
    ]

    def get_challenge():
        for selector in challenge_selectors:
            try:
                if selector.startswith('/'):
                    elems = sb.driver.find_elements(By.XPATH, selector)
                    for elem in elems:
                        if elem.is_displayed():
                            return elem
                else:
                    elems = sb.driver.find_elements(By.CSS_SELECTOR, selector)
                    for elem in elems:
                        if elem.is_displayed():
                            return elem
            except Exception:
                continue
        return None

    # 等待挑战出现
    challenge = None
    while time.time() - start_time < 8:
        challenge = get_challenge()
        if challenge:
            print(f"{label} 检测到图形验证码挑战")
            break
        # 检查是否已经勾选成功
        try:
            checkbox = sb.driver.find_element(By.CSS_SELECTOR, 'div.auth-captcha-inner[role="checkbox"]')
            if checkbox.get_attribute('aria-checked') == 'true':
                print(f"{label} 验证复选框已勾选，验证码流程已完成")
                return True
        except Exception:
            pass
        sb.sleep(0.4)

    if not challenge:
        print(f"{label} 未检测到挑战，可能已通过")
        return True

    # 提取目标文本
    target = ''
    try:
        prompt = challenge.find_element(By.CSS_SELECTOR, '.auth-captcha-prompt strong')
        target = prompt.text.strip()
    except Exception:
        pass
    if not target:
        try:
            prompt = challenge.find_element(By.CSS_SELECTOR, '.auth-capcha-prompt strong')
            target = prompt.text.strip()
        except Exception:
            pass
    if not target:
        aria_label = challenge.get_attribute('aria-label') or ''
        if 'Click on ' in aria_label:
            target = aria_label.split('Click on ')[-1].strip()
        elif 'click on ' in aria_label.lower():
            target = aria_label.lower().split('click on ')[-1].strip()

    print(f"{label} 目标文本: {target or '未识别'}")

    # 获取所有选项按钮
    def get_options(challenge_elem):
        selectors = [
            'button.auth-captcha-option',
            '.auth-captcha-option',
            '.auth-capcha-option',
            'button',
            '[role="button"]',
        ]
        for sel in selectors:
            try:
                elems = challenge_elem.find_elements(By.CSS_SELECTOR, sel)
                visible = [e for e in elems if e.is_displayed() and e.is_enabled()]
                if visible:
                    return visible
            except Exception:
                continue
        return []

    attempts = 0
    max_attempts = 10

    while attempts < max_attempts:
        challenge = get_challenge()
        if not challenge:
            print(f"{label} 挑战已消失，验证完成")
            return True

        options = get_options(challenge)
        if not options:
            print(f"{label} 当前无可用选项，重试...")
            attempts += 1
            sb.sleep(0.8)
            continue

        current_target = target
        try:
            prompt = challenge.find_element(By.CSS_SELECTOR, '.auth-captcha-prompt strong')
            current_target = prompt.text.strip() or current_target
        except Exception:
            pass

        candidate = None
        if current_target:
            for opt in options:
                opt_text = (opt.text or '').strip()
                if not opt_text:
                    try:
                        img = opt.find_element(By.TAG_NAME, 'img')
                        opt_text = (img.get_attribute('alt') or '').strip()
                    except Exception:
                        pass
                if not opt_text:
                    try:
                        opt_text = (opt.get_attribute('aria-label') or '').strip()
                    except Exception:
                        pass

                if current_target.lower() in opt_text.lower() or opt_text.lower() in current_target.lower():
                    candidate = opt
                    break

        if candidate is None:
            # 没匹配到就点第一个
            candidate = options[0]

        print(f"{label} 点击候选选项 #{attempts + 1} (目标: {current_target}) ...")
        clicked = safe_click_element(sb, candidate, f"{label} 选项")
        if not clicked:
            attempts += 1
            sb.sleep(0.8)
            continue

        sb.sleep(2.0)

        # 检查是否成功
        try:
            checkbox = sb.driver.find_element(By.CSS_SELECTOR, 'div.auth-captcha-inner[role="checkbox"]')
            if checkbox.get_attribute('aria-checked') == 'true':
                print(f"{label} 验证复选框已勾选，验证码流程已完成")
                return True
        except Exception:
            pass

        if not get_challenge():
            print(f"{label} 挑战已消失，验证完成")
            return True

        attempts += 1

    print(f"{label} 多次尝试后仍未完成验证码")
    return False

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

def build_success_message(account_name, project_name, old_expiry, new_expiry, email):
    masked_email = mask_email(email)
    lines = [
        "🇫🇷 Aclclouds 续期通知",
        f"账号: {account_name}",
        "",
        "✅ 续期成功",
        f"⏱️ 新过期时间: {new_expiry}",
        f"👤 登录账户: {masked_email}",
        f"⏱️ 运行时间: {beijing_time_str()}",
    ]
    return "\n".join(lines)

def build_not_yet_due_message(account_name, project_name, expiry, email):
    masked_email = mask_email(email)
    lines = [
        "🇫🇷 Aclclouds 续期通知",
        f"账号: {account_name}",
        "",
        "⏳ 未到续期时间",
        f"⏱️ 当前过期时间: {expiry}",
        f"👤 登录账户: {masked_email}",
        f"⏱️ 运行时间: {beijing_time_str()}",
    ]
    return "\n".join(lines)

def build_account_summary(account_name, email, cookie_status, results):
    """把一个账号的所有结果整合成一条消息"""
    masked_email = mask_email(email)
    lines = [
        "🇫🇷 ACLClouds 自动续期汇总",
        f"账号: {account_name}",
        f"登录账户: {masked_email}",
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
    name = account["name"]
    email = account["email"]
    password = account["password"]
    cookie = account["cookie"]
    secret_name = account["secret_name"]

    print(f"\n{'='*20} 开始处理账号: {name} {'='*20}")
    print(f"邮箱: {mask_email(email)}")

    results = []          # 收集本账号所有结果
    cookie_status = "未更新"

    # 登录优先级：Cookie → 密码
    logged_in = False

    if cookie:
        logged_in = login_by_cookie(sb, cookie)

    if not logged_in:
        if not email or not password:
            msg = f"❌ 账号 {name} 登录失败（无有效 Cookie 且无邮箱密码）"
            print(msg)
            send_telegram(msg)
            return
        sb.open(LOGIN_URL)
        sb.wait_for_ready_state_complete()
        time.sleep(2)
        logged_in = login(sb, email, password)

    if not logged_in:
        msg = f"❌ 账号 {name} 登录失败（Cookie + 密码均失败）"
        print(msg)
        send_telegram(msg)
        return

    # 登录成功后更新对应 Cookie Secret
    print(f"账号 {name} 登录成功，开始提取并更新 Cookie → {secret_name}")
    cookie_updated = save_new_cookie(sb, secret_name)
    cookie_status = "✅ 更新成功" if cookie_updated else "❌ 更新失败"

    # 进入项目页执行续期
    sb.open(PROJECTS_URL)
    sb.wait_for_ready_state_complete()
    time.sleep(3)

    cards = find_project_cards(sb)
    if not cards:
        print(f"❌ 账号 {name} 未找到项目卡片")
        log_projects_page_diagnostics(sb)
        results.append("未找到任何项目")
        summary = build_account_summary(name, email, cookie_status, results)
        send_telegram(summary)
        return

    print(f"账号 {name} 找到 {len(cards)} 个项目卡片")

    for idx, card in enumerate(cards, 1):
        try:
            project_name = get_project_name(card, idx)
            old_expiry = get_project_expiry(card)
            print(f"[{project_name}] 当前过期: {old_expiry}")

            renew_btn = find_renew_buttons(card)
            if renew_btn:
                action_label = get_action_button_label(renew_btn[0])
                safe_click_element(sb, renew_btn[0], f"[{project_name}] {action_label}按钮")
                print(f"[{project_name}] 点击 {action_label}...")
                handle_renew_antibot(sb, project_name)
                success, new_expiry, result_note = wait_for_renew_result(sb, idx, timeout=30)

                if success:
                    print(f"续期成功！状态: {result_note}，新过期: {new_expiry}")
                    results.append(f"✅ {project_name} 续期成功\n   原到期: {old_expiry}\n   新到期: {new_expiry}")
                else:
                    results.append(f"❌ {project_name} 续期未确认\n   原到期: {old_expiry}\n   当前: {new_expiry}\n   提示: {result_note or '无'}")
            else:
                note = get_renew_note(card)
                print(f"无 Renew 按钮，提示: {note}")
                results.append(f"⏳ {project_name} 未到续期时间\n   当前到期: {old_expiry}\n   提示: {note}")

        except Exception as e:
            print(f"处理卡片 {idx} 出错: {e}")
            results.append(f"⚠️ 项目处理异常: {str(e)}")

    summary = build_account_summary(name, email, cookie_status, results)
    send_telegram(summary)
    print(f"账号 {name} 处理完成。🍪 Cookie 状态: {cookie_status}")

def main():
    IS_PROXY = os.environ.get("IS_PROXY", "false").lower() == "true"
    PROXY_SERVER = os.getenv('S5_PROXY') or os.getenv('PROXY_SERVER') or "socks://127.0.0.1:1080"

    print("=" * 50)
    print("ACLClouds 自动续期启动（多账号）")
    print("运行时间:", beijing_time_str())
    print("=" * 50)

    # ========== 从 Secrets 读取账号列表 ==========
    accounts = []

    # 账号1
    if os.getenv("EMAIL") or os.getenv("ACL_COOKIE"):
        accounts.append({
            "name": "账号1",
            "email": os.getenv("EMAIL") or "",
            "password": os.getenv("PASSWORD") or "",
            "cookie": os.getenv("ACL_COOKIE") or "",
            "secret_name": "ACL_COOKIE",
        })

    # 账号2
    if os.getenv("EMAIL_2") or os.getenv("ACL_COOKIE_2"):
        accounts.append({
            "name": "账号2",
            "email": os.getenv("EMAIL_2") or "",
            "password": os.getenv("PASSWORD_2") or "",
            "cookie": os.getenv("ACL_COOKIE_2") or "",
            "secret_name": "ACL_COOKIE_2",
        })

    if not accounts:
        print("❌ 没有配置任何账号，请检查 Secrets")
        send_telegram("❌ 没有配置任何账号，请检查 Secrets")
        return

    print(f"共加载 {len(accounts)} 个账号")

    sb_options = {'uc': True, 'headless': False}
    if IS_PROXY:
        sb_options['proxy'] = PROXY_SERVER
        print(f"🔗 挂载代理: {PROXY_SERVER}")
    else:
        print("🍭 未使用代理，直连访问")

    with SB(**sb_options) as sb:
        try:
            try:
                ip = get_current_ip(PROXY_SERVER if IS_PROXY else "")
                print(f"📍 当前出口IP: {ip}")
            except Exception as e:
                print(f"获取出口IP失败: {e}")

            sb.set_window_size(1366, 768)

            for account in accounts:
                try:
                    process_account(sb, account)
                except Exception as e:
                    print(f"账号 {account['name']} 处理过程发生异常: {e}")
                    send_telegram(f"❌ 账号 {account['name']} 处理异常\n{str(e)}")

            print("\n全部账号处理完成")

        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ ACLClouds脚本异常\n{str(e)}\n时间: {beijing_time_str()}")

if __name__ == '__main__':
    main()
