#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import json
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


# ===================== WebDriver 连接保护与 CDP 封装 =====================
def ensure_connected(sb):
    """确保 UC 模式下 chromedriver 处于连接状态，防止 Connection refused"""
    try:
        if hasattr(sb, "is_connected") and not sb.is_connected():
            sb.connect()
    except Exception:
        pass


def exec_cdp(sb, cmd, params=None):
    """兼容不同版本 SeleniumBase 的 CDP 调用方式"""
    ensure_connected(sb)
    if params is None:
        params = {}
    if hasattr(sb, "driver") and hasattr(sb.driver, "execute_cdp_cmd"):
        return sb.driver.execute_cdp_cmd(cmd, params)
    return sb.execute_cdp_cmd(cmd, params)


def save_debug_screenshot(sb, filename):
    try:
        ensure_connected(sb)
        sb.save_screenshot(filename)
        print(f"📸 已保存截图: {filename}")
    except Exception as e:
        print(f"保存截图 {filename} 失败: {e}")


# ===================== Cookie 相关 (支持插件 JSON 与传统字符串) =====================
def parse_cookie_input(cookie_raw):
    if not cookie_raw or not cookie_raw.strip():
        return []
    raw = cookie_raw.strip()

    # 1. 尝试按 JSON 解析
    if (raw.startswith("[") and raw.endswith("]")) or (raw.startswith("{") and raw.endswith("}")):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                if "cookies" in data and isinstance(data["cookies"], list):
                    data = data["cookies"]
                else:
                    return [{
                        "name": str(k).strip(),
                        "value": str(v).strip(),
                        "domain": "aclclouds.com",
                        "hostOnly": True,
                        "path": "/",
                        "secure": True,
                        "httpOnly": False,
                    } for k, v in data.items() if k and v is not None]

            if isinstance(data, list):
                cookie_list = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    value = item.get("value")
                    if name and value is not None:
                        domain = str(item.get("domain") or "aclclouds.com").strip()
                        host_only = item.get("hostOnly")
                        if host_only is None:
                            host_only = not domain.startswith(".")
                        cookie_list.append({
                            "name": str(name).strip(),
                            "value": str(value).strip(),
                            "domain": domain,
                            "hostOnly": bool(host_only),
                            "path": str(item.get("path") or "/"),
                            "secure": bool(item.get("secure", True)),
                            "httpOnly": bool(item.get("httpOnly", False)),
                        })
                print(f"成功以 JSON 格式解析出 {len(cookie_list)} 个 Cookie")
                return cookie_list
        except Exception as e:
            print(f"JSON 格式解析失败，回退为传统字符串解析: {e}")

    # 2. 回退为传统 key=value; 字符串解析
    cookie_list = []
    for item in raw.split(";"):
        item = item.strip()
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        cookie_list.append({
            "name": name.strip(),
            "value": value.strip(),
            "domain": "aclclouds.com",
            "hostOnly": True,
            "path": "/",
            "secure": True,
            "httpOnly": False,
        })
    print(f"成功以字符串格式解析出 {len(cookie_list)} 个 Cookie")
    return cookie_list


def extract_acl_cookie_json(sb):
    keep_names = (
        "XSRF-TOKEN",
        "__Host-aclclouds_session",
        "aclclouds_session",
        "cf_clearance",
    )

    def should_keep(c):
        name = c.get("name", "")
        domain = c.get("domain", "")
        if "aclclouds.com" in domain:
            return True
        return (
            name in keep_names
            or name.startswith("remember_web_")
            or name.startswith("__Host-aclclouds")
        )

    try:
        result = exec_cdp(sb, "Network.getAllCookies", {})
        cookies = result.get("cookies", [])
        keep = []
        for c in cookies:
            if should_keep(c):
                domain = c.get("domain", "aclclouds.com")
                name = c.get("name", "")
                host_only = name.startswith("__Host-") or (not domain.startswith("."))
                keep.append({
                    "name": name,
                    "value": c.get("value", ""),
                    "domain": domain.lstrip(".") if host_only else domain,
                    "hostOnly": host_only,
                    "path": c.get("path", "/"),
                    "secure": c.get("secure", True),
                    "httpOnly": c.get("httpOnly", False),
                })
        if keep:
            return json.dumps(keep, ensure_ascii=False)
    except Exception as e:
        print(f"CDP获取Cookie失败: {e}")

    try:
        ensure_connected(sb)
        cookies = sb.driver.get_cookies()
        keep = []
        for c in cookies:
            if should_keep(c):
                domain = c.get("domain", "aclclouds.com")
                name = c.get("name", "")
                host_only = name.startswith("__Host-") or (not domain.startswith("."))
                keep.append({
                    "name": name,
                    "value": c.get("value", ""),
                    "domain": domain.lstrip(".") if host_only else domain,
                    "hostOnly": host_only,
                    "path": c.get("path", "/"),
                    "secure": c.get("secure", True),
                    "httpOnly": c.get("httpOnly", False),
                })
        if keep:
            return json.dumps(keep, ensure_ascii=False)
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
            print(f"✅ Github Secret [{secret_name}] 更新成功 (JSON格式)")
            return True
        print(f"Github Secret 更新返回状态码: {result.status_code}")
    except Exception as e:
        print(f"Github更新异常: {e}")
    return False


def save_new_cookie(sb, secret_name):
    try:
        cookie_json = extract_acl_cookie_json(sb)
        if not cookie_json:
            print("⚠️ 未能提取到有效Cookie，跳过更新")
            return False
        print("提取到最新Cookie (JSON预览):")
        print(cookie_json[:180] + "..." if len(cookie_json) > 180 else cookie_json)
        return update_github_secret(secret_name, cookie_json)
    except Exception as e:
        print(f"保存Cookie时发生异常: {e}")
        return False


# ===================== 工具函数 =====================
def is_logged_in(sb):
    ensure_connected(sb)
    current_url = sb.get_current_url()
    return ('aclclouds.com' in current_url) and (LOGIN_PATH not in current_url)


def wait_for_url_change(sb, original_url, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        ensure_connected(sb)
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
    ensure_connected(sb)
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


def cdp_mouse_click(sb, x, y):
    """通过 CDP 在指定页面坐标执行真实鼠标点击（穿透 Shadow DOM / 自定义组件）"""
    try:
        exec_cdp(sb, "Input.dispatchMouseEvent", {
            "type": "mousePressed",
            "x": float(x),
            "y": float(y),
            "button": "left",
            "clickCount": 1
        })
        sb.sleep(0.08)
        exec_cdp(sb, "Input.dispatchMouseEvent", {
            "type": "mouseReleased",
            "x": float(x),
            "y": float(y),
            "button": "left",
            "clickCount": 1
        })
        return True
    except Exception as e:
        print(f"CDP 坐标点击失败: {e}")
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
    ensure_connected(sb)
    try:
        exec_cdp(sb, "Network.clearBrowserCookies", {})
    except Exception as e:
        print(f"CDP 清理 Cookie 提示: {e}")
    try:
        sb.open("about:blank")
        sb.sleep(0.5)
    except Exception:
        pass


# ===================== 验证框点击（纯复选框，无选词） =====================
def click_captcha_checkbox(sb, label='验证码', timeout=10):
    """
    点击新版人机验证复选框（如 Cap 组件: 'Vérifier que vous êtes humain' / 'Verify you are human'），
    同时穿透 Shadow DOM 与常规 DOM，无需选词挑战。
    """
    ensure_connected(sb)
    start_time = time.time()
    clicked = False

    while time.time() - start_time < timeout:
        # 使用 JS 深度遍历常规 DOM 与 Shadow DOM 查找复选框或验证文本
        info = sb.execute_script('''
            function findDeepCheckbox(root) {
                const checkboxSelectors = [
                    'input[type="checkbox"]',
                    '[role="checkbox"]',
                    '.auth-captcha-inner',
                    '.auth-captcha-checkbox',
                    '.cap-checkbox',
                    'cap-widget'
                ];
                for (const sel of checkboxSelectors) {
                    const els = root.querySelectorAll(sel);
                    for (const el of els) {
                        const rect = el.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            return { el, rect, type: 'selector:' + sel };
                        }
                    }
                }
                const all = root.querySelectorAll('*');
                for (const el of all) {
                    if (el.shadowRoot) {
                        const found = findDeepCheckbox(el.shadowRoot);
                        if (found) return found;
                    }
                }
                for (const el of all) {
                    const txt = (el.innerText || el.textContent || '').trim().toLowerCase();
                    if (
                        txt === 'vérifier que vous êtes humain' ||
                        txt === 'verify you are human' ||
                        txt === 'verify that you are human' ||
                        txt === 'je ne suis pas un robot' ||
                        txt === 'i am not a robot'
                    ) {
                        const rect = el.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            return { el, rect, type: 'text:' + txt };
                        }
                    }
                }
                return null;
            }

            const res = findDeepCheckbox(document);
            if (!res) return null;

            const el = res.el;
            el.scrollIntoView({ block: 'center', inline: 'center' });
            const r = el.getBoundingClientRect();

            // 尝试触发点击
            try { el.click(); } catch (e) {}
            if (el.parentElement) {
                try { el.parentElement.click(); } catch (e) {}
            }

            // 如果命中整行或文字，左侧为复选框位置；如果命中复选框本身，取中心点
            let clickX = r.left + r.width / 2;
            let clickY = r.top + r.height / 2;
            if (res.type.startsWith('text:') && r.width > 80) {
                clickX = Math.max(10, r.left - 22);
            } else if (r.width > 120) {
                clickX = r.left + 28;
            }

            return {
                type: res.type,
                x: clickX,
                y: clickY,
                w: r.width,
                h: r.height
            };
        ''')

        if info:
            print(f"{label} 定位成功 ({info.get('type')})，执行点击...")
            cdp_mouse_click(sb, info["x"], info["y"])
            clicked = True
            break

        sb.sleep(0.5)

    if not clicked:
        print(f"{label} 未找到复选框")
        return False

    sb.sleep(1.5)
    save_debug_screenshot(sb, "02b_after_checkbox.png")

    # 等待验证状态完成或弹窗自动关闭（最长 18 秒）
    wait_start = time.time()
    while time.time() - wait_start < 18:
        status = sb.execute_script('''
            const bodyText = (document.body.innerText || '').toLowerCase();
            const modalVisible = (
                bodyText.includes('confirmation anti-robot') ||
                bodyText.includes('confirmez que vous êtes humain') ||
                bodyText.includes('anti-bot confirmation')
            );

            // 检查复选框是否已通过
            let isChecked = false;
            function checkVerified(root) {
                const els = root.querySelectorAll('[aria-checked="true"], input[type="checkbox"]:checked, [data-state="verified"], .verified, .success');
                if (els.length > 0) return true;
                for (const el of root.querySelectorAll('*')) {
                    if (el.shadowRoot && checkVerified(el.shadowRoot)) return true;
                }
                return false;
            }
            isChecked = checkVerified(document);

            // 如果弹窗内有除 Annuler/Cancel 之外的确认按钮，顺手点击
            if (modalVisible) {
                const btns = document.querySelectorAll('button');
                for (const b of btns) {
                    const t = (b.innerText || '').trim().toLowerCase();
                    if (t && (t === 'confirmer' || t === 'confirm' || t === 'valider' || t === 'continuer')) {
                        b.click();
                    }
                }
            }

            return { modalVisible, isChecked };
        ''')

        if status:
            if not status.get("modalVisible"):
                print(f"{label} 验证弹窗已自动关闭，验证完成")
                return True
            if status.get("isChecked") and (time.time() - wait_start > 3):
                print(f"{label} 复选框已勾选通过")
                return True

        sb.sleep(0.8)

    print(f"{label} 点击已完成（等待超时后继续）")
    return True


# ===================== 登录相关 =====================
def login_by_cookie(sb, cookie_raw):
    if not cookie_raw:
        print("没有配置 Cookie，跳过 Cookie 登录")
        return False
    print("尝试 Cookie 登录...")
    try:
        ensure_connected(sb)
        cookie_list = parse_cookie_input(cookie_raw)
        if not cookie_list:
            print("未解析出任何有效 Cookie 项")
            return False

        try:
            exec_cdp(sb, "Network.clearBrowserCookies", {})
        except Exception:
            pass

        default_hosts = ["aclclouds.com", "dash.aclclouds.com"]
        injected_count = 0

        for item in cookie_list:
            name = item["name"]
            value = item["value"]
            raw_domain = (item.get("domain") or "aclclouds.com").strip()
            host_only = item.get("hostOnly", True)
            path = item.get("path") or "/"
            secure = item.get("secure", True)
            http_only = item.get("httpOnly", False)

            hosts = set(default_hosts)
            if raw_domain:
                hosts.add(raw_domain.lstrip("."))

            for h in hosts:
                try:
                    if name.startswith("__Host-") or host_only:
                        params = {
                            "name": name,
                            "value": value,
                            "url": f"https://{h}/",
                            "path": "/" if name.startswith("__Host-") else path,
                            "secure": True if name.startswith("__Host-") else secure,
                            "httpOnly": http_only,
                        }
                    else:
                        params = {
                            "name": name,
                            "value": value,
                            "url": f"https://{h}/",
                            "domain": f".{h}",
                            "path": path,
                            "secure": secure,
                            "httpOnly": http_only,
                        }
                    res = exec_cdp(sb, "Network.setCookie", params)
                    if res and res.get("success"):
                        injected_count += 1
                except Exception as e:
                    print(f"CDP写入失败 {name}@{h}: {e}")

        print(f"CDP 成功写入 {injected_count} 条域名 Cookie 记录，正在验证登录态...")

        for test_url in [f"{BASE_URL}/dashboard", f"{DASH_URL}/dashboard"]:
            sb.open(test_url)
            sb.wait_for_ready_state_complete()
            sb.sleep(5)
            cur_url = sb.get_current_url()
            print(f"验证后当前 URL: {cur_url}")
            if is_logged_in(sb) and LOGIN_PATH not in cur_url:
                print("✅ Cookie 登录成功")
                return True

        print("Cookie 登录失败（可能 Cookie 已过期）")
        return False
    except Exception as e:
        print(f"Cookie 登录异常: {e}")
        return False


def js_set_input_value(sb, selector, value):
    ensure_connected(sb)
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


def fill_input(sb, selector, value, label, timeout=10):
    ensure_connected(sb)
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
        print(f"填写{label} ({selector}) 未匹配: {e}")
        return False


def login(sb, email, password):
    print("开始密码登录流程...")
    ensure_connected(sb)
    if not fill_input(sb, '#username', email, '邮箱'):
        for sel in ['input[name="email"]', 'input[type="email"]', 'input[placeholder*="Email"]']:
            if fill_input(sb, sel, email, '邮箱'):
                break
    if not fill_input(sb, '#password', password, '密码'):
        for sel in ['input[name="password"]', 'input[type="password"]']:
            if fill_input(sb, sel, password, '密码'):
                break

    captcha_ok = click_captcha_checkbox(sb, '登录验证码', timeout=8)
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
    ensure_connected(sb)
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
            if 'renew' in txt or 'renouveler' in txt:
                visible.append(btn)
        except Exception:
            continue
    return visible


def page_body(sb):
    ensure_connected(sb)
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
        "start", "restart", "stop", "free plan", "online", "offline",
        "en ligne", "démarrer", "redémarrer", "arrêter", "offre gratuite", "renouveler"
    ])


def open_dashboard_session(sb):
    ensure_connected(sb)
    for url in [f"{BASE_URL}/dashboard", f"{DASH_URL}/dashboard"]:
        try:
            print(f"打开 Dashboard: {url}")
            sb.open(url)
            sb.wait_for_ready_state_complete()
            sb.sleep(4)
            body = page_body(sb)
            print(f"Dashboard URL: {sb.get_current_url()}")
            low = body.lower()
            if not is_error_page(body) and any(k in low for k in ["welcome", "dashboard", "my services", "accueil", "applications", "mes services"]):
                return True
        except Exception as e:
            print(f"打开 Dashboard 失败: {e}")
    return False


def click_dashboard_service(sb, server_url):
    ensure_connected(sb)
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
    ensure_connected(sb)
    try:
        return unique_elements(sb.driver.find_elements(By.XPATH, '//a[contains(@href, "/server/")]'))
    except Exception:
        return []


def open_service_page(sb, server_url):
    ensure_connected(sb)
    # 1. 优先尝试直接打开目标服务页
    if server_url:
        print(f"直接打开服务页: {server_url}")
        sb.open(server_url)
        sb.wait_for_ready_state_complete()
        sb.sleep(5)
        body = page_body(sb)
        if is_valid_service_page(body):
            return True, body

    # 2. 若直接打开异常，回退通过 Dashboard 点击进入
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
            if is_valid_service_page(body):
                return True, body

    return False, page_body(sb)


def read_service_info(sb):
    ensure_connected(sb)
    body = page_body(sb)
    remaining = "未知"
    patterns = [
        r'(?:Time remaining|Temps restant|Expires in)\s*:?\s*([0-9]+\s*(?:d|j|h|m|min|s)[^\n]*)',
    ]
    for p in patterns:
        m = re.search(p, body, re.I)
        if m:
            remaining = m.group(1).strip()
            break

    name = "未知服务"
    for sel in ['h1.server-name', '.server-name', 'main h1', 'main h2', 'h1', 'h2']:
        try:
            for el in sb.driver.find_elements(By.CSS_SELECTOR, sel):
                t = element_text(el)
                if t and 1 <= len(t) <= 40 and not any(ignore in t.lower() for ignore in ['anti-robot', 'anti-bot', 'aclclouds', 'console']):
                    name = t
                    break
            if name != "未知服务":
                break
        except Exception:
            continue
    return name, remaining, body


def handle_renew_antibot(sb, project_name):
    print(f"[{project_name}] 检查是否出现 Confirmation anti-robot 验证框...")
    sb.sleep(2)
    body_low = page_body(sb).lower()
    has_modal = any(k in body_low for k in [
        "confirmation anti-robot",
        "confirmez que vous êtes humain",
        "vérifier que vous êtes humain",
        "verify you are human",
        "anti-bot confirmation",
        "confirm you are human",
    ])
    if not has_modal:
        # 即使文本未直接体现在 body.text（例如在 Shadow DOM 内），也尝试检测一次复选框
        print(f"[{project_name}] 尝试检测验证复选框...")
    else:
        print(f"[{project_name}] 检测到人机验证弹窗，开始点击验证框...")

    success = click_captcha_checkbox(sb, label=f"续期验证框-{project_name}", timeout=10)
    print(f"[{project_name}] 续期验证框处理{'完成' if success else '未命中'}")
    sb.sleep(3)
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
            msg = "❌ 登录失败（Cookie失效且未配置: " + "/".join(missing) + "）"
            print(msg)
            return service_name, email, cookie_status, msg
        for login_url in LOGIN_URLS:
            print(f"尝试密码登录页面: {login_url}")
            ensure_connected(sb)
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

    save_debug_screenshot(sb, "01_before_click.png")

    if is_error_page(body) or not opened:
        print("服务页异常，回退到 Dashboard 查找 Renew 按钮")
        open_dashboard_session(sb)
        renew_btns = find_renew_buttons(sb)
        service_name, remaining, body = read_service_info(sb)
        if not renew_btns:
            return service_name, email, cookie_status, f"⏳ 未到续期时间\n剩余时间: {remaining}"
        clicked = safe_click_element(sb, renew_btns[0], f"{service_name} Renew")
        if not clicked:
            return service_name, email, cookie_status, f"❌ 点击 Renew 失败\n剩余时间: {remaining}"
        save_debug_screenshot(sb, "02_after_click.png")
        handle_renew_antibot(sb, service_name)
        return service_name, email, cookie_status, f"✅ 已在 Dashboard 点击 Renew\n原剩余: {remaining}"

    renew_btns = find_renew_buttons(sb)
    if not renew_btns:
        result_text = f"⏳ 未到续期时间\n剩余时间: {remaining}"
        print(f"[{service_name}] 没有 Renew/Renouveler 按钮，跳过")
        return service_name, email, cookie_status, result_text

    print(f"[{service_name}] 发现 Renouveler/Renew 按钮，开始续期")
    clicked = safe_click_element(sb, renew_btns[0], f"{service_name} Renew")
    if not clicked:
        return service_name, email, cookie_status, f"❌ 点击 Renew 失败\n剩余时间: {remaining}"

    sb.sleep(1.5)
    save_debug_screenshot(sb, "02_after_click.png")

    # 处理 Confirmation anti-robot 复选框弹窗
    handle_renew_antibot(sb, service_name)

    sb.sleep(3)
    sb.refresh()
    sb.wait_for_ready_state_complete()
    sb.sleep(4)
    save_debug_screenshot(sb, "03_after_refresh.png")

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
    print("ACLClouds 自动续期启动（JSON Cookie + 纯复选框验证）")
    print("运行时间:", beijing_time_str())
    print("=" * 50)
    print("环境变量检查（只显示有/无，不打印内容）:")
    print(f"EMAIL={env_flag('EMAIL')} PASSWORD={env_flag('PASSWORD')} ACL_COOKIE={env_flag('ACL_COOKIE')} SERVER_URL={env_flag('SERVER_URL')}")
    print(f"EMAIL_2={env_flag('EMAIL_2')} PASSWORD_2={env_flag('PASSWORD_2')} ACL_COOKIE_2={env_flag('ACL_COOKIE_2')} SERVER_URL_2={env_flag('SERVER_URL_2')}")

    accounts = []
    if os.getenv("EMAIL") or os.getenv("ACL_COOKIE") or os.getenv("PASSWORD"):
        accounts.append({
            "email": os.getenv("EMAIL") or "Account_1",
            "password": os.getenv("PASSWORD") or "",
            "cookie": os.getenv("ACL_COOKIE") or "",
            "secret_name": "ACL_COOKIE",
            "server_url": os.getenv("SERVER_URL") or os.getenv("SERVER_URL_1") or DEFAULT_SERVER_URL_1,
        })
    if os.getenv("EMAIL_2") or os.getenv("ACL_COOKIE_2") or os.getenv("PASSWORD_2"):
        accounts.append({
            "email": os.getenv("EMAIL_2") or "kanezi0417@gmail.com",
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
        print(f"服务{i} URL: {acc.get('server_url') or '(空)'} 账户标识: {mask_email(acc.get('email', ''))}")

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
            final_lines.append("💗母狗任务全部完成💗")
            send_telegram("\n".join(final_lines))
            print("全部服务处理完成，已发送一条总汇总")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ 脚本异常\n{str(e)}")


if __name__ == '__main__':
    main()
