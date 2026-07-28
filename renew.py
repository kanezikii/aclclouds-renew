#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import json
import time
import base64
import requests
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from seleniumbase import SB
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    ElementClickInterceptedException,
    WebDriverException,
    StaleElementReferenceException,
    TimeoutException,
)

EMAIL = os.getenv("EMAIL") or ""
PASSWORD = os.getenv("PASSWORD") or ""
# Cookie 登录
ACL_COOKIE = os.getenv("ACL_COOKIE") or ""
# Telegram
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""
# Proxy
IS_PROXY = os.getenv("IS_PROXY", "false").lower() == "true"
PROXY_SERVER = (
    os.getenv("S5_PROXY")
    or os.getenv("PROXY_SERVER")
    or "socks5://127.0.0.1:1080"
)
# Github 自动更新 Cookie
GH_PAT = os.getenv("GH_PAT") or ""
GH_OWNER = os.getenv("GH_OWNER") or ""
GH_REPO = os.getenv("GH_REPO") or ""
GH_SECRET_NAME = "ACL_COOKIE"
# ACL
BASE_URL = "https://dash.aclclouds.com"
LOGIN_PATH = "/auth/login"
LOGIN_URL = f"{BASE_URL}{LOGIN_PATH}"
PROJECTS_URL = f"{BASE_URL}/dashboard/projects"


def beijing_time_str():
    try:
        return datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def send_telegram(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print(message)
        return
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        requests.post(
            url,
            data={"chat_id": TG_CHAT_ID, "text": message},
            timeout=10,
        )
        print("Telegram发送成功")
    except Exception as e:
        print(f"Telegram失败: {e}")


# =========================================================
# Cookie处理
# =========================================================
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
    cookies = sb.driver.get_cookies()
    keep = []
    for c in cookies:
        name = c.get("name", "")
        if (
            name == "aclclouds_session"
            or name == "XSRF-TOKEN"
            or name.startswith("remember_web_")
        ):
            keep.append(c)
    return build_cookie_string(keep)


def github_encrypt_secret(public_key, secret_value):
    try:
        from nacl import encoding
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
        print("未配置Github Secret更新参数")
        return False
    headers = {
        "Authorization": f"Bearer {GH_PAT}",
        "Accept": "application/vnd.github+json",
    }
    key_url = (
        f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/public-key"
    )
    try:
        r = requests.get(key_url, headers=headers, timeout=15)
        r.raise_for_status()
        key_data = r.json()
        encrypted_value = github_encrypt_secret(key_data["key"], secret_value)
        if not encrypted_value:
            return False
        update_url = (
            f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/{secret_name}"
        )
        result = requests.put(
            update_url,
            headers=headers,
            json={
                "encrypted_value": encrypted_value,
                "key_id": key_data["key_id"],
            },
            timeout=15,
        )
        if result.status_code in [201, 204]:
            print("Github Secret 更新成功")
            return True
        print("Github Secret更新失败:", result.text)
    except Exception as e:
        print(f"Github更新异常: {e}")
    return False


def save_new_cookie(sb):
    cookie = extract_acl_cookie(sb)
    if not cookie:
        print("没有获取到Cookie")
        return False
    print("最新Cookie:")
    print(cookie[:120] + "..." if len(cookie) > 120 else cookie)
    update_github_secret(GH_SECRET_NAME, cookie)
    send_telegram(
        "🍪 ACLClouds Cookie 已自动更新\n"
        f"时间:{beijing_time_str()}"
    )
    return True


# =========================================================
# 登录状态判断
# =========================================================
def is_login_page(sb):
    try:
        return LOGIN_PATH in sb.get_current_url()
    except Exception:
        return False


def is_logged_in(sb):
    try:
        url = sb.get_current_url()
        if BASE_URL not in url or LOGIN_PATH in url:
            return False
        # 额外检查是否有 dashboard 特征
        body = sb.get_page_source().lower()
        if any(x in body for x in ["dashboard", "projects", "logout", "sign out", "déconnexion"]):
            return True
        return True  # URL 已经离开 login 也视为成功
    except Exception:
        return False


def debug_page_info(sb, label=""):
    try:
        print(f"[{label}] 当前URL: {sb.get_current_url()}")
        print(f"[{label}] 标题: {sb.get_title()}")
        body = sb.get_text("body")[:800].replace("\n", " ")
        print(f"[{label}] Body片段: {body}")
    except Exception as e:
        print(f"调试信息获取失败: {e}")


# =========================================================
# Cookie 登录
# =========================================================
def login_by_cookie(sb):
    if not ACL_COOKIE:
        print("没有ACL_COOKIE")
        return False
    print("尝试Cookie登录...")
    try:
        sb.uc_open_with_reconnect(LOGIN_URL, reconnect_time=5)
        sb.sleep(2)

        cookies = parse_cookie_string(ACL_COOKIE)
        for name, value in cookies.items():
            try:
                # 明确指定 domain，提高成功率
                sb.driver.add_cookie({
                    "name": name,
                    "value": value,
                    "path": "/",
                    "domain": "dash.aclclouds.com",
                })
                print("写入Cookie:", name)
            except Exception as e:
                # 某些 cookie 可能拒绝 domain，再试一次不带 domain
                try:
                    sb.driver.add_cookie({
                        "name": name,
                        "value": value,
                        "path": "/",
                    })
                    print("写入Cookie(无domain):", name)
                except Exception as e2:
                    print("Cookie写入失败:", name, e2)

        sb.refresh()
        sb.sleep(6)

        if is_logged_in(sb):
            print("Cookie登录成功")
            save_new_cookie(sb)
            return True

        print("Cookie登录失败")
        debug_page_info(sb, "Cookie失败后")
        return False
    except Exception as e:
        print(f"Cookie登录异常: {e}")
        return False


# =========================================================
# 页面输入
# =========================================================
def js_set_input_value(sb, selector, value):
    return sb.execute_script(
        """
        const el = document.querySelector(arguments[0]);
        if (!el) return false;
        el.focus();
        el.value = arguments[1];
        el.dispatchEvent(new Event('input', {bubbles: true}));
        el.dispatchEvent(new Event('change', {bubbles: true}));
        el.dispatchEvent(new Event('blur', {bubbles: true}));
        return true;
        """,
        selector,
        value,
    )


def fill_input(sb, selectors, value, label):
    """支持多个选择器，提高兼容性"""
    if isinstance(selectors, str):
        selectors = [selectors]
    for selector in selectors:
        try:
            sb.wait_for_element_visible(selector, timeout=8)
            sb.click(selector)
            sb.clear(selector)
            sb.type(selector, value)
            current = sb.get_value(selector)
            if current != value:
                print(f"{label} 普通输入失败，尝试JS修复")
                js_set_input_value(sb, selector, value)
            if sb.get_value(selector) == value:
                print(f"{label} 输入成功: {selector}")
                return True
        except Exception as e:
            continue
    print(f"{label} 所有选择器均失败")
    return False


# =========================================================
# 登录验证码
# =========================================================
def click_login_captcha(sb):
    """ACLClouds 自定义 'I am not a robot' 验证"""
    selectors = [
        'div.auth-captcha-inner[role="checkbox"]',
        'div[role="checkbox"]',
        '//div[contains(@class,"captcha")]//*[@role="checkbox"]',
        '//*[contains(text(),"I am not a robot")]',
        '//*[contains(text(),"not a robot")]',
        '.auth-captcha',
        '[class*="captcha"]',
    ]
    for selector in selectors:
        try:
            if selector.startswith("//"):
                sb.wait_for_element_visible(selector, timeout=4)
                sb.uc_click(selector)
            else:
                sb.wait_for_element_visible(selector, timeout=4)
                sb.uc_click(selector)
            print(f"验证码点击成功: {selector}")
            sb.sleep(3)
            return True
        except Exception:
            continue
    print("未找到可点击的验证码元素（可能已自动通过或页面结构变化）")
    return True  # 不强制失败，继续尝试提交


# =========================================================
# 账号密码登录
# =========================================================
def login_by_password(sb):
    print("开始账号密码登录")
    if not EMAIL or not PASSWORD:
        print("没有配置账号密码")
        return False

    try:
        sb.uc_open_with_reconnect(LOGIN_URL, reconnect_time=6)
        sb.sleep(3)

        # 更宽松的输入框选择器
        email_selectors = [
            "#username",
            'input[name="email"]',
            'input[name="username"]',
            'input[type="email"]',
            'input[placeholder*="Email"]',
            'input[placeholder*="email"]',
            'input[placeholder*="Username"]',
            'input[placeholder*="username"]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
        ]
        pass_selectors = [
            "#password",
            'input[name="password"]',
            'input[type="password"]',
            'input[placeholder*="Password"]',
            'input[placeholder*="password"]',
            'input[autocomplete="current-password"]',
        ]

        if not fill_input(sb, email_selectors, EMAIL, "邮箱/用户名"):
            debug_page_info(sb, "邮箱输入失败")
            return False
        if not fill_input(sb, pass_selectors, PASSWORD, "密码"):
            debug_page_info(sb, "密码输入失败")
            return False

        # 验证码
        click_login_captcha(sb)
        sb.sleep(2)

        # 登录按钮（优先使用 uc_click 降低检测）
        buttons = [
            'button[type="submit"]',
            'div.auth-submit-btn',
            '//button[contains(text(),"Sign in")]',
            '//button[contains(text(),"Sign In")]',
            '//button[contains(text(),"登录")]',
            'button.auth-submit',
            '[class*="submit"]',
        ]
        clicked = False
        for btn in buttons:
            try:
                if btn.startswith("//"):
                    sb.uc_click(btn)
                else:
                    sb.uc_click(btn)
                clicked = True
                print("点击登录:", btn)
                break
            except Exception:
                continue

        if not clicked:
            print("登录按钮点击失败")
            debug_page_info(sb, "按钮点击失败")
            return False

        # 等待跳转或错误
        sb.sleep(8)

        if is_logged_in(sb):
            print("密码登录成功")
            save_new_cookie(sb)
            return True

        print("密码登录失败")
        debug_page_info(sb, "密码登录失败后")
        # 尝试提取页面错误提示
        try:
            body = sb.get_text("body").lower()
            for kw in ["incorrect", "invalid", "wrong", "error", "failed", "错误", "失败", "密码"]:
                if kw in body:
                    print(f"页面可能包含错误关键词: {kw}")
                    break
        except Exception:
            pass
        return False
    except Exception as e:
        print(f"密码登录异常: {e}")
        debug_page_info(sb, "异常时")
        return False


# =========================================================
# 总登录入口
# =========================================================
def login_acl(sb):
    """
    登录优先级：
    1. Cookie
    2. 账号密码
    """
    if login_by_cookie(sb):
        return True
    print("Cookie不可用，尝试账号密码")
    if login_by_password(sb):
        return True
    return False


# =========================================================
# 获取出口IP
# =========================================================
def get_current_ip(proxy_server=""):
    proxies = None
    if proxy_server:
        proxies = {"http": proxy_server, "https": proxy_server}
    try:
        r = requests.get("https://api.ip.sb/ip", proxies=proxies, timeout=15)
        return r.text.strip()
    except Exception as e:
        return "IP获取失败:" + str(e)


# =========================================================
# 安全点击
# =========================================================
def safe_click_element(sb, element, label=""):
    try:
        sb.driver.execute_script(
            "arguments[0].scrollIntoView({block:'center'});",
            element,
        )
        sb.sleep(0.8)
        try:
            element.click()
        except Exception:
            sb.driver.execute_script("arguments[0].click();", element)
        return True
    except Exception as e:
        print(label, e)
        return False


# =========================================================
# 项目卡片处理
# =========================================================
def element_text(element):
    try:
        return element.text.strip()
    except Exception:
        return ""


def unique_elements(elements):
    result = []
    seen = set()
    for e in elements:
        try:
            eid = e.id
            if eid in seen:
                continue
            seen.add(eid)
        except Exception:
            pass
        result.append(e)
    return result


def find_renew_buttons(root):
    selectors = [
        ".projects-renew-btn",
        './/button[contains(translate(normalize-space(.),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"renew")]',
        './/button[contains(translate(normalize-space(.),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"reactivate")]',
        './/*[contains(translate(normalize-space(.),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"renew")]',
    ]
    buttons = []
    for s in selectors:
        try:
            if s.startswith(".//"):
                buttons.extend(root.find_elements(By.XPATH, s))
            else:
                buttons.extend(root.find_elements(By.CSS_SELECTOR, s))
        except Exception:
            pass
    return unique_elements(buttons)


def find_project_cards(sb):
    selectors = [
        ".projects-card",
        "[class*=project]",
        "[class*=card]",
        "article",
    ]
    cards = []
    for selector in selectors:
        try:
            items = sb.driver.find_elements(By.CSS_SELECTOR, selector)
            for item in items:
                txt = element_text(item).lower()
                if any(
                    x in txt
                    for x in [
                        "renew",
                        "reactivate",
                        "expiry",
                        "expire",
                        "valid",
                        "到期",
                        "续期",
                    ]
                ):
                    cards.append(item)
        except Exception:
            pass
    return unique_elements(cards)


def get_project_name(card, index):
    selectors = ["h1", "h2", "h3", "[class*=title]", "[class*=name]"]
    for selector in selectors:
        try:
            for e in card.find_elements(By.CSS_SELECTOR, selector):
                txt = element_text(e)
                if txt and len(txt) < 80:
                    return txt
        except Exception:
            pass
    return f"项目#{index}"


def get_project_expiry(card):
    text = element_text(card)
    patterns = [
        r"\d{4}[-/]\d{1,2}[-/]\d{1,2}",
        r"\d+\s*(day|days|天)",
    ]
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            return m.group(0)
    return "未知"


def get_action_label(button):
    txt = element_text(button).lower()
    if "reactivate" in txt:
        return "Reactivate"
    return "Renew"


# =========================================================
# 续期结果检测
# =========================================================
def wait_renew_result(sb, old_expiry, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            body = sb.driver.find_element(By.TAG_NAME, "body").text.lower()
            success_words = [
                "success",
                "renewed",
                "successfully",
                "续期成功",
                "reactivated",
            ]
            if any(x in body for x in success_words):
                return True
        except Exception:
            pass
        sb.sleep(2)
    return False


# =========================================================
# 续期通知
# =========================================================
def build_success_message(name, expiry):
    return f"""
🇫🇷 ACLClouds续期通知
✅ 续期成功
项目:
{name}
新到期:
{expiry}
时间:
{beijing_time_str()}
""".strip()


def build_fail_message(name):
    return f"""
🇫🇷 ACLClouds续期通知
❌ 续期失败
项目:
{name}
时间:
{beijing_time_str()}
""".strip()


# =========================================================
# Renew执行
# =========================================================
def renew_projects(sb):
    print("进入项目页面")
    sb.uc_open_with_reconnect(PROJECTS_URL, reconnect_time=5)
    sb.wait_for_ready_state_complete()
    sb.sleep(5)

    cards = find_project_cards(sb)
    if not cards:
        print("没有找到项目")
        send_telegram("⚠️ ACLClouds未找到项目")
        debug_page_info(sb, "无项目")
        return

    print(f"发现 {len(cards)} 个项目")
    for index, card in enumerate(cards, 1):
        try:
            name = get_project_name(card, index)
            expiry = get_project_expiry(card)
            print(name, expiry)

            buttons = find_renew_buttons(card)
            if not buttons:
                print(f"{name} 无续期按钮")
                continue

            btn = buttons[0]
            action = get_action_label(btn)
            print(f"{name} 点击 {action}")

            safe_click_element(sb, btn, name)
            sb.sleep(5)

            # 点击后页面可能刷新，重新获取最新到期信息
            new_expiry = "未知"
            try:
                # 简单再找一次当前页面
                new_cards = find_project_cards(sb)
                if new_cards and len(new_cards) >= index:
                    new_expiry = get_project_expiry(new_cards[index - 1])
            except Exception:
                pass

            if wait_renew_result(sb, expiry):
                send_telegram(build_success_message(name, new_expiry or expiry))
            else:
                send_telegram(build_fail_message(name))
        except Exception as e:
            print("处理失败:", e)
            send_telegram(f"⚠️ {name}异常:{e}")


# =========================================================
# 主程序
# =========================================================
def main():
    print("=" * 50)
    print("ACLClouds 自动续期启动")
    print("运行时间:", beijing_time_str())
    print("=" * 50)

    sb_options = {
        "uc": True,
        "headless": False,  # 在 xvfb 下仍保持非 headless 更稳定
    }
    if IS_PROXY:
        sb_options["proxy"] = PROXY_SERVER
        print("代理:", PROXY_SERVER)
    else:
        print("直连模式")

    with SB(**sb_options) as sb:
        try:
            sb.set_window_size(1366, 768)

            # 获取出口IP
            ip = get_current_ip(PROXY_SERVER if IS_PROXY else "")
            print("当前出口IP:", ip)

            print("开始登录检测")
            # 直接进入登录流程（初始状态肯定未登录）
            if not login_acl(sb):
                print("登录失败")
                send_telegram(
                    """
⚠️ ACLClouds登录失败
请检查:
1.Cookie 是否过期
2.账号密码是否正确
3.验证码 / 机房IP 是否被限制
4.建议开启代理 (IS_PROXY=true + 住宅代理)
""".strip()
                )
                debug_page_info(sb, "最终登录失败")
                return

            # 再次保存Cookie
            save_new_cookie(sb)

            # 执行续期
            renew_projects(sb)

            print("全部任务完成")
            send_telegram(
                f"""
✅ ACLClouds自动任务完成
时间:
{beijing_time_str()}
""".strip()
            )
        except Exception as e:
            print("程序异常:", e)
            send_telegram(
                f"""
❌ ACLClouds脚本异常
{str(e)}
时间:
{beijing_time_str()}
"""
            )


if __name__ == "__main__":
    main()
