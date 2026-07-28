#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
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
)

# ===================== 配置 =====================
EMAIL = os.getenv("EMAIL") or ""
PASSWORD = os.getenv("PASSWORD") or ""
ACL_COOKIE = os.getenv("ACL_COOKIE") or ""
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""
IS_PROXY = os.getenv("IS_PROXY", "false").lower() == "true"
PROXY_SERVER = os.getenv("S5_PROXY") or os.getenv("PROXY_SERVER") or "socks5://127.0.0.1:1080"
GH_PAT = os.getenv("GH_PAT") or ""
GH_OWNER = os.getenv("GH_OWNER") or ""
GH_REPO = os.getenv("GH_REPO") or ""
GH_SECRET_NAME = "ACL_COOKIE"

BASE_URL = "https://aclclouds.com"
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
        requests.post(url, data={"chat_id": TG_CHAT_ID, "text": message}, timeout=10)
        print("Telegram发送成功")
    except Exception as e:
        print(f"Telegram失败: {e}")


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
    """优先使用 CDP 获取 Cookie，失败再降级到 driver.get_cookies()"""
    try:
        # 方法1：CDP（更稳定）
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

    # 方法2：普通方式
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
        return False
    headers = {"Authorization": f"Bearer {GH_PAT}", "Accept": "application/vnd.github+json"}
    try:
        r = requests.get(f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/public-key", headers=headers, timeout=15)
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
            print("Github Secret 更新成功")
            return True
    except Exception as e:
        print(f"Github更新异常: {e}")
    return False


def save_new_cookie(sb):
    try:
        cookie = extract_acl_cookie(sb)
        if not cookie:
            print("⚠️ 未能提取到有效Cookie，跳过更新")
            return False

        print("最新Cookie:")
        print(cookie[:180] + "..." if len(cookie) > 180 else cookie)

        # 更新 GitHub Secret
        success = update_github_secret(GH_SECRET_NAME, cookie)
        if success:
            send_telegram(f"🍪 ACLClouds Cookie 已自动更新\n时间:{beijing_time_str()}")
        return success
    except Exception as e:
        print(f"保存Cookie时发生异常（已忽略）: {e}")
        return False


def is_logged_in(sb):
    try:
        url = sb.get_current_url()
        if BASE_URL not in url or LOGIN_PATH in url:
            return False
        body = sb.get_page_source().lower()
        if any(x in body for x in ["dashboard", "projects", "mes services", "我的服务", "logout", "déconnexion"]):
            return True
        return True
    except Exception:
        return False


def login_by_cookie(sb):
    if not ACL_COOKIE:
        print("没有ACL_COOKIE")
        return False
    print("尝试Cookie登录...")
    try:
        sb.uc_open_with_reconnect(LOGIN_URL, reconnect_time=5)
        sb.sleep(2)
        sb.driver.delete_all_cookies()
        sb.sleep(1)

        cookies = parse_cookie_string(ACL_COOKIE)
        print(f"准备写入 {len(cookies)} 个Cookie")
        for name, value in cookies.items():
            try:
                if name.startswith("__Host-"):
                    params = {"name": name, "value": value, "url": "https://aclclouds.com/", "path": "/", "secure": True}
                else:
                    params = {"name": name, "value": value, "domain": "aclclouds.com", "path": "/", "secure": True}
                sb.execute_cdp_cmd("Network.setCookie", params)
                print(f"写入Cookie (CDP): {name}")
            except Exception as e:
                print(f"CDP失败 {name}: {e}")
                try:
                    cookie_dict = {"name": name, "value": value, "path": "/", "secure": True}
                    if not name.startswith("__Host-"):
                        cookie_dict["domain"] = "aclclouds.com"
                    sb.driver.add_cookie(cookie_dict)
                    print(f"写入Cookie (普通): {name}")
                except Exception as e2:
                    print(f"普通方式也失败 {name}: {e2}")

        print("直接访问项目页验证登录状态...")
        sb.open(PROJECTS_URL)
        sb.sleep(8)

        if is_logged_in(sb):
    print("✅ Cookie登录成功")
    try:
        save_new_cookie(sb)
    except Exception as e:
        print(f"保存Cookie失败（可忽略）: {e}")
    return True

        sb.refresh()
        sb.sleep(5)
        if is_logged_in(sb):
            print("✅ Cookie登录成功（刷新后）")
            try:
                save_new_cookie(sb)
            except Exception as e:
                print(f"保存Cookie失败（可忽略）: {e}")
            return True

        print("Cookie登录失败")
        return False
    except Exception as e:
        print(f"Cookie登录异常: {e}")
        return False


# ===================== 续期逻辑（参考你提供的成熟版本） =====================
def element_text(element):
    try:
        return element.text.strip()
    except Exception:
        return ""


def unique_elements(elements):
    unique, seen = [], set()
    for element in elements:
        element_id = getattr(element, "id", None)
        if element_id and element_id in seen:
            continue
        if element_id:
            seen.add(element_id)
        unique.append(element)
    return unique


def find_elements(root, selector):
    by = By.XPATH if selector.startswith(("/", ".//")) else By.CSS_SELECTOR
    return root.find_elements(by, selector)


def find_renew_buttons(root):
    selectors = [
        ".projects-renew-btn",
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        './/button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "reactivate")]',
        './/*[(@role="button" or self::a) and contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        './/*[(@role="button" or self::a) and contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "reactivate")]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "续订")]',
        './/*[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "续期")]',
    ]
    buttons = []
    for selector in selectors:
        try:
            buttons.extend(find_elements(root, selector))
        except Exception:
            continue
    return unique_elements([b for b in buttons if element_text(b) or b.is_displayed()])


def find_project_cards(sb):
    candidate_selectors = [
        ".projects-card",
        '[class*="projects-card"]',
        '[class*="project"][class*="card"]',
        '[class*="service"][class*="card"]',
        "article",
        '[class*="card"]',
    ]
    cards = []
    for selector in candidate_selectors:
        try:
            for card in sb.driver.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(card).lower()
                if any(k in text for k in ["renew", "reactivate", "expiry", "expire", "valid", "到期", "续期", "expire dans", "renouvellement"]):
                    cards.append(card)
        except Exception:
            continue
    return unique_elements(cards)


def extract_duration_like(text):
    if not text:
        return ""
    match = re.search(r"(?:expires?\s+in\s*|expire\s+dans\s*|剩余|还有)?\s*\d+\s*(?:d|day|days|j|天|日)\s*\d*\s*(?:h|hour|hours|小时)?", text, re.I)
    if match:
        return match.group(0).strip()
    match = re.search(r"\d+\s*(?:h|hour|hours|小时)", text, re.I)
    if match:
        return match.group(0).strip()
    return ""


def get_project_name(card, idx):
    for selector in [".projects-card-title", "h1", "h2", "h3", "h4", "[class*=title]", "[class*=name]", "strong"]:
        try:
            for elem in card.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(elem)
                if text and len(text) <= 80 and "renew" not in text.lower() and "expiry" not in text.lower():
                    return text
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
    match = re.search(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", text)
    if match:
        return match.group(0)
    return "未知"


def get_renewal_available_note(card):
    text = element_text(card)
    patterns = [
        r"Renewal\s+will\s+be\s+available[^\n]*",
        r"Le renouvellement sera disponible[^\n]*",
        r"续期[^\n]*前[^\n]*",
        r"可续期[^\n]*",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(0).strip()
    return ""


def safe_click_element(sb, element, label=""):
    try:
        sb.driver.execute_script('arguments[0].scrollIntoView({block: "center"});', element)
        sb.sleep(0.6)
        try:
            element.click()
            return True
        except Exception:
            sb.driver.execute_script("arguments[0].click();", element)
            return True
    except Exception as e:
        print(label, e)
        return False


def wait_for_renew_result(sb, timeout=25):
    start = time.time()
    while time.time() - start < timeout:
        try:
            body = sb.driver.find_element(By.TAG_NAME, "body").text.lower()
            if any(x in body for x in ["success", "successfully", "renewed", "续期成功", "reactivated"]):
                return True, "success"
            if any(x in body for x in ["renouvellement sera disponible", "renewal will be available", "未到续期"]):
                return False, "not_yet"
        except Exception:
            pass
        sb.sleep(1.5)
    return False, "timeout"


def renew_projects(sb):
    print("进入项目页面")
    sb.uc_open_with_reconnect(PROJECTS_URL, reconnect_time=5)
    sb.wait_for_ready_state_complete()
    sb.sleep(5)

    cards = find_project_cards(sb)
    if not cards:
        print("没有找到项目")
        send_telegram("⚠️ ACLClouds未找到项目")
        return

    print(f"发现 {len(cards)} 个项目")
    for idx, card in enumerate(cards, 1):
        try:
            name = get_project_name(card, idx)
            expiry = get_project_expiry(card)
            note = get_renewal_available_note(card)
            print(f"[{name}] 当前过期: {expiry}")

            buttons = find_renew_buttons(card)
            if not buttons:
                msg = f"🇫🇷 ACLClouds续期通知\n\n⏳ 未到续期时间\n项目: {name}\n当前过期: {expiry}\n提示: {note or '按钮不存在'}\n时间: {beijing_time_str()}"
                print(msg)
                send_telegram(msg)
                continue

            print(f"[{name}] 点击续期")
            safe_click_element(sb, buttons[0], name)
            sb.sleep(4)

            success, status = wait_for_renew_result(sb)
            if success:
                new_expiry = get_project_expiry(card)
                msg = f"🇫🇷 ACLClouds续期通知\n\n✅ 续期成功\n项目: {name}\n新到期: {new_expiry}\n时间: {beijing_time_str()}"
                send_telegram(msg)
            else:
                msg = f"🇫🇷 ACLClouds续期通知\n\n❌ 续期失败/未确认\n项目: {name}\n当前过期: {expiry}\n状态: {status}\n时间: {beijing_time_str()}"
                send_telegram(msg)
        except Exception as e:
            print(f"处理失败: {e}")
            send_telegram(f"⚠️ {name}异常: {e}")


def get_current_ip(proxy_server=""):
    proxies = {"http": proxy_server, "https": proxy_server} if proxy_server else None
    try:
        return requests.get("https://api.ip.sb/ip", proxies=proxies, timeout=15).text.strip()
    except Exception as e:
        return f"IP获取失败:{e}"


def main():
    print("=" * 50)
    print("ACLClouds 自动续期启动")
    print("运行时间:", beijing_time_str())
    print("=" * 50)

    sb_options = {"uc": True, "headless": False}
    if IS_PROXY:
        sb_options["proxy"] = PROXY_SERVER
        print("代理:", PROXY_SERVER)
    else:
        print("直连模式")

    with SB(**sb_options) as sb:
        try:
            sb.set_window_size(1366, 768)
            print("当前出口IP:", get_current_ip(PROXY_SERVER if IS_PROXY else ""))

            print("开始登录检测")
            if not login_by_cookie(sb):
                print("登录失败")
                send_telegram("⚠️ ACLClouds Cookie登录失败，请更新 ACL_COOKIE")
                return

            try:
                save_new_cookie(sb)
            except Exception as e:
                print(f"二次保存Cookie失败（可忽略）: {e}")

            renew_projects(sb)
            print("全部任务完成")
            send_telegram(f"✅ ACLClouds自动任务完成\n时间:\n{beijing_time_str()}")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ ACLClouds脚本异常\n{str(e)}\n时间:\n{beijing_time_str()}")


if __name__ == "__main__":
    main()
