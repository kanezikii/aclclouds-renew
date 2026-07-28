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

EMAIL = os.getenv("EMAIL") or ""
PASSWORD = os.getenv("PASSWORD") or ""
ACL_COOKIE = os.getenv("ACL_COOKIE") or ""
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""
IS_PROXY = os.getenv("IS_PROXY", "false").lower() == "true"
PROXY_SERVER = (
    os.getenv("S5_PROXY")
    or os.getenv("PROXY_SERVER")
    or "socks5://127.0.0.1:1080"
)
GH_PAT = os.getenv("GH_PAT") or ""
GH_OWNER = os.getenv("GH_OWNER") or ""
GH_REPO = os.getenv("GH_REPO") or ""
GH_SECRET_NAME = "ACL_COOKIE"

# 已更新为正式域名
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
    """提取关键登录 Cookie（适配新域名和新名称）"""
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
        print("未配置Github Secret更新参数")
        return False
    headers = {
        "Authorization": f"Bearer {GH_PAT}",
        "Accept": "application/vnd.github+json",
    }
    key_url = f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/public-key"
    try:
        r = requests.get(key_url, headers=headers, timeout=15)
        r.raise_for_status()
        key_data = r.json()
        encrypted_value = github_encrypt_secret(key_data["key"], secret_value)
        if not encrypted_value:
            return False
        update_url = f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/actions/secrets/{secret_name}"
        result = requests.put(
            update_url,
            headers=headers,
            json={"encrypted_value": encrypted_value, "key_id": key_data["key_id"]},
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
    print(cookie[:150] + "..." if len(cookie) > 150 else cookie)
    update_github_secret(GH_SECRET_NAME, cookie)
    send_telegram(f"🍪 ACLClouds Cookie 已自动更新\n时间:{beijing_time_str()}")
    return True


def is_logged_in(sb):
    try:
        url = sb.get_current_url()
        if BASE_URL not in url or LOGIN_PATH in url:
            return False
        body = sb.get_page_source().lower()
        if any(x in body for x in ["dashboard", "projects", "logout", "sign out", "déconnexion", "我的服务"]):
            return True
        return True
    except Exception:
        return False


def debug_page_info(sb, label=""):
    try:
        print(f"[{label}] 当前URL: {sb.get_current_url()}")
        print(f"[{label}] 标题: {sb.get_title()}")
        body = sb.get_text("body")[:600].replace("\n", " ")
        print(f"[{label}] Body片段: {body}")
    except Exception as e:
        print(f"调试信息获取失败: {e}")


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
                cookie_dict = {
                    "name": name,
                    "value": value,
                    "path": "/",
                    "secure": True,
                }
                # __Host- 前缀的 Cookie 绝对不能设置 domain
                if not name.startswith("__Host-"):
                    cookie_dict["domain"] = "aclclouds.com"

                sb.driver.add_cookie(cookie_dict)
                print(f"写入Cookie: {name}")
            except Exception as e:
                print(f"Cookie写入失败 {name}: {e}")

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


def login_acl(sb):
    """只使用 Cookie 登录（密码登录已失效）"""
    if login_by_cookie(sb):
        return True
    print("Cookie登录失败，密码登录已禁用（站点强制 Google 登录）")
    return False


def get_current_ip(proxy_server=""):
    proxies = None
    if proxy_server:
        proxies = {"http": proxy_server, "https": proxy_server}
    try:
        r = requests.get("https://api.ip.sb/ip", proxies=proxies, timeout=15)
        return r.text.strip()
    except Exception as e:
        return "IP获取失败:" + str(e)


def safe_click_element(sb, element, label=""):
    try:
        sb.driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
        sb.sleep(0.8)
        try:
            element.click()
        except Exception:
            sb.driver.execute_script("arguments[0].click();", element)
        return True
    except Exception as e:
        print(label, e)
        return False


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
        './/*[contains(translate(normalize-space(.),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"续订")]',
        './/*[contains(translate(normalize-space(.),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"续期")]',
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
        "[class*=service]",
    ]
    cards = []
    for selector in selectors:
        try:
            items = sb.driver.find_elements(By.CSS_SELECTOR, selector)
            for item in items:
                txt = element_text(item).lower()
                if any(x in txt for x in ["renew", "reactivate", "expiry", "expire", "valid", "到期", "续期", "续订", "天"]):
                    cards.append(item)
        except Exception:
            pass
    return unique_elements(cards)


def get_project_name(card, index):
    selectors = ["h1", "h2", "h3", "[class*=title]", "[class*=name]", "strong"]
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
        r"\d+\s*(day|days|天|小时)",
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


def wait_renew_result(sb, timeout=25):
    start = time.time()
    while time.time() - start < timeout:
        try:
            body = sb.driver.find_element(By.TAG_NAME, "body").text.lower()
            if any(x in body for x in ["success", "renewed", "successfully", "续期成功", "reactivated", "续订成功"]):
                return True
        except Exception:
            pass
        sb.sleep(2)
    return False


def build_success_message(name, expiry):
    return f"""🇫🇷 ACLClouds续期通知
✅ 续期成功
项目: {name}
新到期: {expiry}
时间: {beijing_time_str()}""".strip()


def build_fail_message(name):
    return f"""🇫🇷 ACLClouds续期通知
❌ 续期失败
项目: {name}
时间: {beijing_time_str()}""".strip()


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

            if wait_renew_result(sb):
                # 重新获取到期时间
                new_expiry = expiry
                try:
                    new_cards = find_project_cards(sb)
                    if new_cards and len(new_cards) >= index:
                        new_expiry = get_project_expiry(new_cards[index - 1])
                except Exception:
                    pass
                send_telegram(build_success_message(name, new_expiry))
            else:
                send_telegram(build_fail_message(name))
        except Exception as e:
            print("处理失败:", e)
            send_telegram(f"⚠️ {name}异常:{e}")


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

            ip = get_current_ip(PROXY_SERVER if IS_PROXY else "")
            print("当前出口IP:", ip)

            print("开始登录检测")
            if not login_acl(sb):
                print("登录失败")
                send_telegram("""⚠️ ACLClouds登录失败
请检查:
1. Cookie 是否过期（建议重新用 Google 登录后更新 ACL_COOKIE）
2. 代理是否正常
""".strip())
                debug_page_info(sb, "最终登录失败")
                return

            save_new_cookie(sb)
            renew_projects(sb)

            print("全部任务完成")
            send_telegram(f"✅ ACLClouds自动任务完成\n时间:\n{beijing_time_str()}")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ ACLClouds脚本异常\n{str(e)}\n时间:\n{beijing_time_str()}")


if __name__ == "__main__":
    main()
