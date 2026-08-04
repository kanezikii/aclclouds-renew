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
    headers = {"Authorization": f"Bearer {GH_PAT}", "Accept": "application/vnd.github+json"}
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
            print("Github Secret 更新成功")
            return True
        else:
            print(f"Github Secret 更新返回状态码: {result.status_code}")
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
        success = update_github_secret(GH_SECRET_NAME, cookie)
        if success:
            print("✅ Github Secret 更新成功")
        else:
            print("❌ Github Secret 更新失败")
        return success
    except Exception as e:
        print(f"保存Cookie时发生异常: {e}")
        return False

def is_logged_in(sb):
    try:
        url = sb.get_current_url()
        if BASE_URL not in url or LOGIN_PATH in url:
            return False
        body = sb.get_page_source().lower()
        if any(x in body for x in ["dashboard", "projects", "mes services", "我的服务", "logout", "déconnexion", "se déconnecter"]):
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
            return True
        sb.refresh()
        sb.sleep(5)
        if is_logged_in(sb):
            print("✅ Cookie登录成功（刷新后）")
            return True
        print("Cookie登录失败")
        return False
    except Exception as e:
        print(f"Cookie登录异常: {e}")
        return False

def login_by_password(sb):
    if not EMAIL or not PASSWORD:
        print("没有 EMAIL 或 PASSWORD，无法进行密码登录")
        return False
    print("尝试密码登录...")
    try:
        sb.uc_open_with_reconnect(LOGIN_URL, reconnect_time=5)
        sb.sleep(4)
        email_selectors = [
            'input[name="email"]', 'input[type="email"]', '#email',
            'input[placeholder*="email" i]', 'input[placeholder*="courriel" i]',
            'input[placeholder*="Email"]', 'input[name="username"]',
        ]
        password_selectors = [
            'input[name="password"]', 'input[type="password"]', '#password',
        ]
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]', 'button.btn-primary',
            'button:contains("Connexion")', 'button:contains("Login")',
            'button:contains("Se connecter")', 'button:contains("Log in")', '.btn-login',
        ]
        email_found = False
        for sel in email_selectors:
            try:
                if sb.is_element_visible(sel):
                    sb.type(sel, EMAIL)
                    email_found = True
                    print(f"已填入邮箱 (selector: {sel})")
                    break
            except Exception:
                continue
        if not email_found:
            print("找不到邮箱输入框")
            return False
        sb.sleep(0.8)
        pwd_found = False
        for sel in password_selectors:
            try:
                if sb.is_element_visible(sel):
                    sb.type(sel, PASSWORD)
                    pwd_found = True
                    print(f"已填入密码 (selector: {sel})")
                    break
            except Exception:
                continue
        if not pwd_found:
            print("找不到密码输入框")
            return False
        sb.sleep(0.8)
        clicked = False
        for sel in submit_selectors:
            try:
                if sb.is_element_visible(sel):
                    sb.click(sel)
                    clicked = True
                    print(f"已点击提交 (selector: {sel})")
                    break
            except Exception:
                continue
        if not clicked:
            try:
                sb.press_keys('input[type="password"]', "\n")
                print("使用回车键提交")
            except Exception:
                pass
        sb.sleep(10)
        if is_logged_in(sb):
            print("✅ 密码登录成功")
            return True
        sb.open(PROJECTS_URL)
        sb.sleep(6)
        if is_logged_in(sb):
            print("✅ 密码登录成功（二次确认）")
            return True
        print("密码登录失败")
        return False
    except Exception as e:
        print(f"密码登录异常: {e}")
        return False

# ===================== 续期逻辑 =====================
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
    """只匹配真正带有 Renew / Renouveler 文字的按钮，排除纯图标按钮"""
    selectors = [
        # 最精准：必须同时有文字
        '//button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew") and not(.//svg[contains(@data-icon, "sync")])]',
        '//button[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler") and not(.//svg[contains(@data-icon, "sync")])]',
        '//a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renew")]',
        '//a[contains(translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "renouveler")]',
        
        # 备用
        'button:contains("Renew")',
        'button:contains("Renouveler")',
        'a:contains("Renew")',
        'a:contains("Renouveler")',
    ]
    
    buttons = []
    for selector in selectors:
        try:
            found = find_elements(root, selector)
            for btn in found:
                text = element_text(btn).lower()
                # 必须包含文字，且不能是纯图标
                if ("renew" in text or "renouveler" in text) and len(text) > 2:
                    buttons.append(btn)
        except Exception:
            continue
            
    return unique_elements(buttons)

def find_project_cards(sb):
    candidate_selectors = [
        ".projects-card",
        '[class*="projects-card"]',
        '[class*="project"][class*="card"]',
        '[class*="service"][class*="card"]',
        "article",
        '[class*="card"]',
    ]
    raw_cards = []
    for selector in candidate_selectors:
        try:
            for card in sb.driver.find_elements(By.CSS_SELECTOR, selector):
                text = element_text(card).lower()
                has_expiry = any(k in text for k in ["expire", "expires", "到期", "expire dans", "expires in", "剩余"])
                has_name_hint = any(k in text for k in ["node", "bot", "vps", "minecraft", "renqi", "人气", "服务"])
                if has_expiry and (has_name_hint or len(text) > 40):
                    raw_cards.append(card)
        except Exception:
            continue
    unique_cards = []
    seen = set()
    for card in unique_elements(raw_cards):
        name = get_project_name(card, 0).lower().strip()
        expiry = get_project_expiry(card).lower().strip()
        if name in ["expires in", "expire dans", "ram", "stockage", "内存", "贮存", "未知", ""]:
            continue
        if len(name) < 2:
            continue
        signature = (name, expiry)
        if signature in seen:
            continue
        seen.add(signature)
        unique_cards.append(card)
    return unique_cards

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
        # 打印被点击元素的 HTML，方便排查
        try:
            outer = element.get_attribute("outerHTML")
            print(f"  → 即将点击的元素HTML: {outer[:300]}...")
        except Exception:
            pass

        sb.driver.execute_script(
            'arguments[0].scrollIntoView({behavior: "smooth", block: "center"});',
            element
        )
        sb.sleep(1.5)

        try:
            element.click()
            print(f"  → 普通点击成功 ({label})")
            return True
        except Exception:
            pass

        sb.driver.execute_script("arguments[0].click();", element)
        print(f"  → JS强制点击成功 ({label})")
        return True
    except Exception as e:
        print(f"  → 点击失败 ({label}): {e}")
        return False

def renew_projects(sb):
    print("进入项目页面")
    sb.uc_open_with_reconnect(PROJECTS_URL, reconnect_time=5)
    sb.wait_for_ready_state_complete()
    sb.sleep(6)

    sb.save_screenshot("01_before_click.png")
    print("已保存截图: 01_before_click.png")

    cards = find_project_cards(sb)
    results = []

    if not cards:
        print("没有找到项目")
        results.append("⚠️ 未找到任何项目")
        return results

    print(f"发现 {len(cards)} 个项目")

    for idx, card in enumerate(cards, 1):
        try:
            name = get_project_name(card, idx)
            old_expiry = get_project_expiry(card)
            note = get_renewal_available_note(card)
            print(f"[{name}] 当前过期: {old_expiry}")

            buttons = find_renew_buttons(card)
            if not buttons:
                buttons = find_renew_buttons(sb.driver)

            if not buttons:
                status = f"⏳ 未到续期时间\n提示: {note or '按钮不存在'}"
                results.append(f"项目: {name}\n当前过期: {old_expiry}\n{status}")
                continue

            print(f"[{name}] 找到 {len(buttons)} 个续期按钮，准备强制点击")
            clicked = safe_click_element(sb, buttons[0], name)

            if not clicked:
                results.append(f"项目: {name}\n❌ 点击按钮失败\n当前过期: {old_expiry}")
                continue

            sb.sleep(3)
            sb.save_screenshot("02_after_click.png")
            print("已保存截图: 02_after_click.png")

            # ==================== 通用 Anti-bot 破解（支持任意随机词） ====================
            print(f"[{name}] 开始自动破解 Anti-bot 验证...")
            try:
                sb.sleep(2)

                # ---------- 第一阶段：点击自定义复选框 ----------
                captcha_selectors = [
                    'div.auth-captcha-checkbox',
                    '.auth-captcha-checkbox',
                    '[role="checkbox"]',
                    '.auth-captcha-inner',
                ]
                for sel in captcha_selectors:
                    try:
                        if sb.is_element_visible(sel):
                            sb.click(sel)
                            print(f"  → 已点击第一阶段验证框")
                            break
                    except Exception:
                        continue
                else:
                    sb.execute_script("""
                        const el = document.querySelector('div.auth-captcha-checkbox') 
                                || document.querySelector('[role="checkbox"]');
                        if (el) el.click();
                    """)
                    print("  → 已使用 JS 点击第一阶段验证框")

                sb.sleep(3)
                sb.save_screenshot("02b_after_checkbox.png")
                print("已保存截图: 02b_after_checkbox.png")

                # ---------- 第二阶段：动态提取 “Click on XXX” 并点击 ----------
                print("  → 正在识别第二阶段随机目标...")

                # 获取弹窗区域文字
                body_text = sb.get_text("body")
                
                # 用正则提取 “Click on XXX” 后面的单词（支持大小写、空格、加粗等）
                target = None
                match = re.search(r'Click\s+on\s+([A-Za-zÀ-ÿ]+)', body_text, re.IGNORECASE)
                if match:
                    target = match.group(1).strip()
                    print(f"  → 成功识别到目标单词: 【{target}】")
                else:
                    # 备用方案：在常见位置找
                    print("  → 正则未匹配到，尝试备用提取...")
                    for line in body_text.splitlines():
                        if "click on" in line.lower():
                            parts = line.lower().split("click on")
                            if len(parts) > 1:
                                target = parts[1].strip().split()[0]
                                print(f"  → 备用方案识别到目标: 【{target}】")
                                break

                if target:
                    clicked_target = False

                    # 方法1：Selenium 精确点击
                    try:
                        elements = sb.find_elements("button, div, span, a")
                        for el in elements:
                            try:
                                text = el.text.strip()
                                if text.lower() == target.lower():
                                    el.click()
                                    print(f"  → 已点击目标选项: {target}")
                                    clicked_target = True
                                    break
                            except Exception:
                                continue
                    except Exception as e:
                        print(f"  → Selenium 点击异常: {e}")

                    # 方法2：JS 强制点击（更可靠）
                    if not clicked_target:
                        try:
                            sb.execute_script(f"""
                                const target = "{target}".toLowerCase();
                                const elements = document.querySelectorAll('button, div, span, a');
                                for (let el of elements) {{
                                    if (el.innerText && el.innerText.trim().toLowerCase() === target) {{
                                        el.scrollIntoView({{block: 'center'}});
                                        el.click();
                                        return true;
                                    }}
                                }}
                                return false;
                            """)
                            print(f"  → 已使用 JS 点击目标选项: {target}")
                            clicked_target = True
                        except Exception as e:
                            print(f"  → JS 点击目标失败: {e}")

                    if clicked_target:
                        sb.sleep(6)
                        sb.save_screenshot("02c_after_target.png")
                        print("已保存截图: 02c_after_target.png")
                    else:
                        print("  → 未能成功点击目标选项")
                        sb.save_screenshot("02c_failed_click.png")
                else:
                    print("  → 完全未能识别出目标单词")
                    sb.save_screenshot("02c_no_target.png")

            except Exception as e:
                print(f"处理 Anti-bot 弹窗时出错: {e}")
            # ==================================================================

            # 刷新后对比时间
            print(f"[{name}] 刷新页面，对比续期前后时间...")
            sb.refresh()
            sb.sleep(6)
            sb.save_screenshot("03_after_refresh.png")
            print("已保存截图: 03_after_refresh.png")

            new_cards = find_project_cards(sb)
            new_expiry = "未知"
            if new_cards:
                new_expiry = get_project_expiry(new_cards[0])

            print(f"[{name}] 原到期: {old_expiry}  →  新到期: {new_expiry}")

            if new_expiry != "未知" and new_expiry != old_expiry:
                results.append(
                    f"项目: {name}\n✅ 续期成功\n"
                    f"原到期: {old_expiry}\n新到期: {new_expiry}"
                )
                print(f"[{name}] ✅ 续期成功确认")
            else:
                results.append(
                    f"项目: {name}\n❌ 续期失败（时间未变化）\n"
                    f"原到期: {old_expiry}\n新到期: {new_expiry}"
                )
                print(f"[{name}] ❌ 续期未生效（时间未变化）")

        except Exception as e:
            results.append(f"项目处理异常: {e}")
            print(f"项目处理异常: {e}")

    return results

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

            logged_in = login_by_cookie(sb)
            if not logged_in:
                logged_in = login_by_password(sb)

            if not logged_in:
                print("登录失败")
                send_telegram("⚠️ ACLClouds 登录失败（Cookie + 密码均失败），请检查 ACL_COOKIE / EMAIL / PASSWORD")
                return

            print("登录成功，开始提取并更新最新 Cookie...")
            cookie_updated = False
            try:
                cookie_updated = save_new_cookie(sb)
            except Exception as e:
                print(f"保存Cookie失败: {e}")

            renew_results = renew_projects(sb)

            cookie_status = "✅ 更新成功" if cookie_updated else "❌ 更新失败"
            summary_lines = [
                "🇫🇷 ACLClouds 自动任务汇总",
                f"时间: {beijing_time_str()}",
                "",
                f"🍪 Cookie 状态: {cookie_status}",
                "",
            ]
            if renew_results:
                summary_lines.append("📋 项目结果:")
                summary_lines.extend(renew_results)
            else:
                summary_lines.append("未发现可处理的项目")
            summary_lines.append("")
            summary_lines.append("✅ 任务执行完毕")
            send_telegram("\n".join(summary_lines))
            print("全部任务完成")
        except Exception as e:
            print("程序异常:", e)
            send_telegram(f"❌ ACLClouds脚本异常\n{str(e)}\n时间:\n{beijing_time_str()}")

if __name__ == "__main__":
    main()
