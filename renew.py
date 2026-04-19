import os
from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()

    # 从环境变量中获取 Cookie 字符串
    raw_cookies = os.environ.get('ACL_COOKIES', '')
    if not raw_cookies:
        print("错误: 未找到 ACL_COOKIES 环境变量。")
        return

    # 将字符串格式的 Cookie 转换为 Playwright 需要的字典列表格式
    cookies = []
    for item in raw_cookies.split(';'):
        if '=' in item:
            name, value = item.split('=', 1)
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "domain": "dash.aclclouds.com",
                "path": "/"
            })

    # 注入 Cookies
    context.add_cookies(cookies)
    page = context.new_page()

    try:
        print("正在访问项目面板...")
        page.goto("https://dash.aclclouds.com/projects", timeout=60000)
        page.wait_for_load_state("networkidle")

        # 查找带有 "Renew" 文本的按钮
        renew_buttons = page.locator("button:has-text('Renew')")
        count = renew_buttons.count()

        if count == 0:
            print("未找到 'Renew' 按钮。可能尚未到达续期时间。")
        else:
            print(f"找到 {count} 个 'Renew' 按钮，准备点击...")
            for i in range(count):
                button = renew_buttons.nth(i)
                if button.is_visible():
                    button.click()
                    print(f"已点击第 {i+1} 个 Renew 按钮。")
                    # 点击后稍作等待，确保请求发送成功
                    page.wait_for_timeout(3000) 

        print("任务执行完毕。")

    except Exception as e:
        print(f"执行过程中发生错误: {e}")
    finally:
        browser.close()

with sync_playwright() as playwright:
    run(playwright)
