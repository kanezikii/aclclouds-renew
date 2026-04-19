import os
from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(
        # 伪装一下 User-Agent，降低被拦截的概率
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    raw_cookies = os.environ.get('ACL_COOKIES', '')
    if not raw_cookies:
        print("错误: 未找到 ACL_COOKIES 环境变量。")
        return

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

    context.add_cookies(cookies)
    page = context.new_page()

    try:
        print("正在访问项目面板...")
        page.goto("https://dash.aclclouds.com/projects", timeout=60000)
        
        # 强制等待 5 秒，确保前端 React/Vue 等框架把按钮渲染出来
        page.wait_for_timeout(5000)

        # 核心调试步骤：截取当前页面的完整长图
        print("正在保存页面截图以供排查...")
        page.screenshot(path="debug_page.png", full_page=True)
        print("截图保存成功: debug_page.png")

        # 放宽查找条件，只要包含 Renew 文本的元素都找出来
        renew_buttons = page.locator("text='Renouveler'")
        count = renew_buttons.count()

        if count == 0:
            print("未找到 'Renew' 按钮。请查看下载的截图确认当前页面状态。")
        else:
            print(f"找到 {count} 个 'Renouveler' 元素，准备点击...")
            for i in range(count):
                button = renew_buttons.nth(i)
                if button.is_visible():
                    button.click()
                    print(f"已点击第 {i+1} 个 Renew 按钮。")
                    page.wait_for_timeout(3000) 
            
            # 点击完成后再截一张图看看结果
            page.screenshot(path="debug_page_after_click.png", full_page=True)

        print("任务执行完毕。")

    except Exception as e:
        print(f"执行过程中发生错误: {e}")
        # 出错时也尝试截图
        page.screenshot(path="error_page.png", full_page=True)
    finally:
        browser.close()

with sync_playwright() as playwright:
    run(playwright)
