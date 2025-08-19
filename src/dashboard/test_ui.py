#!/usr/bin/env python3
"""Test the dashboard UI with Playwright"""

import time

from playwright.sync_api import sync_playwright


def test_dashboard():
    with sync_playwright() as p:
        # Launch browser
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        try:
            # Navigate to the dashboard
            print("📍 Navigating to dashboard...")
            page.goto("http://localhost:3002")
            page.wait_for_load_state("networkidle")

            # Take initial screenshot
            page.screenshot(path="dashboard_home.png")
            print("✅ Dashboard loaded")

            # Click on Scanner tab
            print("📍 Clicking Scanner tab...")
            scanner_button = page.get_by_text("Scanner").first
            scanner_button.click()
            time.sleep(1)

            # Select GitHub mode
            print("📍 Selecting GitHub mode...")
            github_card = page.locator(".mode-card").filter(has_text="GitHub Repository")
            github_card.click()

            # Enter the GitHub URL
            print("📍 Entering GitHub URL...")
            target_input = page.locator('input[type="text"]').first
            target_input.fill("https://github.com/centralmind/gateway")

            # Enable AI Analysis (optional)
            print("📍 Configuring scan options...")
            # ai_checkbox = page.locator('#enableLLM')
            # ai_checkbox.check()

            # Take screenshot before scan
            page.screenshot(path="dashboard_before_scan.png")

            # Start the scan
            print("📍 Starting security scan...")
            scan_button = page.get_by_text("Start Security Scan")
            scan_button.click()

            # Wait for results (with timeout)
            print("⏳ Waiting for scan results...")
            page.wait_for_selector(".scan-progress", state="visible", timeout=5000)

            # Wait for results to appear
            try:
                page.wait_for_selector("text=Scan Results", timeout=30000)
                print("✅ Scan completed!")

                # Take screenshot of results
                page.screenshot(path="dashboard_results.png", full_page=True)

                # Check if threats were found
                if page.locator("text=Security Threats Detected").count() > 0:
                    threat_count = page.locator(".border.border-gray-200.rounded-lg").count()
                    print(f"⚠️  Found {threat_count} security threats")
                else:
                    print("✅ No security threats detected")

            except Exception as e:
                print(f"❌ Error waiting for results: {e}")
                page.screenshot(path="dashboard_error.png", full_page=True)

                # Check console for errors
                console_messages = page.evaluate("() => window.console.logs || []")
                if console_messages:
                    print("Console logs:", console_messages)

        except Exception as e:
            print(f"❌ Test failed: {e}")
            page.screenshot(path="dashboard_error_final.png")

        finally:
            print("🧹 Cleaning up...")
            browser.close()

if __name__ == "__main__":
    print("🚀 Starting dashboard UI test...")
    test_dashboard()
    print("✅ Test complete!")
