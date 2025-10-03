import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ScreenshotCapture:
    """Handles screenshot capture using Playwright."""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.playwright_available = False
        
        try:
            from playwright.sync_api import sync_playwright
            self.playwright_available = True
        except ImportError:
            if verbose:
                print("  ⚠️  Playwright not available. Screenshots disabled.")
    
    def capture_screenshot(self, url: str, port: int) -> Optional[Dict[str, Any]]:
        """Capture screenshot of web service using Playwright."""
        if not self.playwright_available:
            return None
            
        try:
            screenshot_dir = "screenshots"
            os.makedirs(screenshot_dir, exist_ok=True)
            
            filename = f"{self.target.replace('.', '_')}_port_{port}_{int(time.time())}.png"
            filepath = os.path.join(screenshot_dir, filename)
            
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.goto(url, timeout=10000, wait_until='networkidle')
                page.screenshot(path=filepath, full_page=True)
                browser.close()
            
            result = {
                'url': url,
                'filepath': filepath,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            if self.verbose:
                print(f"  📸 Screenshot saved: {filepath}")
                
            return result
                
        except Exception as e:
            error_msg = f"Screenshot capture failed for {url}: {str(e)}"
            if self.verbose:
                print(f"  ⚠️  {error_msg}")
            return None