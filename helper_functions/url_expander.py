"""
URL Expansion Module

This module handles URL expansion for shortened URLs and redirects.
Supports multiple expansion methods:
- HTTP-based expansion (fast, for standard redirects)
- Browser-based expansion (Selenium, for JavaScript redirects and bot protection)
- Comprehensive mode (smart method selection with fallback)
- Aggressive mode (attempts expansion on all URLs)
"""

import time
import logging
import re
import requests
from urllib.parse import urlparse, urljoin

# Optional: Selenium for JavaScript-based redirects
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# URL shortening services (24+ known services)
SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "tr.im", "cli.gs", "j.mp", "bit.do", "short.link",
    "tiny.cc", "u.to", "v.gd", "cutt.ly", "rebrand.ly", "shorte.st",
    "bl.ink", "lc.chat", "hyperurl.co", "s.id", "clc.am", "bc.vc",
    "shorturl.at", "short.io", "link.to", "soo.gd", "clck.ru"
]


def extract_redirect_from_html(html_content, base_url):
    """
    Extract redirect URL from HTML meta refresh tags or JavaScript redirects.
    
    Args:
        html_content: HTML content as string
        base_url: Base URL for resolving relative URLs
    
    Returns:
        str or None: Extracted redirect URL, or None if not found
    """
    # Check for meta refresh tag
    meta_refresh = re.search(
        r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'](\d+);?\s*url=([^"\']+)["\']',
        html_content,
        re.IGNORECASE
    )
    if meta_refresh:
        redirect_url = meta_refresh.group(2)
        return urljoin(base_url, redirect_url)
    
    # Check for JavaScript window.location redirects
    js_redirect = re.search(
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        html_content,
        re.IGNORECASE
    )
    if js_redirect:
        redirect_url = js_redirect.group(1)
        return urljoin(base_url, redirect_url)
    
    # Check for document.location redirects
    js_doc_redirect = re.search(
        r'document\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        html_content,
        re.IGNORECASE
    )
    if js_doc_redirect:
        redirect_url = js_doc_redirect.group(1)
        return urljoin(base_url, redirect_url)
    
    return None


def expand_url_with_browser(short_url, timeout=10, headless=True):
    """
    Expand URL using Selenium browser automation (handles JavaScript redirects).
    This is slower but can bypass bot protection and JavaScript-based redirects.
    
    Args:
        short_url: The URL to expand
        timeout: Maximum time to wait for redirect (seconds)
        headless: Run browser in headless mode (default: True)
    
    Returns:
        tuple: (expanded_url, redirect_count, success)
    """
    if not SELENIUM_AVAILABLE:
        logger.error("Selenium not available. Install with: pip install selenium")
        return short_url, 0, False
    
    driver = None
    try:
        # Ensure URL has scheme
        if not short_url.startswith(('http://', 'https://')):
            short_url = 'http://' + short_url
        
        logger.info(f"[BROWSER] Expanding URL with Selenium: {short_url}")
        
        # Configure Chrome options
        chrome_options = Options()
        if headless:
            chrome_options.add_argument('--headless=new')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        # Initialize driver
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(timeout)
        
        # Track URL changes
        initial_url = short_url
        driver.get(short_url)
        
        # Wait a bit for JavaScript redirects
        time.sleep(2)
        
        # Get final URL
        final_url = driver.current_url
        
        # Estimate redirect count (simplified)
        redirect_count = 1 if final_url != initial_url else 0
        
        logger.info(f"[BROWSER] Expanded to: {final_url} (via browser)")
        
        return final_url, redirect_count, True
        
    except TimeoutException:
        logger.warning(f"[BROWSER] Timeout loading URL: {short_url}")
        return short_url, 0, False
        
    except WebDriverException as e:
        logger.error(f"[BROWSER] WebDriver error: {str(e)}")
        logger.info("Make sure Chrome/Chromium is installed and chromedriver is in PATH")
        return short_url, 0, False
        
    except Exception as e:
        logger.error(f"[BROWSER] Unexpected error: {str(e)}")
        return short_url, 0, False
        
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass


def has_shortening_service(url):
    """
    Check if URL uses a known URL shortening service.
    Returns True if shortened, False otherwise.
    """
    url_lower = url.lower()
    return any(shortener in url_lower for shortener in SHORTENERS)


def expand_url(short_url, timeout=5, max_redirects=10):
    """
    Expand a shortened URL to its final destination using HTTP requests.
    
    Args:
        short_url: The shortened URL to expand
        timeout: Request timeout in seconds (default: 5)
        max_redirects: Maximum number of redirects to follow (default: 10)
    
    Returns:
        tuple: (expanded_url, redirect_count, success)
            - expanded_url: The final URL after all redirects
            - redirect_count: Number of redirects followed
            - success: Boolean indicating if expansion was successful
    """
    try:
        # Ensure URL has scheme
        if not short_url.startswith(('http://', 'https://')):
            short_url = 'http://' + short_url
        
        logger.info(f"Expanding URL: {short_url}")
        
        # Create a session to control redirect behavior
        session = requests.Session()
        session.max_redirects = max_redirects
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Try HEAD request first (faster, doesn't download content)
        try:
            response = session.head(
                short_url,
                allow_redirects=True,
                timeout=timeout,
                headers=headers
            )
            
            expanded = response.url
            redirect_count = len(response.history)
            
            # If HEAD didn't work or returned error status, try GET
            if redirect_count == 0 and response.status_code >= 400:
                raise requests.exceptions.RequestException(f"HEAD returned {response.status_code}")
        
        except requests.exceptions.RequestException:
            # If HEAD fails, try GET
            logger.info(f"HEAD request failed, trying GET for: {short_url}")
            response = session.get(
                short_url,
                allow_redirects=True,
                timeout=timeout,
                headers=headers,
                stream=False  # Need to read content for HTML parsing
            )
            
            expanded = response.url
            redirect_count = len(response.history)
            
            # Check for bot protection (Cloudflare, etc.)
            if response.status_code == 403:
                cf_mitigated = response.headers.get('cf-mitigated', '')
                if 'challenge' in cf_mitigated.lower():
                    logger.warning(f"Bot protection detected (Cloudflare challenge) for: {short_url}")
                    # Try to extract redirect from HTML as last resort
                    try:
                        html_content = response.text[:10000]  # Only read first 10KB
                        html_redirect = extract_redirect_from_html(html_content, short_url)
                        if html_redirect and html_redirect != short_url:
                            logger.info(f"Extracted redirect from HTML: {html_redirect}")
                            return html_redirect, 1, True
                    except Exception as e:
                        logger.debug(f"Failed to extract HTML redirect: {e}")
                    return short_url, 0, False
            
            # If no HTTP redirect but we got 200, try to extract from HTML
            if redirect_count == 0 and response.status_code == 200:
                try:
                    html_content = response.text[:10000]  # Only read first 10KB
                    html_redirect = extract_redirect_from_html(html_content, short_url)
                    if html_redirect and html_redirect != short_url:
                        logger.info(f"Found HTML/JS redirect: {html_redirect}")
                        expanded = html_redirect
                        redirect_count = 1
                except Exception as e:
                    logger.debug(f"Failed to extract HTML redirect: {e}")
        
        logger.info(f"Expanded to: {expanded} (Redirects: {redirect_count})")
        return expanded, redirect_count, True
        
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects for URL: {short_url}")
        return short_url, max_redirects, False
        
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout while expanding URL: {short_url}")
        return short_url, 0, False
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to expand URL {short_url}: {str(e)}")
        return short_url, 0, False
        
    except Exception as e:
        logger.error(f"Unexpected error expanding URL {short_url}: {str(e)}")
        return short_url, 0, False


def expand_url_comprehensive(url, timeout=10, prefer_browser=False):
    """
    Comprehensive URL expansion with smart method selection.
    
    Automatically chooses the best expansion strategy:
    - If prefer_browser=True: Use browser (slowest but most reliable)
    - Otherwise: Try HTTP first, fallback to browser on failure
    
    Args:
        url: URL to expand
        timeout: Request timeout in seconds (default: 10)
        prefer_browser: Always use browser if available (default: False)
    
    Returns:
        dict: {
            'expanded_url': Final URL after all expansions,
            'redirect_count': Number of redirects,
            'expansion_success': Whether expansion succeeded,
            'method_used': 'http', 'browser', or 'none',
            'was_expanded': Boolean (True if URL changed)
        }
    """
    result = {
        'expanded_url': url,
        'redirect_count': 0,
        'expansion_success': True,
        'method_used': 'none',
        'was_expanded': False
    }
    
    if not url or url.startswith('#'):
        return result
    
    try:
        if prefer_browser and SELENIUM_AVAILABLE:
            # Skip HTTP, go straight to browser
            logger.debug(f"Using browser directly for: {url}")
            final_url, redirects, success = expand_url_with_browser(url, timeout=timeout)
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['method_used'] = 'browser'
            result['was_expanded'] = (final_url != url)
        else:
            # Try HTTP first
            final_url, redirects, success = expand_url(url, timeout=timeout)
            
            # If HTTP failed and we have Selenium, try browser as fallback
            if not success and SELENIUM_AVAILABLE and not prefer_browser:
                logger.debug(f"HTTP failed, trying browser fallback for: {url}")
                final_url, redirects, success = expand_url_with_browser(url, timeout=timeout)
                result['method_used'] = 'browser'
            else:
                result['method_used'] = 'http'
            
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['was_expanded'] = (final_url != url)
    
    except Exception as e:
        logger.error(f"Error in comprehensive expansion: {e}")
        result['expansion_success'] = False
    
    return result


def expand_url_if_shortened(url, timeout=5, use_browser=False):
    """
    Check if URL is shortened and expand it if necessary.
    
    Args:
        url: The URL to check and potentially expand
        timeout: Request timeout in seconds (default: 5)
        use_browser: Use Selenium browser automation for JavaScript redirects (default: False)
    
    Returns:
        dict: {
            'original_url': The input URL,
            'expanded_url': The expanded URL (same as original if not shortened),
            'is_shortened': Boolean indicating if URL was shortened,
            'redirect_count': Number of redirects followed,
            'expansion_success': Boolean indicating if expansion was successful,
            'method': Expansion method used ('http', 'browser', or 'none')
        }
    """
    result = {
        'original_url': url,
        'expanded_url': url,
        'is_shortened': False,
        'redirect_count': 0,
        'expansion_success': True,
        'method': 'none'
    }
    
    # Check if URL uses a shortening service
    if has_shortening_service(url):
        result['is_shortened'] = True
        
        if use_browser and SELENIUM_AVAILABLE:
            # Use browser automation
            expanded, redirects, success = expand_url_with_browser(url, timeout=timeout)
            result['expanded_url'] = expanded
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['method'] = 'browser'
        else:
            # Use HTTP requests
            expanded, redirects, success = expand_url(url, timeout=timeout)
            result['expanded_url'] = expanded
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['method'] = 'http'
            
            # If HTTP failed and browser is available, suggest browser method
            if not success and SELENIUM_AVAILABLE:
                logger.info(f"HTTP expansion failed. Consider using use_browser=True for: {url}")
    
    return result


def expand_url_full_coverage(url, timeout=10, fallback_http=True):
    """
    Maximum coverage URL expansion with optional HTTP fallback.
    
    Always tries to expand ALL URLs using the best available method.
    
    Args:
        url: Any URL to expand
        timeout: Request timeout in seconds (default: 10)
        fallback_http: Try HTTP first, then browser if it fails (default: True)
    
    Returns:
        dict: {
            'expanded_url': Final URL,
            'redirect_count': Number of redirects,
            'expansion_success': Success status,
            'method_used': 'http', 'browser', or 'none',
            'was_expanded': Boolean (True if URL changed)
        }
    """
    result = {
        'expanded_url': url,
        'redirect_count': 0,
        'expansion_success': True,
        'method_used': 'none',
        'was_expanded': False
    }
    
    if not url:
        return result
    
    try:
        if fallback_http:
            # Try HTTP first (fast), fallback to browser
            final_url, redirects, success = expand_url(url, timeout=timeout)
            
            if success and redirects > 0:
                # HTTP worked
                result['method_used'] = 'http'
            elif SELENIUM_AVAILABLE:
                # HTTP didn't find redirects, try browser
                logger.debug(f"HTTP found no redirects, trying browser for: {url}")
                final_url, redirects, success = expand_url_with_browser(url, timeout=timeout)
                result['method_used'] = 'browser'
            else:
                result['method_used'] = 'http'
            
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
        else:
            # Always use browser (most reliable, slower)
            if not SELENIUM_AVAILABLE:
                logger.warning("Browser mode requested but Selenium not available. Falling back to HTTP.")
                final_url, redirects, success = expand_url(url, timeout=timeout)
                result['method_used'] = 'http'
            else:
                final_url, redirects, success = expand_url_with_browser(url, timeout=timeout)
                result['method_used'] = 'browser'
            
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
        
        result['was_expanded'] = (result['expanded_url'] != url)
    
    except Exception as e:
        logger.error(f"Error in full coverage expansion: {e}")
        result['expansion_success'] = False
    
    return result


def expand_url_aggressive(url, timeout=5, use_browser=False):
    """
    Attempt URL expansion on ALL URLs without checking shortener list.
    This catches unknown/new shortening services and custom redirects.
    
    SAFE: Only follows HTTP redirects (max 10), doesn't download full content.
    
    Args:
        url: Any URL to attempt expansion on
        timeout: Request timeout in seconds (default: 5)
        use_browser: Use browser automation for JavaScript redirects (default: False)
    
    Returns:
        dict: {
            'original_url': The input URL,
            'expanded_url': The final URL after redirects,
            'redirect_count': Number of redirects followed,
            'expansion_success': Boolean indicating success,
            'was_expanded': Boolean (True if URL changed),
            'method': Expansion method used ('http', 'browser', or 'none')
        }
    """
    result = {
        'original_url': url,
        'expanded_url': url,
        'redirect_count': 0,
        'expansion_success': True,
        'was_expanded': False,
        'method': 'none'
    }
    
    try:
        if use_browser and SELENIUM_AVAILABLE:
            # Use browser automation
            final_url, redirects, success = expand_url_with_browser(url, timeout=timeout)
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['was_expanded'] = (final_url != url)
            result['method'] = 'browser'
        else:
            # Use HTTP requests (always attempt, no shortener check)
            final_url, redirects, success = expand_url(url, timeout=timeout)
            result['expanded_url'] = final_url
            result['redirect_count'] = redirects
            result['expansion_success'] = success
            result['was_expanded'] = (final_url != url)
            result['method'] = 'http'
    
    except Exception as e:
        logger.warning(f"Error in aggressive expansion of {url}: {e}")
        result['expansion_success'] = False
    
    return result
