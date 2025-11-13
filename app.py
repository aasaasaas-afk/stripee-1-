#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import json
import time
import os
import threading
from bs4 import BeautifulSoup
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from datetime import datetime, timedelta
import random
import asyncio
import aiohttp
from queue import Queue
import signal

BOT_TOKEN = "8315841088:AAHOvimC_sSr0n7mGKEsK3u3cbg26Ta_3aE"
FLARESOLVERR_URL = "https://rockyxdorker.onrender.com/v1"
OWNER_ID = 8278658138
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# CMS patterns
CMS_PATTERNS = {
    'Shopify': r'cdn\.shopify\.com|shopify\.js',
    'BigCommerce': r'cdn\.bigcommerce\.com|bigcommerce\.com',
    'Wix': r'static\.parastorage\.com|wix\.com',
    'Squarespace': r'static1\.squarespace\.com|squarespace-cdn\.com',
    'WooCommerce': r'wp-content/plugins/woocommerce/',
    'Magento': r'static/version\d+/frontend/|magento/',
    'PrestaShop': r'prestashop\.js|prestashop/',
    'OpenCart': r'catalog/view/theme|opencart/',
    'Shopify Plus': r'shopify-plus|cdn\.shopifycdn\.net/',
    'Salesforce Commerce Cloud': r'demandware\.edgesuite\.net/',
    'WordPress': r'wp-content|wp-includes/',
    'Joomla': r'media/jui|joomla\.js|media/system/js|joomla\.javascript/',
    'Drupal': r'sites/all/modules|drupal\.js/|sites/default/files|drupal\.settings\.js/',
    'TYPO3': r'typo3temp|typo3/',
    'Concrete5': r'concrete/js|concrete5/',
    'Umbraco': r'umbraco/|umbraco\.config/',
    'Sitecore': r'sitecore/content|sitecore\.js/',
    'Kentico': r'cms/getresource\.ashx|kentico\.js/',
    'Episerver': r'episerver/|episerver\.js/',
    'Custom CMS': r'(?:<meta name="generator" content="([^"]+)")'
}

# Security patterns
SECURITY_PATTERNS = {
    '3D Secure': r'3d_secure|threed_secure|secure_redirect',
}

# Payment gateways list
PAYMENT_GATEWAYS = [
    "PayPal", "Stripe", "Braintree", "Square", "Cybersource", "lemon-squeezy",
    "Authorize.Net", "2Checkout", "Adyen", "Worldpay", "SagePay",
    "Checkout.com", "Bolt", "Eway", "PayFlow", "Payeezy",
    "Paddle", "Mollie", "Viva Wallet", "Rocketgateway", "Rocketgate",
    "Rocket", "Auth.net", "Authnet", "rocketgate.com", "Recurly",
    "Shopify", "WooCommerce", "BigCommerce", "Magento", "Magento Payments",
    "OpenCart", "PrestaShop", "3DCart", "Ecwid", "Shift4Shop",
    "Shopware", "VirtueMart", "CS-Cart", "X-Cart", "LemonStand",
    "Convergepay", "PaySimple", "oceanpayments", "eProcessing",
    "hipay", "cybersourse", "payjunction", "usaepay", "creo",
    "SquareUp", "ebizcharge", "cpay", "Moneris", "cardknox",
    "matt sorra", "Chargify", "Paytrace", "hostedpayments", "securepay",
    "blackbaud", "LawPay", "clover", "cardconnect", "bluepay",
    "fluidpay", "Ebiz", "chasepaymentech", "Auruspay", "sagepayments",
    "paycomet", "geomerchant", "realexpayments", "Razorpay",
    "Apple Pay", "Google Pay", "Samsung Pay", "Cash App",
    "Revolut", "Zelle", "Alipay", "WeChat Pay", "PayPay", "Line Pay",
    "Skrill", "Neteller", "WebMoney", "Payoneer", "Paysafe",
    "Payeer", "GrabPay", "PayMaya", "MoMo", "TrueMoney",
    "Touch n Go", "GoPay", "JKOPay", "EasyPaisa",
    "Paytm", "UPI", "PayU", "PayUBiz", "PayUMoney", "CCAvenue",
    "Mercado Pago", "PagSeguro", "Yandex.Checkout", "PayFort", "MyFatoorah",
    "Kushki", "RuPay", "BharatPe", "Midtrans", "MOLPay",
    "iPay88", "KakaoPay", "Toss Payments", "NaverPay",
    "Bizum", "Culqi", "Pagar.me", "Rapyd", "PayKun", "Instamojo",
    "PhonePe", "BharatQR", "Freecharge", "Mobikwik", "BillDesk",
    "Citrus Pay", "RazorpayX", "Cashfree",
    "Klarna", "Affirm", "Afterpay",
    "Splitit", "Perpay", "Quadpay", "Laybuy", "Openpay",
    "Cashalo", "Hoolah", "Pine Labs", "ChargeAfter",
    "BitPay", "Coinbase Commerce", "CoinGate", "CoinPayments", "Crypto.com Pay",
    "BTCPay Server", "NOWPayments", "OpenNode", "Utrust", "MoonPay",
    "Binance Pay", "CoinsPaid", "BitGo", "Flexa",
    "ACI Worldwide", "Bank of America Merchant Services",
    "JP Morgan Payment Services", "Wells Fargo Payment Solutions",
    "Deutsche Bank Payments", "Barclaycard", "American Express Payment Gateway",
    "Discover Network", "UnionPay", "JCB Payment Gateway",
]

# Social media domains to filter out
SOCIAL_MEDIA_DOMAINS = [
    'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'whatsapp.com',
    'github.com', 'google.com', 'youtube.com', 'tiktok.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'snapchat.com', 'telegram.org', 'discord.com',
    'tumblr.com', 'flickr.com', 'vimeo.com', 'dailymotion.com', 'medium.com'
]

# Queue for background tasks
task_queue = Queue()

# Session for aiohttp
session = None

# Flag to stop autodorking
stop_autodork = {}

# Track active tasks to ensure proper background processing
active_tasks = {}

# Rate limiting
last_edit_time = {}
edit_lock = threading.Lock()

async def init_session():
    global session
    if session is None or session.closed:
        session = aiohttp.ClientSession()

async def close_session():
    global session
    if session and not session.closed:
        await session.close()

def rate_limit_edit(chat_id):
    """Apply rate limiting to message edits"""
    with edit_lock:
        now = time.time()
        if chat_id in last_edit_time:
            elapsed = now - last_edit_time[chat_id]
            if elapsed < 1:  # Minimum 1 second between edits
                sleep_time = 1 - elapsed
                time.sleep(sleep_time)
        last_edit_time[chat_id] = time.time()

def send_message(chat_id, text, reply_to=None, parse_mode="HTML"):
    url = f"{TELEGRAM_API}/sendMessage"
    data = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_to:
        data["reply_to_message_id"] = reply_to
    try:
        response = requests.post(url, data=data, timeout=10)
        result = response.json()
        if not result.get('ok'):
            print(f"Error sending message: {result}")
        return result
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def edit_message(chat_id, message_id, text, parse_mode="HTML"):
    # Apply rate limiting
    rate_limit_edit(chat_id)
    
    url = f"{TELEGRAM_API}/editMessageText"
    data = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(url, data=data, timeout=10)
            result = response.json()
            
            if result.get('ok'):
                return result
            elif result.get('error_code') == 429:
                retry_after = result.get('parameters', {}).get('retry_after', 1)
                print(f"Rate limited, waiting {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            else:
                print(f"Error editing message: {result}")
                return result
        except Exception as e:
            print(f"Error editing message: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
    
    return None

def send_document(chat_id, file_path, caption="", filename=None, reply_to=None):
    url = f"{TELEGRAM_API}/sendDocument"
    if not filename:
        filename = os.path.basename(file_path)
    
    with open(file_path, 'rb') as file:
        files = {'document': (filename, file)}
        data = {'chat_id': chat_id, 'parse_mode': 'HTML'}
        if caption:
            data['caption'] = caption
        if reply_to:
            data['reply_to_message_id'] = reply_to
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(url, files=files, data=data, timeout=30)
                result = response.json()
                
                if result.get('ok'):
                    return result
                elif result.get('error_code') == 429:
                    retry_after = result.get('parameters', {}).get('retry_after', 1)
                    print(f"Rate limited, waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                else:
                    print(f"Error sending document: {result}")
                    return result
            except Exception as e:
                print(f"Error sending document: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
        
        return None

def get_updates(offset=None):
    url = f"{TELEGRAM_API}/getUpdates"
    params = {"timeout": 10}
    if offset:
        params["offset"] = offset
    try:
        response = requests.get(url, params=params, timeout=15)
        return response.json()
    except Exception as e:
        print(f"Error getting updates: {e}")
        return None

def create_progress_bar(progress, total=100, width=15):
    filled = int(width * progress / total)
    bar = '▰' * filled + '▱' * (width - filled)
    return f"{bar} {progress}%"

def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return None

def is_social_media_url(url):
    domain = extract_domain(url)
    if domain:
        for social_domain in SOCIAL_MEDIA_DOMAINS:
            if social_domain in domain:
                return True
    return False

def is_ecosia_url(url):
    """Check if URL contains ecosia"""
    return 'ecosia' in url.lower()

def filter_urls(urls):
    """Filter out social media and ecosia URLs"""
    filtered_urls = []
    filtered_count = 0
    for url in urls:
        if not is_social_media_url(url) and not is_ecosia_url(url):
            # Ensure URL has proper scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            filtered_urls.append(url)
        else:
            filtered_count += 1
    return filtered_urls, filtered_count

def deduplicate_by_domain(urls):
    seen_domains = {}
    unique_urls = []
    for url in urls:
        domain = extract_domain(url)
        if domain and domain not in seen_domains:
            seen_domains[domain] = True
            unique_urls.append(url)
    return unique_urls

def extract_urls_from_html(html_content):
    urls = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http://') or href.startswith('https://'):
                if 'ecosia.org' not in href:
                    urls.append(href)
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return unique_urls
    except Exception as e:
        print(f"Error extracting URLs: {e}")
        return []

def search_ecosia_with_flaresolverr(query, page=0):
    try:
        ecosia_url = f"https://www.ecosia.org/search?q={requests.utils.quote(query)}&provider=google&engine=google"
        if page > 0:
            ecosia_url += f"&p={page}"
        payload = {"cmd": "request.get", "url": ecosia_url, "maxTimeout": 60000}
        response = requests.post(FLARESOLVERR_URL, headers={'Content-Type': 'application/json'}, json=payload, timeout=70)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok' and 'solution' in data:
                html_content = data['solution']['response']
                urls = extract_urls_from_html(html_content)
                return urls, None
            else:
                return [], f"Search error: {data.get('message', 'Unknown error')}"
        else:
            return [], f"HTTP Error: {response.status_code}"
    except Exception as e:
        return [], f"Request error: {str(e)}"

def generate_dork_queries(target):
    """Generate high-quality dork queries focused on donation/shopping/checkout sites"""
    target = target.lower()
    queries = []
    
    # Donation-focused queries with specific URL patterns
    queries.append(f"inurl:/donate intext:\"{target}\"")
    queries.append(f"inurl:/donate-us intext:\"{target}\"")
    queries.append(f"inurl:/donation intext:\"{target}\"")
    queries.append(f"inurl:/donations intext:\"{target}\"")
    queries.append(f"inurl:/give intext:\"{target}\"")
    queries.append(f"inurl:/contribute intext:\"{target}\"")
    queries.append(f"inurl:/support-us intext:\"{target}\"")
    queries.append(f"inurl:/fundraising intext:\"{target}\"")
    
    # Shopping cart focused queries
    queries.append(f"inurl:/cart intext:\"{target}\"")
    queries.append(f"inurl:/checkout intext:\"{target}\"")
    queries.append(f"inurl:/shop intext:\"{target}\"")
    queries.append(f"inurl:/store intext:\"{target}\"")
    queries.append(f"inurl:/product intext:\"{target}\"")
    queries.append(f"inurl:/item intext:\"{target}\"")
    queries.append(f"inurl:/buy intext:\"{target}\"")
    queries.append(f"inurl:/purchase intext:\"{target}\"")
    
    # Payment page focused queries
    queries.append(f"inurl:/payment intext:\"{target}\"")
    queries.append(f"inurl:/payments intext:\"{target}\"")
    queries.append(f"inurl:/billing intext:\"{target}\"")
    queries.append(f"inurl:/pay intext:\"{target}\"")
    queries.append(f"inurl:/transaction intext:\"{target}\"")
    queries.append(f"inurl:/transactions intext:\"{target}\"")
    
    # Form-based queries
    queries.append(f"inurl:/form intext:\"{target}\" intext:\"donate\"")
    queries.append(f"inurl:/form intext:\"{target}\" intext:\"payment\"")
    queries.append(f"inurl:/submit intext:\"{target}\" intext:\"donate\"")
    
    # Specific to payment gateways
    queries.append(f"intext:\"{target}\" intext:\"donate\" intext:\"€\"")
    queries.append(f"intext:\"{target}\" intext:\"donate\" intext:\"$\"")
    queries.append(f"intext:\"{target}\" intext:\"donate\" intext:\"£\"")
    queries.append(f"intext:\"{target}\" intext:\"checkout\" intext:\"€\"")
    queries.append(f"intext:\"{target}\" intext:\"checkout\" intext:\"$\"")
    queries.append(f"intext:\"{target}\" intext:\"checkout\" intext:\"£\"")
    
    # Combine terms
    queries.append(f"intext:\"{target}\" (inurl:donate OR inurl:cart OR inurl:checkout)")
    queries.append(f"intext:\"{target}\" (inurl:donation OR inurl:payment OR inurl:purchase)")
    
    # Randomize the order of queries
    random.shuffle(queries)
    
    return queries

def create_results_file(dork_query, urls, user_id, message_id):
    # Clean the query to make it a valid filename
    clean_query = re.sub(r'[^\w\s-]', '', dork_query)
    clean_query = re.sub(r'\s+', '_', clean_query.strip())
    filename = f"{clean_query}_urls.txt"
    
    # Write URLs to the file, one per line
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url + "\n")
    
    return filename

async def fetch_site(url: str):
    await init_session()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc

    headers = {
        "authority": domain,
        "scheme": "https",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/140.0.0.0 Mobile Safari/537.36",
    }

    try:
        async with session.get(url, headers=headers, timeout=15) as resp:
            text = await resp.text()
            return resp.status, text, resp.headers
    except Exception:
        return None, None, None

def detect_cms(html: str):
    for cms, pattern in CMS_PATTERNS.items():
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            if cms == 'Custom CMS':
                return match.group(1) or "Custom CMS"
            return cms
    return "Unknown"

def detect_security(html: str):
    patterns_3ds = [
        r'3d\s*secure',
        r'verified\s*by\s*visa',
        r'mastercard\s*securecode',
        r'american\s*express\s*safekey',
        r'3ds',
        r'3ds2',
        r'acsurl',
        r'pareq',
        r'three-domain-secure',
        r'secure_redirect',
    ]
    for pattern in patterns_3ds:
        if re.search(pattern, html, re.IGNORECASE):
            return "3D Secure Detected ✅"
    return "2D (No 3D Secure Found ❌)"

def detect_gateways(html: str):
    detected = []
    for gateway in PAYMENT_GATEWAYS:
        # Use word boundaries to avoid partial matches (e.g., "PayU" in "PayUmoney")
        pattern = r'\b' + re.escape(gateway) + r'\b'
        if re.search(pattern, html, re.IGNORECASE):
            detected.append(gateway)
    return ", ".join(detected) if detected else "None Detected"

def detect_captcha(html: str):
    html_lower = html.lower()
    if "hcaptcha" in html_lower:
        return "hCaptcha Detected ✅"
    elif "recaptcha" in html_lower or "g-recaptcha" in html_lower:
        return "reCAPTCHA Detected ✅"
    elif "captcha" in html_lower:
        return "Generic Captcha Detected ✅"
    return "No Captcha Detected"

def detect_cloudflare(html: str, headers=None, status=None):
    if headers is None:
        headers = {}
    lower_keys = [k.lower() for k in headers.keys()]
    server = headers.get('Server', '').lower()
    # Check for Cloudflare presence (CDN or protection)
    cloudflare_indicators = [
        r'cloudflare',
        r'cf-ray',
        r'cf-cache-status',
        r'cf-browser-verification',
        r'__cfduid',
        r'cf_chl_',
        r'checking your browser',
        r'enable javascript and cookies',
        r'ray id',
        r'ddos protection by cloudflare',
    ]
    # Check headers for Cloudflare signatures
    if 'cf-ray' in lower_keys or 'cloudflare' in server or 'cf-cache-status' in lower_keys:
        # Parse HTML to check for verification/challenge page
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip().lower() if soup.title else ''
        challenge_indicators = [
            "just a moment",
            "attention required",
            "checking your browser",
            "enable javascript and cookies to continue",
            "ddos protection by cloudflare",
            "please wait while we verify",
        ]
        # Check for challenge page indicators
        if any(indicator in title for indicator in challenge_indicators):
            return "Cloudflare Verification Detected ✅"
        if any(re.search(pattern, html, re.IGNORECASE) for pattern in cloudflare_indicators):
            return "Cloudflare Verification Detected ✅"
        if status in (403, 503) and 'cloudflare' in html.lower():
            return "Cloudflare Verification Detected ✅"
        return "Cloudflare Present (No Verification) 🔍"
    return "None"

def detect_graphql(html: str):
    if re.search(r'/graphql|graphqlendpoint|apollo-client|query\s*\{|mutation\s*\{', html, re.IGNORECASE):
        return "GraphQL Detected ✅"
    return "No GraphQL Detected ❌"

def detect_server(headers):
    if headers and 'Server' in headers:
        return headers['Server']
    return "Unknown"

async def scan_site(url):
    """Scan a site and return its details"""
    status_code, html, headers = await fetch_site(url)
    
    if status_code is None:
        return None
    
    domain = extract_domain(url)
    cms = detect_cms(html) if html else "Unknown"
    security = detect_security(html) if html else "Unknown"
    captcha = detect_captcha(html) if html else "Unknown"
    cloudflare = detect_cloudflare(html, headers, status_code) if html and headers else "Unknown"
    graphql = detect_graphql(html) if html else "Unknown"
    gateways = detect_gateways(html) if html else "None Detected"
    server = detect_server(headers) if headers else "Unknown"
    
    # Check if site is "clean" (no captcha, no cloudflare, no graphql, 2D security)
    is_clean = (
        "No Captcha Detected" in captcha and
        "None" in cloudflare and
        "No GraphQL Detected" in graphql and
        "2D" in security
    )
    
    return {
        "url": url,
        "domain": domain,
        "status_code": status_code,
        "cms": cms,
        "security": security,
        "captcha": captcha,
        "cloudflare": cloudflare,
        "graphql": graphql,
        "gateways": gateways,
        "server": server,
        "is_clean": is_clean
    }

def format_site_result(site_data):
    """Format site data for display"""
    if not site_data:
        return ""
    
    return f"""<a href='https://t.me/abtlnx'>⊀</a> <b>𝐔𝐑𝐋</b> ↬ <code>{site_data['url']}</code>
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐒𝐓𝐀𝐓𝐔𝐒</b> ↬ <code>{site_data['status_code']}</code>
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐂𝐌𝐒</b> ↬ <code>{site_data['cms']}</code>
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐒𝐄𝐂𝐔𝐑𝐈𝐓𝐘</b> ↬ {site_data['security']}
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐂𝐀𝐏𝐓𝐂𝐇𝐀</b> ↬ {site_data['captcha']}
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐂𝐋𝐎𝐔𝐃𝐅𝐋𝐀𝐑𝐄</b> ↬ {site_data['cloudflare']}
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐆𝐑𝐀𝐏𝐇𝐐𝐋</b> ↬ {site_data['graphql']}
<a href='https://t.me/abtlnx'>⊀</a> <b>𝐏𝐀𝐘𝐌𝐄𝐍𝐓𝐒</b> ↬ {site_data['gateways']}

"""

def format_clean_site_result(site_data, count, total):
    """Format clean site result for autodork"""
    if not site_data:
        return ""
    
    return f"""⩙ 𝑮𝒂𝒕𝒆 𝑫𝒆𝒄𝒌 𝑹𝒆𝒔𝒖𝒍𝒕𝒔
⊀ 𝐔𝐑𝐋 ↬ <code>{site_data['url']}</code>
⊀ 𝐒𝐓𝐀𝐓𝐔𝐒 ↬ <code>{site_data['status_code']}</code>
⊀ 𝐂𝐌𝐒 ↬ <code>{site_data['cms']}</code>
⊀ 𝐒𝐄𝐂𝐔𝐑𝐈𝐓𝐘 ↬ {site_data['security']}
⊀ 𝐂𝐀𝐏𝐓𝐂𝐇𝐀 ↬ {site_data['captcha']}
⊀ 𝐂𝐋𝐎𝐔𝐃𝐅𝐋𝐀𝐑𝐄 ↬ {site_data['cloudflare']}
⊀ 𝐆𝐑𝐀𝐏𝐇𝐐𝐋 ↬ {site_data['graphql']}
⊀ 𝐏𝐀𝐘𝐌𝐄𝐍𝐓𝐒 ↬ {site_data['gateways']}
⊀ 𝐒𝐄𝐑𝐕𝐄𝐑 ↬ <code>{site_data['server']}</code>
⌬ 𝐃𝐞𝐯 ↬ kคli liຖนxx

⩙ 𝑺𝒄𝒂𝒏𝒏𝒊𝒏𝒈 ↬ {count}/{total}
"""

def process_dork_with_progress(dork_query, chat_id, message_id):
    """Process dork query and return URLs"""
    all_urls = []
    completed_pages = 0
    total_pages = 10
    lock = threading.Lock()
    start_time = time.time()
    total_filtered = 0
    last_progress_update = 0
    
    try:
        # Send initial progress message
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑰𝒏𝒊𝒕𝒊𝒂𝒍𝒊𝒛𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▱▱▱▱▱▱▱▱ 0%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Starting parallel requests..."""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_page = {executor.submit(search_ecosia_with_flaresolverr, dork_query, page): page for page in range(total_pages)}
            for future in as_completed(future_to_page):
                page = future_to_page[future]
                try:
                    urls, error = future.result()
                    if error:
                        print(f"Error on page {page}: {error}")
                    elif urls:
                        # Filter social media and ecosia URLs
                        filtered_urls, filtered_count = filter_urls(urls)
                        total_filtered += filtered_count
                        
                        with lock:
                            all_urls.extend(filtered_urls)
                            completed_pages += 1
                            
                            # Update progress only every 2 pages or on completion to avoid rate limiting
                            now = time.time()
                            if completed_pages % 2 == 0 or completed_pages == total_pages:
                                if now - last_progress_update > 2:  # Minimum 2 seconds between updates
                                    # Update progress
                                    progress_percent = int((completed_pages / total_pages) * 90) + 10
                                    progress_bar = create_progress_bar(progress_percent)
                                    
                                    # Calculate estimated time remaining
                                    elapsed_time = time.time() - start_time
                                    if completed_pages > 0:
                                        avg_time_per_page = elapsed_time / completed_pages
                                        remaining_pages = total_pages - completed_pages
                                        eta_seconds = avg_time_per_page * remaining_pages
                                        eta = str(timedelta(seconds=int(eta_seconds)))
                                    else:
                                        eta = "Calculating..."
                                    
                                    # Format query for better display
                                    formatted_query = dork_query
                                    if len(formatted_query) > 30:
                                        formatted_query = formatted_query[:27] + "..."
                                    
                                    progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑷𝒓𝒐𝒄𝒆𝒔𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{formatted_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ {progress_bar}
⊀ 𝐏𝐚𝐠𝐞𝐬 ↬ {completed_pages}/{total_pages}
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(all_urls)}
⊀ 𝐅𝐢𝐥𝐭𝐞𝐫𝐞𝐝 ↬ {total_filtered}
⊀ 𝐄𝐓𝐀 ↬ {eta}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Processing..."""
                                    
                                    print(f"Updating progress message")
                                    edit_result = edit_message(chat_id, message_id, progress_text)
                                    if not edit_result or not edit_result.get('ok'):
                                        print(f"Failed to update progress message: {edit_result}")
                                    last_progress_update = now
                    else:
                        with lock:
                            completed_pages += 1
                except Exception as e:
                    print(f"Error processing page {page}: {e}")
                    with lock:
                        completed_pages += 1
        
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑫𝒆𝒅𝒖𝒑𝒍𝒊𝒄𝒂𝒕𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▰▰▰▰▰▰▰▰▰▰▰▰ 95%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Deduplicating domains..."""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        deduplicated_urls = deduplicate_by_domain(unique_urls)
        
        elapsed_time = time.time() - start_time
        time_str = str(timedelta(seconds=int(elapsed_time)))
        
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑪𝒐𝒎𝒑𝒍𝒆𝒕𝒆 ✅
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▰▰▰▰▰▰▰▰▰▰▰▰ 100%
⊀ 𝐓𝐢𝒎𝒆 ↬ {time_str}
⊀ 𝐅𝐢𝒏𝒂𝒍 𝐔𝐑𝐋𝐒 ↬ {len(deduplicated_urls)}
⊀ 𝐅𝐢𝐥𝒕𝒆𝒓𝒆𝒅 ↬ {total_filtered}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Complete!"""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        return {"urls": deduplicated_urls, "total_found": len(unique_urls), "after_dedupe": len(deduplicated_urls), "filtered": total_filtered}, None
    except Exception as e:
        print(f"Error in process_dork_with_progress: {e}")
        return None, f"Unexpected Error: {str(e)}"

async def process_autodork(dork_query, chat_id, message_id):
    """Process autodork query with multiple rounds and scan sites"""
    all_urls = []
    all_clean_sites = []
    start_time = time.time()
    
    # Initialize stop flag for this chat
    stop_autodork[chat_id] = False
    
    try:
        # Send initial message
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑰𝒏𝒊𝒕𝒊𝒂𝒍𝒊𝒛𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▱▱▱▱▱▱▱▱ 0%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Starting 10 rounds of dorking...

⚠️ Send /stop to cancel autodorking"""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        # Process 3 rounds of dorking
        total_rounds = 10
        completed_rounds = 0
        
        for round_num in range(1, total_rounds + 1):
            # Check if stop was requested
            if stop_autodork.get(chat_id, False):
                progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒕𝒐𝒑𝒑𝒆𝒅 ⚠️
⊀ 𝐑𝐨𝐮𝐧𝐝𝐬 ↬ {completed_rounds}/{total_rounds}
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(all_urls)}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Autodorking stopped by user"""
                
                print(f"Updating progress message")
                edit_result = edit_message(chat_id, message_id, progress_text)
                if not edit_result or not edit_result.get('ok'):
                    print(f"Failed to update progress message: {edit_result}")
                return False
            
            # Update progress for current round
            progress_percent = int((completed_rounds / total_rounds) * 30)
            progress_bar = create_progress_bar(progress_percent)
            
            progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑫𝒐𝒓𝒌𝒊𝒏𝒈 ⚡
⊀ 𝐑𝐨𝐮𝐧𝐝 ↬ {round_num}/{total_rounds}
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ {progress_bar}
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(all_urls)}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Processing round {round_num}...

⚠️ Send /stop to cancel autodorking"""
            
            print(f"Updating progress message")
            edit_result = edit_message(chat_id, message_id, progress_text)
            if not edit_result or not edit_result.get('ok'):
                print(f"Failed to update progress message: {edit_result}")
            
            # Process the query for this round
            all_pages = 10
            completed_pages = 0
            round_urls = []
            total_filtered = 0
            last_round_update = 0
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_page = {executor.submit(search_ecosia_with_flaresolverr, dork_query, page): page for page in range(all_pages)}
                for future in as_completed(future_to_page):
                    page = future_to_page[future]
                    try:
                        urls, error = future.result()
                        if error:
                            print(f"Error on page {page}: {error}")
                        elif urls:
                            # Filter social media and ecosia URLs
                            filtered_urls, filtered_count = filter_urls(urls)
                            total_filtered += filtered_count
                            round_urls.extend(filtered_urls)
                        
                        completed_pages += 1
                        
                        # Update progress less frequently to avoid rate limiting
                        now = time.time()
                        if completed_pages % 3 == 0 or completed_pages == all_pages:
                            if now - last_round_update > 3:  # Minimum 3 seconds between updates
                                # Update progress for this round
                                round_progress = int((completed_pages / all_pages) * 100)
                                round_progress_bar = create_progress_bar(round_progress)
                                
                                progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑫𝒐𝒓𝒌𝒊𝒏𝒈 ⚡
⊀ 𝐑𝐨𝐮𝐧𝐝 ↬ {round_num}/{total_rounds}
⊀ 𝐏𝐚𝐠𝐞𝐬 ↬ {completed_pages}/{all_pages}
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ {round_progress_bar}
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(all_urls) + len(round_urls)}
⊀ 𝐅𝐢𝐥𝐭𝐞𝐫𝐞𝐝 ↬ {total_filtered}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Processing round {round_num}...

⚠️ Send /stop to cancel autodorking"""
                                
                                print(f"Updating progress message")
                                edit_result = edit_message(chat_id, message_id, progress_text)
                                if not edit_result or not edit_result.get('ok'):
                                    print(f"Failed to update progress message: {edit_result}")
                                last_round_update = now
                    except Exception as e:
                        print(f"Error processing page {page}: {e}")
                        completed_pages += 1
            
            # Add round URLs to all URLs
            all_urls.extend(round_urls)
            completed_rounds += 1
        
        # Deduplicate URLs
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑫𝒆𝒅𝒖𝒑𝒍𝒊𝒄𝒂𝒕𝒊𝒏𝒈 ⚡
⊀ 𝐑𝐨𝐮𝐧𝐝𝐬 ↬ {completed_rounds}/{total_rounds}
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▰▰▰▰▰▰▰▰▰▰ 30%
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(all_urls)}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Deduplicating domains..."""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        deduplicated_urls = deduplicate_by_domain(unique_urls)
        
        # Limit to 300 URLs for scanning
        urls_to_scan = deduplicated_urls[:300]
        
        # Update progress for scanning phase
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒄𝒂𝒏𝒏𝒊𝒏𝒈 ⚡
⊀ 𝐔𝐑𝐋𝐒 ↬ {len(urls_to_scan)}
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▰▰▰▰▱▱▱▱ 30%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Scanning sites for clean results...

⚠️ Send /stop to cancel autodorking"""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        # Scan each URL
        total_urls = len(urls_to_scan)
        scanned_urls = 0
        clean_sites_count = 0
        last_scan_update = 0
        
        for url in urls_to_scan:
            # Check if stop was requested
            if stop_autodork.get(chat_id, False):
                progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒕𝒐𝒑𝒑𝒆𝒅 ⚠️
⊀ 𝐒𝐜𝐚𝐧𝐧𝐞𝐝 ↬ {scanned_urls}/{total_urls}
⊀ 𝐂𝐥𝐞𝐚𝐧 ↬ {clean_sites_count}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Autodorking stopped by user"""
                
                print(f"Updating progress message")
                edit_result = edit_message(chat_id, message_id, progress_text)
                if not edit_result or not edit_result.get('ok'):
                    print(f"Failed to update progress message: {edit_result}")
                return False
            
            # Scan the site
            site_data = await scan_site(url)
            
            if site_data and site_data['is_clean']:
                all_clean_sites.append(site_data)
                clean_sites_count += 1
                
                # Send clean site instantly with proper formatting
                clean_site_text = format_clean_site_result(site_data, clean_sites_count, total_urls)
                
                print(f"Sending clean site message")
                send_result = send_message(chat_id, clean_site_text, reply_to=message_id)
                if not send_result or not send_result.get('ok'):
                    print(f"Failed to send clean site message: {send_result}")
            
            scanned_urls += 1
            
            # Update progress less frequently to avoid rate limiting
            now = time.time()
            if scanned_urls % 20 == 0 or scanned_urls == total_urls:
                if now - last_scan_update > 5:  # Minimum 5 seconds between updates
                    progress_percent = 30 + int((scanned_urls / total_urls) * 70)
                    progress_bar = create_progress_bar(progress_percent)
                    
                    # Calculate estimated time remaining
                    elapsed_time = time.time() - start_time
                    if scanned_urls > 0:
                        avg_time_per_url = elapsed_time / scanned_urls
                        remaining_urls = total_urls - scanned_urls
                        eta_seconds = avg_time_per_url * remaining_urls
                        eta = str(timedelta(seconds=int(eta_seconds)))
                    else:
                        eta = "Calculating..."
                    
                    progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒄𝒂𝒏𝒏𝒊𝒏𝒈 ⚡
⊀ 𝐔𝐑𝐋𝐒 ↬ {scanned_urls}/{total_urls}
⊀ 𝐂𝐥𝐞𝐚𝐧 ↬ {clean_sites_count}
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ {progress_bar}
⊀ 𝐄𝐓𝐀 ↬ {eta}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Scanning sites for clean results...

⚠️ Send /stop to cancel autodorking"""
                    
                    print(f"Updating progress message")
                    edit_result = edit_message(chat_id, message_id, progress_text)
                    if not edit_result or not edit_result.get('ok'):
                        print(f"Failed to update progress message: {edit_result}")
                    last_scan_update = now
        
        # Final results
        elapsed_time = time.time() - start_time
        time_str = str(timedelta(seconds=int(elapsed_time)))
        
        progress_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑪𝒐𝒎𝒑𝒍𝒆𝒕𝒆 ✅
⊀ 𝐓𝐢𝒎𝒆 ↬ {time_str}
⊀ 𝐓𝐨𝐭𝐚𝐥 𝐔𝐑𝐋𝐒 ↬ {len(deduplicated_urls)}
⊀ 𝐒𝐜𝐚𝐧𝐧𝐞𝐝 ↬ {scanned_urls}
⊀ 𝐂𝐥𝐞𝐚𝐧 ↬ {clean_sites_count}
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Complete!"""
        
        print(f"Updating progress message")
        edit_result = edit_message(chat_id, message_id, progress_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        
        # Send final summary if there are clean sites
        if all_clean_sites:
            filename = f"clean_sites_{chat_id}_{message_id}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                for i, site in enumerate(all_clean_sites, 1):
                    f.write(f"{i}. {site['url']}\n")
                    f.write(f"   Status: {site['status_code']}\n")
                    f.write(f"   CMS: {site['cms']}\n")
                    f.write(f"   Security: {site['security']}\n")
                    f.write(f"   Captcha: {site['captcha']}\n")
                    f.write(f"   Cloudflare: {site['cloudflare']}\n")
                    f.write(f"   GraphQL: {site['graphql']}\n")
                    f.write(f"   Payment Gateways: {site['gateways']}\n")
                    f.write(f"   Server: {site['server']}\n\n")
            
            summary_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒖𝒎𝒎𝒂𝒓𝒚 ✅

⊀ 𝐓𝐨𝐭𝐚𝐥 𝐂𝐥𝐞𝐚𝐧 ↬ {len(all_clean_sites)}
⊀ 𝐓𝐢𝒎𝒆 ↬ {time_str}

⤷ 𝐃𝐨𝐰𝐧𝐥𝐨𝐚𝐝 ⤷

📁 All clean sites have been sent individually above.
📄 Full report with all clean sites is attached.

🔗 Join our channel: https://t.me/abtlnx"""
            
            print(f"Sending document with summary")
            # Don't reply to the deleted message
            doc_result = send_document(chat_id, filename, summary_text, f"clean_sites_{len(all_clean_sites)}.txt", reply_to=None)
            if not doc_result or not doc_result.get('ok'):
                print(f"Failed to send document: {doc_result}")
            os.remove(filename)
        else:
            no_results_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑵𝒐 𝑪𝒍𝒆𝒂𝒏 𝑺𝒊𝒕𝒆𝒔 ❌

⊀ 𝐓𝐢𝒎𝒆 ↬ {time_str}
⊀ 𝐓𝐨𝐭𝐚𝐥 𝐔𝐑𝐋𝐒 ↬ {len(deduplicated_urls)}
⊀ 𝐒𝐜𝐚𝐧𝐧𝐞𝐝 ↬ {scanned_urls}
⊀ 𝐂𝐥𝒆𝒂𝒏 ↬ 0
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ No clean sites found. Try different queries."""
            
            print(f"Updating progress message with no results")
            edit_result = edit_message(chat_id, message_id, no_results_text)
            if not edit_result or not edit_result.get('ok'):
                print(f"Failed to update progress message: {edit_result}")
        
        return True
    except Exception as e:
        print(f"Error in process_autodork: {e}")
        error_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ {str(e)}"""
        
        print(f"Updating progress message with error")
        edit_result = edit_message(chat_id, message_id, error_text)
        if not edit_result or not edit_result.get('ok'):
            print(f"Failed to update progress message: {edit_result}")
        return False

def is_bot_command(text):
    bot_commands = ['/start', '/dork', '/list', '/gen', '/autodork', '/stop']
    for command in bot_commands:
        if text.startswith(command):
            return True
    return False

def handle_message(message):
    chat_id = message['chat']['id']
    user_id = message['from']['id']
    message_id = message['message_id']
    text = message.get('text', '')
    username = message['from'].get('username', 'Unknown')
    first_name = message['from'].get('first_name', 'User')
    chat_type = message['chat'].get('type', 'private')
    print(f"📨 Message from {user_id} (@{username}) in {chat_type}: {text}")
    
    # Handle /stop command
    if text == '/stop':
        if chat_id in stop_autodork and not stop_autodork[chat_id]:
            stop_autodork[chat_id] = True
            response_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑺𝒕𝒐𝒑𝒑𝒊𝒏𝒈 ⚠️

⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Autodorking will stop at the next checkpoint."""
            
            send_result = send_message(chat_id, response_text, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send stop message: {send_result}")
        else:
            response_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ No active autodorking process to stop."""
            
            send_result = send_message(chat_id, response_text, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send stop message: {send_result}")
        return
    
    if not is_bot_command(text):
        return
    
    # Handle /autodork command with regular dork syntax
    if text.startswith('/autodork'):
        # Extract query from command
        query_part = text[10:].strip()  # Remove '/autodork' prefix
        
        if not query_part:
            response_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⊀ 𝐌𝐢𝐬𝐬𝐢𝐧𝐠 𝐐𝐮𝐞𝐫𝐲 ↬ Please provide a query!

⤷ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ⤷

• /autodork intext:"stripe" inurl:"donate" intext:"€"
• /autodork inurl:/donate intext:"paypal"

⌬ 𝐓𝐢𝐩𝐬 ⤷

• Autodork will process 3 rounds of dorking
• Up to 300 URLs will be scanned
• Clean sites will be sent instantly"""
            
            send_result = send_message(chat_id, response_text, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send autodork help message: {send_result}")
            return
        
        # Start processing
        initial_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑰𝒏𝒊𝒕𝒊𝒂𝒍𝒊𝒛𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{query_part}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▱▱▱▱▱▱▱▱ 0%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Starting..."""
        
        processing_response = send_message(chat_id, initial_text, reply_to=message_id)
        if not processing_response or not processing_response.get('ok'):
            print(f"Failed to send initial autodork message: {processing_response}")
            return
        
        processing_msg_id = processing_response.get('result', {}).get('message_id')
        
        # Add to task queue for background processing
        task_queue.put(('autodork', query_part, chat_id, processing_msg_id))
        return
    
    if text == '/start' or text.startswith('/start '):
        role = "👑 Owner" if user_id == OWNER_ID else "✅ Approved"
        welcome_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ {role}
⊀ 𝐔𝐬𝐞𝐫 ↬ {first_name}
⊀ 𝐈𝐃 ↬ {user_id}
⊀ 𝐔𝐬𝐞𝐫𝐧𝐚𝐦𝐞 ↬ @{username}

⤷ 𝐂𝐨𝐦𝐦𝐚𝐧𝐝𝐬 ⤷

• /dork &lt;query&gt; - Parse URLs using dork query
• /gen &lt;target&gt; - Generate high-quality dork queries for donation sites
• /autodork &lt;query&gt; - Advanced dorking with site scanning
• /stop - Stop autodorking process
• /list - List all available commands

⤷ 𝐅𝐞𝐚𝐭𝐮𝐫𝐞𝐬 ⤷

• Parallel processing (10 pages)
• Domain deduplication
• Real-time progress tracking
• Social media filtering
• Ecosia URL filtering
• Query generator for donation sites
• Site scanning with instant clean site notifications
• Background processing (no command blocking)

⌬ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ↬ /dork "index of" admin
⌬ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ↬ /gen stripe
⌬ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ↬ /autodork intext:"stripe" inurl:"donate" intext:"€"

🔗 Join our channel: https://t.me/abtlnx"""
        
        message_parts = [welcome_text[i:i+4096] for i in range(0, len(welcome_text), 4096)]
        for part in message_parts:
            send_result = send_message(chat_id, part, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send welcome message part: {send_result}")
    elif text == '/list':
        list_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑪𝒐𝒎𝒎𝐚𝐧𝐝 𝑳𝒊𝒔𝒕 ⚡

⤷ 𝐀𝐯𝐚𝐢𝐥𝐚𝐛𝐥𝐞 𝐂𝐨𝐦𝐦𝐚𝐧𝐝𝐬 ⤷

• /dork &lt;query&gt; - Parse URLs using dork query
• /gen &lt;target&gt; - Generate high-quality dork queries for donation sites
• /autodork &lt;query&gt; - Advanced dorking with site scanning
• /stop - Stop autodorking process
• /list - List all available commands
• /start - Show welcome message and features

⤷ 𝐓𝐢𝐩𝐬 ⤷

• Use specific dork queries for better results
• Results are deduplicated by domain
• All URLs are saved to a text file
• Social media URLs are automatically filtered
• Ecosia URLs are automatically filtered
• Use /gen with payment processors like stripe, braintree, adyen
• Use /autodork for advanced dorking with site scanning
• Use /stop to cancel autodorking at any time

⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Command list complete!

🔗 Join our channel: https://t.me/abtlnx"""
        
        send_result = send_message(chat_id, list_text, reply_to=message_id)
        if not send_result or not send_result.get('ok'):
            print(f"Failed to send list message: {send_result}")
    elif text.startswith('/gen '):
        target = text[5:].strip()
        if not target:
            error_msg = """⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⊀ 𝐌𝐢𝐬𝐬𝐢𝐧𝐠 𝐓𝐚𝐫𝐠𝐞𝐭 ↬ Please provide a target!

⤷ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ⤷

• /gen stripe
• /gen braintree
• /gen adyen"""
            send_result = send_message(chat_id, error_msg, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send gen error message: {send_result}")
            return
        
        # Generate queries
        queries = generate_dork_queries(target)
        
        # Format the response
        response_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑸𝒖𝐞𝐫𝐲 𝑮𝒆𝒏𝒆𝒓𝒂𝒕𝒐𝐫 ✅

⊀ 𝐓𝐚𝐫𝐠𝐞𝐭 ↬ <code>{target}</code>
⊀ 𝐅𝐨𝐜𝐮𝐝 ↬ Donation/Shopping/Checkout Sites

⤷ 𝐆𝐞𝐧𝐞𝐫𝐚𝐭𝐞𝐝 𝐃𝐨𝐫𝐤𝐬 ⤷

"""
        
        for query in queries:
            response_text += f"• <code>{query}</code>\n"
        
        response_text += f"""

⌬ 𝐔𝐬𝐚𝐠𝐞 ↬ Copy any query and use with /dork or /autodork

🔗 Join our channel: https://t.me/abtlnx"""
        
        send_result = send_message(chat_id, response_text, reply_to=message_id)
        if not send_result or not send_result.get('ok'):
            print(f"Failed to send gen result message: {send_result}")
    elif text.startswith('/dork '):
        dork_query = text[6:].strip()
        if not dork_query:
            error_msg = """⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⊀ 𝐌𝐢𝐬𝐬𝐢𝐧𝐠 𝐐𝐮𝐞𝐫𝐲 ↬ Please provide a dork query!

⤷ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ⤷

• /dork "index of" admin"""
            send_result = send_message(chat_id, error_msg, reply_to=message_id)
            if not send_result or not send_result.get('ok'):
                print(f"Failed to send dork error message: {send_result}")
            return
        
        # Start processing
        initial_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑰𝒏𝒊𝒕𝒊𝒂𝒍𝒊𝒛𝒊𝒏𝒈 ⚡
⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▱▱▱▱▱▱▱▱ 0%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ Starting..."""
        
        processing_response = send_message(chat_id, initial_text, reply_to=message_id)
        if not processing_response or not processing_response.get('ok'):
            print(f"Failed to send initial dork message: {processing_response}")
            return
        
        processing_msg_id = processing_response.get('result', {}).get('message_id')
        
        # Add to task queue for background processing
        task_queue.put(('dork', dork_query, chat_id, processing_msg_id))
    elif text == '/dork':
        help_msg = """⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⊀ 𝐌𝐢𝐬𝐬𝐢𝐧𝐠 𝐐𝐮𝐞𝐫𝐲 ↬ Usage: /dork &lt;your_query&gt;

⤷ 𝐄𝐱𝐚𝐦𝐩𝐥𝐞 ⤷

• /dork "index of" admin"""
        send_result = send_message(chat_id, help_msg, reply_to=message_id)
        if not send_result or not send_result.get('ok'):
            print(f"Failed to send dork help message: {send_result}")

def background_worker():
    """Background worker to process tasks"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        try:
            # Get a task from the queue
            task_type, data, chat_id, message_id = task_queue.get()
            
            if task_type == 'dork':
                # Process dork query
                dork_query = data
                result, error = process_dork_with_progress(dork_query, chat_id, message_id)
                
                if error:
                    error_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑬𝒓𝒓𝒐𝒓 ❌

⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▱▱▱▱▱▱▱▱ 0%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ {error}"""
                    edit_result = edit_message(chat_id, message_id, error_text)
                    if not edit_result or not edit_result.get('ok'):
                        print(f"Failed to update error message: {edit_result}")
                elif result and 'urls' in result and result['urls']:
                    urls = result['urls']
                    url_count = len(urls)
                    total_found = result['total_found']
                    after_dedupe = result['after_dedupe']
                    filtered = result['filtered']
                    
                    # Create file with URLs
                    filename = create_results_file(dork_query, urls, chat_id, message_id)
                    
                    # Delete the progress message
                    delete_url = f"{TELEGRAM_API}/deleteMessage"
                    delete_data = {"chat_id": chat_id, "message_id": message_id}
                    delete_result = requests.post(delete_url, data=delete_data)
                    if not delete_result.json().get('ok'):
                        print(f"Failed to delete progress message: {delete_result.json()}")
                    
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    caption = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑹𝒆𝒔𝒖𝒍𝒕𝒔 𝑹𝒆𝒂𝒅𝒚 ✅

⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⊀ 𝐓𝐨𝐭𝐚𝐥 𝐅𝐨𝐮𝐧𝐝 ↬ {total_found} URLs
⊀ 𝐔𝐧𝐢𝐪𝐮𝐞 𝐃𝐨𝐦𝐚𝐢𝐧𝐬 ↬ {after_dedupe}
⊀ 𝐅𝐢𝐥𝐭𝐞𝐫𝐞𝐝 ↬ {filtered}
⊀ 𝐓𝐢𝒎𝒆 ↬ {timestamp}

🔗 Join our channel: https://t.me/abtlnx"""
                    
                    # Send the file without replying to the deleted message
                    doc_result = send_document(chat_id, filename, caption, reply_to=None)
                    if not doc_result or not doc_result.get('ok'):
                        print(f"Failed to send document: {doc_result}")
                    
                    # Remove the file after sending
                    os.remove(filename)
                    print(f"✅ Processed '{dork_query}' - {url_count} domains")
                else:
                    no_results_text = f"""⩙ 𝑺𝒕𝒂𝒕𝒖𝒔 ↬ 𝑵𝒐 𝑹𝒆𝒔𝒖𝒍𝒕𝒔 ❌

⊀ 𝐐𝐮𝐞𝐫𝐲 ↬ <code>{dork_query}</code>
⤷ 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 ↬ ▰▰▰▰▰▰▰▰▰▰▰▰ 100%
⌬ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 ↬ No URLs found. Try a different query."""
                    edit_result = edit_message(chat_id, message_id, no_results_text)
                    if not edit_result or not edit_result.get('ok'):
                        print(f"Failed to update no results message: {edit_result}")
            
            elif task_type == 'autodork':
                # Process autodork query
                dork_query = data
                loop.run_until_complete(process_autodork(dork_query, chat_id, message_id))
            
            # Mark task as done
            task_queue.task_done()
            
        except Exception as e:
            print(f"Error in background worker: {e}")

def main():
    print("=" * 60)
    print("🤖 Dork URL Parser Bot - Beast Edition")
    print("=" * 60)
    print(f"👑 Owner ID: {OWNER_ID}")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")
    print("🔄 Clearing old messages...")
    try:
        clear_response = requests.get(f"{TELEGRAM_API}/getUpdates?offset=-1", timeout=10)
        if clear_response.status_code == 200:
            print("✅ Old messages cleared\n")
    except Exception as e:
        print(f"⚠️ Warning: {e}\n")
    
    # Start background worker thread
    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()
    
    offset = None
    while True:
        try:
            updates = get_updates(offset)
            if updates and updates.get('ok'):
                for update in updates['result']:
                    if 'message' in update:
                        handle_message(update['message'])
                    offset = update['update_id'] + 1
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n👋 Bot stopped")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()
