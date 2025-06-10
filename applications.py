import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import ttkbootstrap as bttk
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.constants import *
import threading
import queue
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, quote, unquote
import webbrowser
import re
import ssl
import socket
from datetime import datetime
import whois
import time
import html
import base64

# --- نیازمندی‌های جدید ---
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import dns.resolver

# --- وارد کردن کتابخانه‌های سلنیوم ---
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium_stealth import stealth

# دیکشنری Regex
SECRETS_REGEX = {
    "Google API Key": r'AIzaSy[A-Za-z0-9\-_]{35}', "AWS Access Key ID": r'AKIA[0-9A-Z]{16}',
    "GitHub Token": r'ghp_[a-zA-Z0-9]{36}', "Generic Token/Secret": r'(?i)("token"|"secret"|"password"|"auth_key")\s*[:=]\s*["\']([^\'"]{10,})["\']'
}

# لیست مسیرهای رایج برای اسکن دایرکتوری
COMMON_PATHS = [
    'admin', 'administrator', 'login', 'wp-login.php', 'dashboard', 'admin.php', 'config',
    'uploads', 'test', 'dev', 'backup', 'old', 'v1', 'v2', 'api', 'app', 'shop', 'blog',
    '.env', '.env.local', 'env.php', 'config.json', 'config.php', 'config.js', 'package.json',
    '.git/config', '.svn/entries', 'server-status', 'phpinfo.php', 'info.php', 'logs',
    'backup.zip', 'backup.tar.gz', 'site.zip', 'sql.zip', 'database.sql'
]


# --- توابع کمکی ---
def get_ssl_info(hostname, stop_event):
    try:
        if stop_event.is_set(): return None
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            if stop_event.is_set(): return None
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        expires_on = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expires_on - datetime.now()).days
        return {'issuer': issuer.get('organizationName', 'N/A'), 'subject': subject.get('commonName', 'N/A'), 'expires_on': expires_on.strftime('%Y-%m-%d'), 'days_left': days_left}
    except Exception:
        return None

def get_host_info(hostname, stop_event):
    info = {'ip': 'N/A', 'isp': 'N/A', 'country': 'N/A', 'registrar': 'N/A', 'creation_date': 'N/A', 'expiration_date': 'N/A'}
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(4)
        if stop_event.is_set(): return info
        ip_address = socket.gethostbyname(hostname)
        info['ip'] = ip_address
        if stop_event.is_set(): return info
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=country,isp', timeout=3)
            ip_data = response.json()
            info['isp'] = ip_data.get('isp', 'N/A')
            info['country'] = ip_data.get('country', 'N/A')
        except requests.RequestException:
            pass
        if stop_event.is_set(): return info
        try:
            w = whois.whois(hostname)
            info['registrar'] = w.registrar
            if isinstance(w.creation_date, list): info['creation_date'] = w.creation_date[0].strftime('%Y-%m-%d')
            else: info['creation_date'] = w.creation_date.strftime('%Y-%m-%d')
            if isinstance(w.expiration_date, list): info['expiration_date'] = w.expiration_date[0].strftime('%Y-%m-%d')
            else: info['expiration_date'] = w.expiration_date.strftime('%Y-%m-%d')
        except Exception:
            pass
    except socket.gaierror:
        info['ip'] = "دامنه یافت نشد"
    finally:
        socket.setdefaulttimeout(original_timeout)
    return info

def analyze_page_seo(soup):
    issues = set()
    title_tag = soup.find('title')
    if not title_tag or not title_tag.get_text().strip(): issues.add('title_missing')
    elif not 50 <= len(title_tag.get_text().strip()) <= 60: issues.add('title_length')
    meta_desc_tag = soup.find('meta', attrs={'name': 'description'})
    if not meta_desc_tag or not meta_desc_tag.get('content', '').strip(): issues.add('meta_desc_missing')
    elif not 150 <= len(meta_desc_tag.get('content', '').strip()) <= 160: issues.add('meta_desc_length')
    h1_tags = soup.find_all('h1')
    if len(h1_tags) == 0: issues.add('h1_missing')
    elif len(h1_tags) > 1: issues.add('h1_multiple')
    if any(not img.get('alt', '').strip() for img in soup.find_all('img')): issues.add('alt_text_missing')
    if not soup.find('meta', attrs={'name': 'viewport'}): issues.add('viewport_missing')
    if not soup.find('script', attrs={'type': 'application/ld+json'}): issues.add('schema_missing')
    return issues

def analyze_page_content(page_text, current_link, results_queue, found_emails_set):
    soup = BeautifulSoup(page_text, 'html.parser')
    for secret_type, regex_pattern in SECRETS_REGEX.items():
        for match in re.finditer(regex_pattern, page_text):
            found_value = match.group(2) if len(match.groups()) > 1 else match.group(0)
            results_queue.put(('secret_found', {'type': secret_type, 'value': found_value, 'source': current_link}))

    resources = {'link': soup.find_all('a', href=True), 'image': soup.find_all('img', src=True), 'script': soup.find_all('script', src=True), 'style': soup.find_all('link', rel='stylesheet', href=True), 'form': soup.find_all('form'), 'comment': soup.find_all(string=lambda text: isinstance(text, Comment))}
    new_internal_links = []
    hostname = urlparse(current_link).hostname
    for res_type, tags in resources.items():
        for tag in tags:
            if res_type == 'link':
                href, full_url = tag.get('href', ''), urljoin(current_link, tag.get('href', '')).split('#')[0]
                if urlparse(full_url).netloc != hostname and full_url.startswith('http'): results_queue.put(('external_link', full_url))
                elif urlparse(full_url).netloc == hostname: new_internal_links.append(full_url)
            elif res_type not in ['form', 'comment']: url_attr = 'href' if res_type == 'style' else 'src'; results_queue.put((res_type, urljoin(current_link, tag.get(url_attr, ''))))
            else: results_queue.put((res_type, ''))

    emails_in_page = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', page_text)
    for email in emails_in_page:
        if email not in found_emails_set: found_emails_set.add(email); results_queue.put(('email', email))

    generator_tag = soup.find('meta', attrs={'name': 'generator'})
    if generator_tag: results_queue.put(('generator', generator_tag.get('content', '')))

    seo_issues = analyze_page_seo(soup)
    for issue_key in seo_issues:
        results_queue.put(('seo_issue', {'key': issue_key, 'url': current_link}))
    return new_internal_links

# --- موتورهای تحلیل و حمله ---
def directory_bruteforce_engine(target_url, results_queue, stop_event):
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'})
        for i, path in enumerate(COMMON_PATHS):
            if stop_event.is_set():
                results_queue.put(("---STATUS---", "اسکن دایرکتوری توسط کاربر متوقف شد."))
                break
            full_url = urljoin(target_url, path)
            status_text = f"اسکن مسیرها: {i+1}/{len(COMMON_PATHS)} ({path})"
            results_queue.put(("---STATUS---", status_text))
            try:
                response = session.head(full_url, timeout=4, allow_redirects=False)
                if response.status_code in [200, 204, 301, 302, 307, 401, 403, 405]:
                    content_length = response.headers.get('Content-Length', 'N/A')
                    results_queue.put(('dir_brute_result', {'url': full_url, 'status': response.status_code, 'size': content_length}))
            except requests.RequestException:
                pass
    except Exception as e:
        results_queue.put(("---ERROR---", f"خطا در موتور اسکن دایرکتوری: {e}"))
    finally:
        results_queue.put(("---STOP_SCAN_UI---", None))

def initial_recon_and_crawl(target_url, results_queue, stop_event, use_selenium):
    try:
        results_queue.put(("---STATUS---", "شروع تحلیل اولیه..."))
        hostname = urlparse(target_url).hostname
        if not hostname:
            raise ValueError("آدرس URL نامعتبر است.")
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'})
        if stop_event.is_set(): raise InterruptedError
        host_info = get_host_info(hostname, stop_event)
        if stop_event.is_set(): raise InterruptedError
        results_queue.put(('host_info', host_info))
        if urlparse(target_url).scheme == 'https':
            if stop_event.is_set(): raise InterruptedError
            ssl_info = get_ssl_info(hostname, stop_event)
            if stop_event.is_set(): raise InterruptedError
            if ssl_info: results_queue.put(('ssl_result', ssl_info))
        if stop_event.is_set(): raise InterruptedError
        initial_response = session.get(target_url, timeout=10, allow_redirects=True)
        initial_response.raise_for_status()
        headers = initial_response.headers
        security_headers = {'Content-Security-Policy': 'CSP' in headers, 'Strict-Transport-Security': 'HSTS' in headers, 'X-Content-Type-Options': 'nosniff' in headers.get('X-Content-Type-Options', ''), 'X-Frame-Options': 'X-Frame-Options' in headers, 'Referrer-Policy': 'Referrer-Policy' in headers, 'Permissions-Policy': 'Permissions-Policy' in headers}
        results_queue.put(('headers_result', security_headers))
        for cookie in initial_response.cookies:
            if stop_event.is_set(): raise InterruptedError
            raw_cookie_header = initial_response.headers.get('Set-Cookie', '')
            match = re.search(r'SameSite=([^;]+)', raw_cookie_header, re.IGNORECASE)
            samesite_val = match.group(1) if match else 'N/A'
            results_queue.put(('cookie_detail', {'name': cookie.name, 'secure': cookie.secure, 'httponly': 'HttpOnly' in raw_cookie_header, 'samesite': samesite_val}))
        results_queue.put(('tech_profile', {'Server': headers.get('Server', 'N/A'), 'X-Powered-By': headers.get('X-Powered-By', 'N/A')}))
        if stop_event.is_set(): raise InterruptedError
        robots_url, sitemap_url = urljoin(target_url, '/robots.txt'), urljoin(target_url, '/sitemap.xml')
        robots_found = session.head(robots_url, timeout=3, allow_redirects=True).status_code == 200
        if stop_event.is_set(): raise InterruptedError
        sitemap_found = session.head(sitemap_url, timeout=3, allow_redirects=True).status_code == 200
        results_queue.put(('file_check', {'robots.txt': robots_found, 'sitemap.xml': sitemap_found}))
        if use_selenium:
            selenium_spider_logic(target_url, results_queue, stop_event)
        else:
            requests_spider_logic(target_url, session, results_queue, stop_event)
    except InterruptedError:
        results_queue.put(("---STATUS---", "عملیات توسط کاربر متوقف شد."))
    except (requests.exceptions.RequestException, ValueError) as e:
        results_queue.put(("---ERROR---", f"خطای شبکه یا آدرس نامعتبر: {e}"))
    except Exception as e:
        results_queue.put(("---ERROR---", f"یک خطای ناشناخته رخ داد: {e}"))
    finally:
        results_queue.put(("---STOP_SCAN_UI---", None))

def scroll_to_bottom(driver, stop_event):
    """تابع کمکی برای اسکرول کردن تا انتهای صفحه و بارگذاری تمام محتوا."""
    last_height = driver.execute_script("return document.body.scrollHeight")
    scroll_attempts = 0
    while scroll_attempts < 15: # حداکثر 15 بار اسکرول برای جلوگیری از حلقه بی‌نهایت
        if stop_event.is_set():
            break
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            time.sleep(2)
        except InterruptedError:
            break
        
        new_height = driver.execute_script("return document.body.scrollHeight")
        if new_height == last_height:
            break
        last_height = new_height
        scroll_attempts += 1

def selenium_spider_logic(target_url, results_queue, stop_event):
    driver = None
    try:
        results_queue.put(("---STATUS---", "اجرای مرورگر در حالت Stealth..."))
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        
        options.add_argument('--headless=new')
        options.add_argument('--mute-audio')
        options.add_argument('--log-level=3')
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)

        driver = webdriver.Chrome(service=service, options=options)
        stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32", webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
        
        driver.set_page_load_timeout(30)
        
    except WebDriverException as e:
        results_queue.put(("---ERROR---", f"خطا در اجرای Selenium: {e}\nمطمئن شوید کروم نصب است."))
        return
        
    crawled_links, found_emails, links_to_crawl = set(), set(), [target_url]
    try:
        while links_to_crawl and not stop_event.is_set():
            current_link = links_to_crawl.pop(0)
            if current_link in crawled_links:
                continue
            
            try:
                if stop_event.is_set(): break
                
                results_queue.put(("---STATUS---", f"پیمایش با سلنیوم: {current_link[:70]}..."))
                driver.get(current_link)
                
                WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                
                results_queue.put(("---STATUS---", "در حال اسکرول برای بارگذاری محتوای داینامیک..."))
                scroll_to_bottom(driver, stop_event)
                
                time.sleep(2)

                if stop_event.is_set(): break
                
                crawled_links.add(current_link)
                results_queue.put(('link', current_link))
                
                page_source = driver.page_source
                if page_source:
                    new_links = analyze_page_content(page_source, current_link, results_queue, found_emails)
                    for link in new_links:
                        if link not in crawled_links and link not in links_to_crawl:
                            links_to_crawl.append(link)
                else:
                    results_queue.put(("---ERROR---", f"صفحه {current_link[:80]} منبع معتبری برنگرداند."))

            except TimeoutException:
                results_queue.put(("---ERROR---", f"زمان انتظار برای لود {current_link[:80]} تمام شد. ادامه با لینک بعدی..."))
            except Exception as e:
                results_queue.put(("---ERROR---", f"خطا در پیمایش {current_link[:80]}: {e}"))
                
    finally:
        if driver:
            driver.quit()

def requests_spider_logic(target_url, session, results_queue, stop_event):
    crawled_links, found_emails, links_to_crawl = set(), set(), [target_url]
    while links_to_crawl and not stop_event.is_set():
        current_link = links_to_crawl.pop(0)
        if current_link in crawled_links: continue
        try:
            if stop_event.is_set(): break
            results_queue.put(("---STATUS---", f"پیمایش با ریکوئست: {current_link[:70]}..."))
            response = session.get(current_link, timeout=10)
            crawled_links.add(current_link)
            results_queue.put(('link', current_link))
            if response.status_code == 200:
                new_links = analyze_page_content(response.text, current_link, results_queue, found_emails)
                for link in new_links:
                    if link not in crawled_links and link not in links_to_crawl:
                        links_to_crawl.append(link)
            else:
                results_queue.put(("---ERROR---", f"خطا در {current_link[:80]} (وضعیت: {response.status_code})"))
        except requests.RequestException as e:
            results_queue.put(("---ERROR---", f"خطا در پیمایش {current_link[:80]}: {e}"))

# --- پنجره ها و منطق ابزارهای جدید ---

class WhoisWindow(bttk.Toplevel):
    def __init__(self, parent_app):
        super().__init__(title="Whois Lookup", master=parent_app.root)
        self.transient(parent_app.root)
        self.geometry("600x500")
        self.parent_app = parent_app
        
        input_frame = bttk.Frame(self, padding=10)
        input_frame.pack(fill=X)
        
        bttk.Label(input_frame, text="دامنه:").pack(side=RIGHT, padx=5)
        self.domain_entry = bttk.Entry(input_frame, bootstyle="primary")
        self.domain_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        self.domain_entry.insert(0, urlparse(parent_app.url_entry.get()).hostname or "")
        
        self.lookup_button = bttk.Button(input_frame, text="جستجو", command=self.start_lookup, bootstyle="info")
        self.lookup_button.pack(side=LEFT)
        
        self.results_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.results_text.config(state='disabled')

    def start_lookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("خطا", "لطفاً یک دامنه وارد کنید.", parent=self)
            return
        self.lookup_button.config(state="disabled")
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"در حال جستجوی Whois برای {domain}...")
        self.results_text.config(state='disabled')
        threading.Thread(target=self.whois_logic, args=(domain,), daemon=True).start()

    def whois_logic(self, domain):
        try:
            w = whois.whois(domain)
            result = str(w)
        except Exception as e:
            result = f"خطا در دریافت اطلاعات Whois:\n{e}"
        
        self.after(0, self.update_results, result)

    def update_results(self, result):
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, result)
        self.results_text.config(state='disabled')
        self.lookup_button.config(state="normal")


class DnsWindow(bttk.Toplevel):
    def __init__(self, parent_app):
        super().__init__(title="DNS Lookup", master=parent_app.root)
        self.transient(parent_app.root)
        self.geometry("600x500")
        self.parent_app = parent_app
        
        input_frame = bttk.Frame(self, padding=10)
        input_frame.pack(fill=X)
        
        bttk.Label(input_frame, text="دامنه:").pack(side=RIGHT, padx=5)
        self.domain_entry = bttk.Entry(input_frame, bootstyle="primary")
        self.domain_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        self.domain_entry.insert(0, urlparse(parent_app.url_entry.get()).hostname or "")
        
        self.lookup_button = bttk.Button(input_frame, text="جستجو", command=self.start_lookup, bootstyle="info")
        self.lookup_button.pack(side=LEFT)
        
        self.results_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.results_text.config(state='disabled')

    def start_lookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("خطا", "لطفاً یک دامنه وارد کنید.", parent=self)
            return
        self.lookup_button.config(state="disabled")
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"در حال جستجوی رکوردهای DNS برای {domain}...")
        self.results_text.config(state='disabled')
        threading.Thread(target=self.dns_logic, args=(domain,), daemon=True).start()

    def dns_logic(self, domain):
        results = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        for r_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, r_type)
                results.append(f"--- {r_type} Records ---")
                for rdata in answers:
                    results.append(str(rdata))
                results.append("")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                results.append(f"--- {r_type} Records ---")
                results.append("No records found.")
                results.append("")
            except Exception as e:
                results.append(f"--- {r_type} Records ---")
                results.append(f"Error: {e}")
                results.append("")
        self.after(0, self.update_results, "\n".join(results))

    def update_results(self, result):
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, result)
        self.results_text.config(state='disabled')
        self.lookup_button.config(state="normal")


class PortScannerWindow(bttk.Toplevel):
    def __init__(self, parent_app):
        super().__init__(title="Port Scanner", master=parent_app.root)
        self.transient(parent_app.root)
        self.geometry("600x500")
        
        try:
            initial_ip = socket.gethostbyname(urlparse(parent_app.url_entry.get()).hostname or 'localhost')
        except socket.gaierror:
            initial_ip = "127.0.0.1"
            
        self.target_ip = tk.StringVar(value=initial_ip)
        
        input_frame = bttk.Frame(self, padding=10)
        input_frame.pack(fill=X)
        bttk.Label(input_frame, text="IP / Host:").pack(side=LEFT, padx=5)
        bttk.Entry(input_frame, textvariable=self.target_ip, bootstyle="primary").pack(side=LEFT, fill=X, expand=True, padx=5)
        self.scan_button = bttk.Button(input_frame, text="اسکن", command=self.start_scan, bootstyle="info")
        self.scan_button.pack(side=LEFT)
        
        self.results_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10), bg="#1e1e1e", fg="white")
        self.results_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.results_text.config(state='disabled')
        self.results_text.tag_config('open', foreground='#28a745')
        self.results_text.tag_config('closed', foreground='#dc3545')
        
    def start_scan(self):
        target = self.target_ip.get().strip()
        if not target:
            messagebox.showerror("خطا", "لطفاً یک آدرس IP یا هاست وارد کنید.", parent=self)
            return
        self.scan_button.config(state="disabled")
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"شروع اسکن پورت‌های رایج برای {target}...\n\n")
        self.results_text.config(state='disabled')
        threading.Thread(target=self.scan_logic, args=(target,), daemon=True).start()

    def scan_logic(self, target):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5900, 8080, 8443]
        try:
            target_ip_resolved = socket.gethostbyname(target)
            self.after(0, self.update_results, f"IP Resolved: {target_ip_resolved}\n\n")
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip_resolved, port))
                if result == 0:
                    status_text = f"پورت {port:<5} باز است\n"
                    tag = 'open'
                else:
                    status_text = f"پورت {port:<5} بسته است\n"
                    tag = 'closed'
                self.after(0, self.update_results, status_text, tag)
                sock.close()
        except socket.gaierror:
            self.after(0, self.update_results, "خطا: نام هاست پیدا نشد.\n", 'closed')
        except Exception as e:
            self.after(0, self.update_results, f"خطا: {e}\n", 'closed')
        finally:
            self.after(0, lambda: self.scan_button.config(state="normal"))

    def update_results(self, result, tag=None):
        self.results_text.config(state='normal')
        if tag:
            self.results_text.insert(tk.END, result, tag)
        else:
            self.results_text.insert(tk.END, result)
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')

class SubdomainScannerWindow(bttk.Toplevel):
    def __init__(self, parent_app):
        super().__init__(title="Subdomain Scanner", master=parent_app.root)
        self.transient(parent_app.root)
        self.geometry("600x500")
        self.stop_event = threading.Event()

        self.domain = tk.StringVar(value=urlparse(parent_app.url_entry.get()).hostname or "")
        
        input_frame = bttk.Frame(self, padding=10)
        input_frame.pack(fill=X)
        bttk.Label(input_frame, text="Domain:").pack(side=LEFT, padx=5)
        bttk.Entry(input_frame, textvariable=self.domain, bootstyle="primary").pack(side=LEFT, fill=X, expand=True, padx=5)
        self.scan_button = bttk.Button(input_frame, text="Scan", command=self.start_scan, bootstyle="info")
        self.scan_button.pack(side=LEFT, padx=(0, 5))
        self.stop_button = bttk.Button(input_frame, text="Stop", command=self.stop_scan, bootstyle="danger", state="disabled")
        self.stop_button.pack(side=LEFT)
        
        self.results_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.results_text.config(state='disabled')
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def start_scan(self):
        target = self.domain.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a domain.", parent=self)
            return
        self.stop_event.clear()
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting subdomain scan for {target}...\n\n")
        self.results_text.config(state='disabled')
        threading.Thread(target=self.scan_logic, args=(target,), daemon=True).start()
        
    def stop_scan(self):
        self.stop_event.set()
        self.stop_button.config(state="disabled")

    def on_close(self):
        self.stop_event.set()
        self.destroy()

    def scan_logic(self, target):
        subdomain_list = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'admin', 'panel', 'cpanel', 'blog', 'dev', 'test', 'api', 'shop', 'm', 'support', 'docs', 'staging', 'portal', 'app', 'secure', 'vpn', 'cloud', 'owa', 'files', 'images', 'assets']
        for sub in subdomain_list:
            if self.stop_event.is_set():
                self.after(0, self.update_results, "Scan stopped by user.\n")
                break
            domain_to_check = f"{sub}.{target}"
            try:
                ip = socket.gethostbyname(domain_to_check)
                self.after(0, self.update_results, f"[FOUND] {domain_to_check} -> {ip}\n")
            except socket.error:
                pass
        self.after(0, self.finalize_scan)

    def finalize_scan(self):
        if not self.stop_event.is_set():
            self.update_results("\nScan finished.\n")
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def update_results(self, result):
        self.results_text.config(state='normal')
        self.results_text.insert(tk.END, result)
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')


class EncoderWindow(bttk.Toplevel):
    def __init__(self, parent_app):
        super().__init__(title="Encoder / Decoder", master=parent_app.root)
        self.transient(parent_app.root)
        self.geometry("700x500")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.create_tab("Base64", self.base64_logic)
        self.create_tab("URL", self.url_logic)

    def create_tab(self, name, logic_func):
        tab = bttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text=name)

        input_label = bttk.Label(tab, text="Input:")
        input_label.pack(anchor=W)
        input_text = scrolledtext.ScrolledText(tab, height=8, wrap=tk.WORD)
        input_text.pack(fill=X, pady=5)
        
        button_frame = bttk.Frame(tab)
        button_frame.pack(fill=X, pady=5)
        encode_button = bttk.Button(button_frame, text="Encode", command=lambda: logic_func(input_text, output_text, 'encode'), bootstyle="success-outline")
        encode_button.pack(side=LEFT, padx=5, expand=True, fill=X)
        decode_button = bttk.Button(button_frame, text="Decode", command=lambda: logic_func(input_text, output_text, 'decode'), bootstyle="info-outline")
        decode_button.pack(side=LEFT, padx=5, expand=True, fill=X)

        output_label = bttk.Label(tab, text="Output:")
        output_label.pack(anchor=W, pady=(10, 0))
        output_text = scrolledtext.ScrolledText(tab, height=8, wrap=tk.WORD)
        output_text.pack(fill=X, pady=5)
        output_text.config(state='disabled')
    
    def base64_logic(self, in_widget, out_widget, mode):
        out_widget.config(state='normal')
        out_widget.delete(1.0, tk.END)
        try:
            data = in_widget.get(1.0, tk.END).strip()
            if mode == 'encode':
                result = base64.b64encode(data.encode('utf-8')).decode('utf-8')
            else: # decode
                result = base64.b64decode(data.encode('utf-8')).decode('utf-8')
            out_widget.insert(tk.END, result)
        except Exception as e:
            out_widget.insert(tk.END, f"Error: {e}")
        out_widget.config(state='disabled')

    def url_logic(self, in_widget, out_widget, mode):
        out_widget.config(state='normal')
        out_widget.delete(1.0, tk.END)
        try:
            data = in_widget.get(1.0, tk.END).strip()
            if mode == 'encode':
                result = quote(data)
            else: # decode
                result = unquote(data)
            out_widget.insert(tk.END, result)
        except Exception as e:
            out_widget.insert(tk.END, f"Error: {e}")
        out_widget.config(state='disabled')
        


class SpiderApp:
    def __init__(self, root):
        self.root = root
        self.root.style.theme_use('darkly')
        self.root.title("Web Analysis Suite ")
        self.root.state('zoomed')
        self.root.resizable(True, True)
        self.show_legal_warning()
        self.results_queue, self.stop_event, self.active_thread, self.dos_window = queue.Queue(), threading.Event(), None, None
        self.link_count=self.image_count=self.script_count=self.style_count=0; self.form_count=self.comment_count=self.external_link_count=self.email_count=0; self.found_secrets=0; self.found_emails=set()
        try:
            pass # self.root.iconbitmap('icon.ico')
        except tk.TclError:
            print("فایل آیکون (icon.ico) پیدا نشد.")
        self.seo_issues = {}
        self.SEO_ISSUE_DEFINITIONS = {
            'title_missing': {'factor': 'تگ عنوان', 'status': '❌ مشکل', 'recommendation': 'تگ عنوان در صفحه وجود ندارد.'},
            'title_length': {'factor': 'تگ عنوان', 'status': '⚠️ بهبود لازم', 'recommendation': 'طول عنوان بهینه نیست (باید بین 50-60 باشد).'},
            'meta_desc_missing': {'factor': 'متا توضیحات', 'status': '❌ مشکل', 'recommendation': 'متا توضیحات وجود ندارد.'},
            'meta_desc_length': {'factor': 'متا توضیحات', 'status': '⚠️ بهبود لازم', 'recommendation': 'طول توضیحات بهینه نیست (باید بین 150-160 باشد).'},
            'h1_missing': {'factor': 'تگ H1', 'status': '❌ مشکل', 'recommendation': 'هیچ تگ H1 در صفحه وجود ندارد.'},
            'h1_multiple': {'factor': 'تگ H1', 'status': '⚠️ بهبود لازم', 'recommendation': 'بیش از یک تگ H1 در صفحه وجود دارد.'},
            'alt_text_missing': {'factor': 'متن Alt تصاویر', 'status': '⚠️ بهبود لازم', 'recommendation': 'حداقل یک تصویر متن جایگزین ندارد.'},
            'viewport_missing': {'factor': 'متا Viewport', 'status': '❌ مشکل', 'recommendation': 'تگ Viewport برای واکنش‌گرایی وجود ندارد.'},
            'schema_missing': {'factor': 'دیتای ساختاریافته', 'status': '⚠️ بهبود لازم', 'recommendation': 'دیتای ساختاریافته (Schema) پیدا نشد.'},
        }
        self.create_menu()
        self.create_widgets()
        self.process_queue()

    def show_legal_warning(self):
        try:
            warning_window = bttk.Toplevel(master=self.root)
            warning_window.title("شرایط استفاده و هشدار قانونی"); warning_window.geometry("650x550"); warning_window.resizable(False, False); warning_window.transient(self.root); warning_window.grab_set()
            self.root.update_idletasks()
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (650 // 2); y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (520 // 2); warning_window.geometry(f"+{x}+{y}")
            main_frame = bttk.Frame(warning_window, padding=20); main_frame.pack(expand=True, fill=BOTH)
            header_frame = bttk.Frame(main_frame); header_frame.pack(fill=X, pady=(0, 10))
            title_label = bttk.Label(header_frame, text="شرایط استفاده و هشدار بسیار مهم", font=("Vazirmatn", 16, "bold"), bootstyle="danger", anchor="e", justify="right"); title_label.pack(side=RIGHT)
            icon_label = bttk.Label(header_frame, text="⚠️", font=("Segoe UI Symbol", 28), bootstyle="warning"); icon_label.pack(side=LEFT, padx=(15, 0))
            bttk.Separator(main_frame).pack(fill=X, pady=15)
            sections = [(" هدف ابزار", "این ابزار صرفاً برای اهداف آموزشی، پژوهشی و آزمون نفوذ قانونی بر روی سیستم‌هایی طراحی شده است که شما مالک آن هستید یا مجوز صریح برای آزمون آن را دارید."), (" مسئولیت مستقیم کاربر", "هرگونه سوءاستفاده از این ابزار، از جمله اسکن وب‌سایت‌ها بدون مجوز یا اجرای حملات منع سرویس (DoS)، یک عمل غیرقانونی است. مسئولیت کامل و تمامی عواقب حقوقی و کیفری ناشی از هرگونه استفاده غیرمجاز، مستقیماً بر عهده شخص کاربر است."), (" سلب مسئولیت توسعه‌دهنده", "توسعه‌دهنده هیچ‌گونه مسئولیتی در قبال استفاده نادرست شما از این برنامه و خسارات احتمالی ناشی از آن بر عهده نمی‌گیرد.")]
            for title, body in sections:
                heading = bttk.Label(main_frame, text=title, font=("Vazirmatn", 12, "bold"), justify="right", anchor="e"); heading.pack(fill=X, pady=(10, 2), anchor="e")
                body_label = bttk.Label(main_frame, text=body, wraplength=600, justify="right", anchor="e", font=("Vazirmatn", 11)); body_label.pack(fill=X, pady=(0, 10), anchor="e")
            bttk.Separator(main_frame).pack(fill=X, pady=15)
            acceptance_label = bttk.Label(main_frame, text="با کلیک روی دکمه زیر، شما تأیید می‌کنید که این شرایط را خوانده، فهمیده و پذیرفته‌اید.", font=("Vazirmatn", 10, "italic"), justify="center", anchor="center"); acceptance_label.pack(fill=X, pady=10)
            ok_button = bttk.Button(main_frame, text="شرایط را خواندم و می‌پذیرم", bootstyle="success", command=warning_window.destroy); ok_button.pack(pady=10, ipady=5, ipadx=10)
            credit_label = bttk.Label(main_frame, text="ساخته شده توسط : امیرحسین میرزایی", font=("Vazirmatn", 9), bootstyle="secondary", anchor="center", justify="center"); credit_label.pack(side=BOTTOM, pady=(15, 0))
            self.root.wait_window(warning_window)
        except Exception as e:
            messagebox.showwarning("هشدار قانونی", f"سوءاستفاده از این ابزار پیگرد قانونی دارد.\nError: {e}", parent=self.root)

    def create_menu(self):
        self.menu_bar = tk.Menu(self.root); self.root.config(menu=self.menu_bar)
        file_menu = tk.Menu(self.menu_bar, tearoff=0); self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="شروع تحلیل جامع", command=lambda: self.start_scan_thread('full'), accelerator="Ctrl+R")
        file_menu.add_command(label="شروع اسکن دایرکتوری", command=lambda: self.start_scan_thread('dir_brute'))
        file_menu.add_command(label="توقف", command=self.stop_scan, accelerator="Ctrl+T")
        file_menu.add_separator(); file_menu.add_command(label="خروج", command=self.root.quit)
        edit_menu = tk.Menu(self.menu_bar, tearoff=0); self.menu_bar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="کپی لینک‌های یافت‌شده", command=self.copy_to_clipboard, accelerator="Ctrl+C")
        
        tools_menu = tk.Menu(self.menu_bar, tearoff=0); self.menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Whois Lookup...", command=self.open_whois_tool)
        tools_menu.add_command(label="DNS Lookup...", command=self.open_dns_tool)
        tools_menu.add_command(label="Port Scanner...", command=self.open_port_scanner_tool)
        tools_menu.add_command(label="Subdomain Scanner...", command=self.open_subdomain_scanner_tool)
        tools_menu.add_command(label="Encoder / Decoder...", command=self.open_encoder_tool)
        
        self.root.bind("<Control-r>", lambda event: self.start_scan_thread('full')); self.root.bind("<Control-t>", lambda event: self.stop_scan()); self.root.bind("<Control-c>", lambda event: self.copy_to_clipboard())

    def create_widgets(self):
        main_pane = ttk.PanedWindow(self.root, orient=HORIZONTAL); main_pane.pack(fill=BOTH, expand=True, padx=10, pady=10)
        left_frame_container = bttk.Frame(main_pane, padding=5); main_pane.add(left_frame_container, weight=3)
        input_frame = bttk.Frame(left_frame_container); input_frame.pack(fill=X, pady=(0, 10)); url_label=bttk.Label(input_frame, text="آدرس سایت هدف:"); url_label.pack(side=RIGHT, padx=5); self.url_entry=bttk.Entry(input_frame, bootstyle="primary"); self.url_entry.pack(side=LEFT, fill=X, expand=YES)
        self.use_selenium_var = tk.BooleanVar(); selenium_check = bttk.Checkbutton(left_frame_container, text="موتور پیشرفته (ضد شناسایی، برای سایت‌های پیچیده)", variable=self.use_selenium_var, bootstyle="info-round-toggle"); selenium_check.pack(fill=X, pady=5)
        control_frame=bttk.Frame(left_frame_container); control_frame.pack(fill=X, pady=5); self.start_button=bttk.Button(control_frame, text="تحلیل جامع", command=lambda: self.start_scan_thread('full'), bootstyle="success"); self.start_button.pack(side=RIGHT, expand=YES, fill=X, padx=(2,0)); self.dir_brute_button=bttk.Button(control_frame, text="اسکن دایرکتوری", command=lambda: self.start_scan_thread('dir_brute'), bootstyle="primary"); self.dir_brute_button.pack(side=RIGHT, expand=YES, fill=X, padx=(2,2)); self.stop_button=bttk.Button(control_frame, text="توقف", command=self.stop_scan, bootstyle="danger", state="disabled"); self.stop_button.pack(side=LEFT, expand=YES, fill=X, padx=(0,2))
        results_label=bttk.Label(left_frame_container, text="لینک‌های داخلی یافت شده:"); results_label.pack(fill=X, pady=(10, 5)); self.results_text=scrolledtext.ScrolledText(left_frame_container, wrap=tk.WORD, height=8, font=("Vazirmatn", 10)); self.results_text.pack(fill=BOTH, expand=YES); self.results_text.config(state='disabled'); self.results_text.bind("<Double-1>", self.open_link_from_list)
        save_frame = bttk.Frame(left_frame_container); save_frame.pack(fill=X, pady=(10, 0)); self.save_report_button = bttk.Button(save_frame, text="ذخیره گزارش کامل", command=self.save_full_report, bootstyle="success", state="disabled"); self.save_report_button.pack(side=LEFT, expand=YES, fill=X, padx=(0,5)); self.copy_button = bttk.Button(save_frame, text="کپی لینک‌ها", command=self.copy_to_clipboard, bootstyle="secondary", state="disabled"); self.copy_button.pack(side=RIGHT, expand=YES, fill=X, padx=(5,0)); self.save_txt_button = bttk.Button(save_frame, text="ذخیره لینک‌ها (TXT)", command=self.save_as_txt, bootstyle="info", state="disabled"); self.save_txt_button.pack(side=RIGHT, expand=YES, fill=X, padx=(5, 5));
        status_frame = bttk.Frame(left_frame_container); status_frame.pack(fill=X, pady=(10, 0)); self.status_label = bttk.Label(status_frame, text="آماده به کار..."); self.status_label.pack(side=LEFT, expand=YES); self.progress_bar = bttk.Progressbar(status_frame, mode='indeterminate', bootstyle="success-striped"); self.progress_bar.pack(side=RIGHT)
        right_container_frame = bttk.Frame(main_pane); main_pane.add(right_container_frame, weight=4)
        right_scrolled_frame = ScrolledFrame(right_container_frame, autohide=True); right_scrolled_frame.pack(fill=BOTH, expand=YES)
        grid_manager_frame = bttk.Frame(right_scrolled_frame); grid_manager_frame.pack(fill=X); grid_manager_frame.columnconfigure(0, weight=1); grid_manager_frame.columnconfigure(1, weight=1)
        host_frame = bttk.Labelframe(grid_manager_frame, text="اطلاعات هاست و دامنه", bootstyle="light", padding=10); host_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5); self.host_labels = {}; host_info_to_check = ['آدرس IP', 'سرویس‌دهنده (ISP)', 'کشور', 'ثبت‌کننده دامنه', 'تاریخ ثبت', 'تاریخ انقضا'];
        for i, item in enumerate(host_info_to_check): label=bttk.Label(host_frame, text=f"{item}:"); label.grid(row=i, column=0, sticky='w', padx=5, pady=2); status_label = bttk.Label(host_frame, text="...", font="-weight bold"); status_label.grid(row=i, column=1, sticky='w'); self.host_labels[item] = status_label
        ssl_frame = bttk.Labelframe(grid_manager_frame, text="تحلیل گواهی SSL/TLS", bootstyle="success", padding=10); ssl_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5); self.ssl_labels={}; ssl_info_to_check=['صادرکننده','موضوع','تاریخ انقضا','روزهای باقیمانده'];
        for i, item in enumerate(ssl_info_to_check): label=bttk.Label(ssl_frame, text=f"{item}:"); label.grid(row=i, column=0, sticky='w', padx=5, pady=2); status_label=bttk.Label(ssl_frame, text="..."); status_label.grid(row=i, column=1, sticky='w'); self.ssl_labels[item]=status_label
        
        rank_frame = bttk.Labelframe(grid_manager_frame, text="تخمین ترافیک و ارزش سایت", bootstyle="primary", padding=10)
        rank_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        rank_label = bttk.Label(rank_frame, text="برای مشاهده نمودار تخمین ترافیک و ارزش سایت (بدون نیاز به ثبت‌نام) از ابزار زیر استفاده کنید.", wraplength=400)
        rank_label.pack(pady=5)
        self.traffic_button = bttk.Button(rank_frame, text="دریافت و نمایش نمودار ترافیک", command=self.fetch_and_display_traffic_chart, state="disabled", bootstyle="primary-outline")
        self.traffic_button.pack(pady=5, fill=X, padx=20)
        
        seo_frame = bttk.Labelframe(grid_manager_frame, text="چک‌لیست سلامت سئو (کل سایت)", bootstyle="info", padding=10); seo_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5); seo_columns = ('factor', 'status', 'recommendation'); self.seo_tree = bttk.Treeview(seo_frame, columns=seo_columns, show='headings', height=6); self.seo_tree.heading('factor', text='فاکتور سئو'); self.seo_tree.heading('status', text='وضعیت'); self.seo_tree.heading('recommendation', text='توضیحات و تعداد صفحات'); self.seo_tree.column('factor', width=120, anchor='center'); self.seo_tree.column('status', width=100, anchor='center'); self.seo_tree.column('recommendation', width=350); self.seo_tree.pack(fill=BOTH, expand=YES); self.seo_tree.bind("<Double-1>", self.show_seo_issue_urls); self.seo_tree.tag_configure('success', foreground=self.root.style.colors.success); self.seo_tree.tag_configure('warning', foreground=self.root.style.colors.warning); self.seo_tree.tag_configure('danger', foreground=self.root.style.colors.danger)
        dir_brute_frame = bttk.Labelframe(grid_manager_frame, text="نتایج اسکن دایرکتوری و فایل", bootstyle="warning", padding=10)
        dir_brute_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        dir_columns = ('path', 'status', 'size')
        self.dir_brute_tree = bttk.Treeview(dir_brute_frame, columns=dir_columns, show='headings', height=5)
        self.dir_brute_tree.heading('path', text='مسیر یافت شده'); self.dir_brute_tree.heading('status', text='کد وضعیت'); self.dir_brute_tree.heading('size', text='حجم (بایت)')
        self.dir_brute_tree.column('path', width=400); self.dir_brute_tree.column('status', width=100, anchor='center'); self.dir_brute_tree.column('size', width=100, anchor='center')
        self.dir_brute_tree.pack(fill=BOTH, expand=YES)
        self.dir_brute_tree.tag_configure('status_ok', foreground=self.root.style.colors.success)
        self.dir_brute_tree.tag_configure('status_redirect', foreground=self.root.style.colors.info)
        self.dir_brute_tree.tag_configure('status_forbidden', foreground=self.root.style.colors.warning)
        secrets_frame = bttk.Labelframe(grid_manager_frame, text="یافته‌های حساس (Secrets)", bootstyle="danger", padding=10); secrets_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=5, pady=5); secrets_columns = ('type', 'value', 'source'); self.secrets_tree = bttk.Treeview(secrets_frame, columns=secrets_columns, show='headings', height=4); self.secrets_tree.heading('type', text='نوع یافته'); self.secrets_tree.heading('value', text='مقدار'); self.secrets_tree.heading('source', text='منبع'); self.secrets_tree.column('type', width=100); self.secrets_tree.column('value', width=200); self.secrets_tree.column('source', width=200); self.secrets_tree.pack(fill=BOTH, expand=YES)
        headers_frame = bttk.Labelframe(grid_manager_frame, text="تحلیل هدرهای امنیتی", bootstyle="warning", padding=10); headers_frame.grid(row=5, column=0, sticky="nsew", padx=5, pady=5); self.header_labels={}; headers_to_check=['Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy'];
        for i, header in enumerate(headers_to_check): label=bttk.Label(headers_frame,text=f"{header}:", wraplength=150);label.grid(row=i,column=0,sticky='w',padx=5,pady=2);status_label=bttk.Label(headers_frame,text="...");status_label.grid(row=i,column=1,sticky='w');self.header_labels[header]=status_label
        cookie_frame = bttk.Labelframe(grid_manager_frame, text="جزئیات کوکی‌های دریافتی", bootstyle="info", padding=10); cookie_frame.grid(row=5, column=1, sticky="nsew", padx=5, pady=5); columns=('name','secure','httponly','samesite'); self.cookie_tree=bttk.Treeview(cookie_frame,columns=columns,show='headings',height=4); self.cookie_tree.heading('name',text='نام کوکی');self.cookie_tree.heading('secure',text='Secure');self.cookie_tree.heading('httponly',text='HttpOnly');self.cookie_tree.heading('samesite',text='SameSite'); self.cookie_tree.column('name',width=80);self.cookie_tree.column('secure',width=50,anchor='center');self.cookie_tree.column('httponly',width=50,anchor='center');self.cookie_tree.column('samesite',width=60,anchor='center'); self.cookie_tree.pack(fill=BOTH, expand=YES)
        stats_frame = bttk.Labelframe(grid_manager_frame, text="پروفایل تکنولوژی و محتوا", bootstyle="primary", padding=10); stats_frame.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=5, pady=5); stats_frame.columnconfigure(1, weight=1); stats_frame.columnconfigure(3, weight=1); self.image_var=tk.StringVar(value="0");self.script_var=tk.StringVar(value="0");self.style_var=tk.StringVar(value="0");self.form_var=tk.StringVar(value="0");self.comment_var=tk.StringVar(value="0");self.external_link_var=tk.StringVar(value="0");self.email_var=tk.StringVar(value="0");self.generator_var=tk.StringVar(value="...");self.server_var=tk.StringVar(value="...");self.powered_by_var=tk.StringVar(value="...");self.robots_var = tk.StringVar(value="...");self.sitemap_var = tk.StringVar(value="...");
        self.robots_button = bttk.Button(stats_frame, textvariable=self.robots_var, bootstyle="outline-secondary", state="disabled"); self.robots_button.grid(row=1, column=3, sticky='w', padx=5); self.sitemap_button = bttk.Button(stats_frame, textvariable=self.sitemap_var, bootstyle="outline-secondary", state="disabled"); self.sitemap_button.grid(row=2, column=1, sticky='w', padx=5)
        bttk.Label(stats_frame,text="Server:").grid(row=0,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.server_var,font="-weight bold").grid(row=0,column=1,sticky='w');bttk.Label(stats_frame,text="X-Powered-By:").grid(row=0,column=2,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.powered_by_var,font="-weight bold").grid(row=0,column=3,sticky='w');bttk.Label(stats_frame,text="Generator:").grid(row=1,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.generator_var,font="-weight bold").grid(row=1,column=1,sticky='w');bttk.Label(stats_frame,text="robots.txt:").grid(row=1,column=2,sticky='w',padx=5);bttk.Label(stats_frame,text="sitemap.xml:").grid(row=2,column=0,sticky='w',padx=5);bttk.Separator(stats_frame,orient='horizontal').grid(row=3,column=0,columnspan=4,pady=10,sticky='ew');bttk.Label(stats_frame,text="تصاویر:").grid(row=4,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.image_var).grid(row=4,column=1,sticky='w');bttk.Label(stats_frame,text="اسکریپت‌ها:").grid(row=5,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.script_var).grid(row=5,column=1,sticky='w');bttk.Label(stats_frame,text="فرم‌ها:").grid(row=6,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.form_var).grid(row=6,column=1,sticky='w');bttk.Label(stats_frame,text="کامنت‌های HTML:").grid(row=7,column=0,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.comment_var).grid(row=7,column=1,sticky='w');bttk.Label(stats_frame,text="لینک‌های خارجی:").grid(row=4,column=2,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.external_link_var).grid(row=4,column=3,sticky='w');bttk.Label(stats_frame,text="استایل‌شیت‌ها:").grid(row=5,column=2,sticky='w',padx=5);bttk.Label(stats_frame,textvariable=self.style_var).grid(row=5,column=3,sticky='w');email_frame=bttk.Frame(stats_frame);email_frame.grid(row=6,column=2,columnspan=2,sticky='w');bttk.Label(email_frame,text="ایمیل‌های منحصربفرد:").pack(side=LEFT,padx=5);bttk.Label(email_frame,textvariable=self.email_var).pack(side=LEFT);self.show_emails_button=bttk.Button(email_frame,text="نمایش",command=self.show_found_emails,bootstyle="outline-info",state="disabled");self.show_emails_button.pack(side=LEFT,padx=5)

    def reset_ui_for_new_scan(self):
        self.link_count=self.image_count=self.script_count=self.style_count=0; self.form_count=self.comment_count=self.external_link_count=self.email_count=0; self.found_secrets=0; self.found_emails.clear()
        self.image_var.set("0"); self.script_var.set("0"); self.style_var.set("0"); self.form_var.set("0"); self.comment_var.set("0"); self.external_link_var.set("0"); self.email_var.set("0")
        self.generator_var.set("..."); self.server_var.set("..."); self.powered_by_var.set("...")
        self.robots_button.config(text="...", state="disabled", bootstyle="outline-secondary"); self.sitemap_button.config(text="...", state="disabled", bootstyle="outline-secondary")
        for label in self.header_labels.values(): label.config(text="...", bootstyle="default")
        for label in self.ssl_labels.values(): label.config(text="...", bootstyle="default")
        for label in self.host_labels.values(): label.config(text="...", bootstyle="default")
        self.seo_issues.clear()
        for i in self.seo_tree.get_children(): self.seo_tree.delete(i)
        for i in self.cookie_tree.get_children(): self.cookie_tree.delete(i)
        for i in self.secrets_tree.get_children(): self.secrets_tree.delete(i)
        for i in self.dir_brute_tree.get_children(): self.dir_brute_tree.delete(i)
        self.traffic_button.config(state="disabled")
        self.results_text.config(state='normal'); self.results_text.delete(1.0, tk.END); self.results_text.config(state='disabled')
        for btn in [self.save_report_button, self.save_txt_button, self.copy_button, self.show_emails_button]: btn.config(state='disabled')

    def start_scan_thread(self, scan_type, options=None):
        if self.active_thread and self.active_thread.is_alive():
            messagebox.showwarning("هشدار", "یک عملیات دیگر در حال اجراست. لطفاً ابتدا آن را متوقف کنید.", parent=self.root)
            return
        self.stop_event.clear()
        url = self.url_entry.get().strip()
        if not url:
            self.status_label.config(text="خطا: لطفاً آدرس سایت را وارد کنید."); return
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_entry.delete(0, tk.END); self.url_entry.insert(0, url)
        self.reset_ui_for_new_scan()
        self.traffic_button.config(state="normal")
        target_function = None; args = ()
        if scan_type == 'full':
            use_selenium = self.use_selenium_var.get()
            target_function = initial_recon_and_crawl
            args = (url, self.results_queue, self.stop_event, use_selenium)
        elif scan_type == 'dir_brute':
            target_function = directory_bruteforce_engine
            args = (url, self.results_queue, self.stop_event)
        
        if target_function:
            self.active_thread = threading.Thread(target=target_function, args=args, daemon=True)
            self.start_button.config(state='disabled'); self.dir_brute_button.config(state='disabled'); self.stop_button.config(state='normal'); self.progress_bar.start()
            self.active_thread.start()

    def stop_scan(self):
        if self.active_thread and self.active_thread.is_alive() and not self.stop_event.is_set():
            self.stop_event.set()
            self.status_label.config(text="در حال ارسال سیگنال توقف...")
            self.stop_button.config(state='disabled')
            
    def process_queue(self):
        try:
            while not self.results_queue.empty():
                msg_type, data = self.results_queue.get_nowait()
                if msg_type == "---STOP_SCAN_UI---":
                    self.progress_bar.stop(); self.start_button.config(state='normal'); self.dir_brute_button.config(state='normal'); self.stop_button.config(state='disabled')
                    if self.host_labels['آدرس IP'].cget("text") == "..." and self.link_count == 0 and self.dir_brute_tree.get_children() == (): final_message = "عملیات بدون یافتن نتیجه پایان یافت."
                    else: final_message = f"عملیات پایان یافت."
                    if self.host_labels['آدرس IP'].cget("text") != "...":
                        self.save_report_button.config(state="normal")
                        if self.link_count > 0: self.save_txt_button.config(state="normal"); self.copy_button.config(state="normal")
                    if self.email_count > 0: self.show_emails_button.config(state="normal")
                    self.status_label.config(text=final_message)
                elif msg_type == "---ERROR---": self.status_label.config(text=data)
                elif msg_type == "---STATUS---": self.status_label.config(text=data)
                else: self.handle_data_message(msg_type, data)
        except queue.Empty: pass
        finally: self.root.after(100, self.process_queue)

    def handle_data_message(self, msg_type, data):
        if msg_type == 'dir_brute_result':
            status = data['status']; tags = ()
            if 200 <= status < 300: tags = ('status_ok',)
            elif 300 <= status < 400: tags = ('status_redirect',)
            elif 400 <= status < 500: tags = ('status_forbidden',)
            self.dir_brute_tree.insert('', tk.END, values=(data['url'], status, data['size']), tags=tags)
        elif msg_type == 'seo_issue':
            key, url = data['key'], data['url']
            if key not in self.seo_issues: self.seo_issues[key] = set()
            if url not in self.seo_issues[key]: self.seo_issues[key].add(url); self.update_seo_treeview()
        elif msg_type == 'image': self.image_count += 1; self.image_var.set(str(self.image_count))
        elif msg_type == 'script': self.script_count += 1; self.script_var.set(str(self.script_count))
        elif msg_type == 'style': self.style_count += 1; self.style_var.set(str(self.style_count))
        elif msg_type == 'form': self.form_count += 1; self.form_var.set(str(self.form_count))
        elif msg_type == 'comment': self.comment_count += 1; self.comment_var.set(str(self.comment_count))
        elif msg_type == 'external_link': self.external_link_count += 1; self.external_link_var.set(str(self.external_link_count))
        elif msg_type == 'host_info':
            self.host_labels['آدرس IP'].config(text=data['ip']); self.host_labels['سرویس‌دهنده (ISP)'].config(text=data['isp']); self.host_labels['کشور'].config(text=data['country']); self.host_labels['ثبت‌کننده دامنه'].config(text=data['registrar']); self.host_labels['تاریخ ثبت'].config(text=str(data['creation_date'])); self.host_labels['تاریخ انقضا'].config(text=str(data['expiration_date']))
        elif msg_type == 'file_check':
            if data['robots.txt']: self.robots_button.config(text="✔ نمایش", bootstyle="success-outline", state="normal", command=lambda: self.show_file_content('robots'))
            else: self.robots_button.config(text="❌ یافت نشد", bootstyle="danger-outline", state="disabled")
            if data['sitemap.xml']: self.sitemap_button.config(text="✔ نمایش", bootstyle="success-outline", state="normal", command=lambda: self.show_file_content('sitemap'))
            else: self.sitemap_button.config(text="❌ یافت نشد", bootstyle="danger-outline", state="disabled")
        elif msg_type == 'secret_found': 
            self.found_secrets += 1; self.secrets_tree.insert('', tk.END, values=(data['type'], data['value'], data['source'][:40]+'...')); self.status_label.config(text=f"!!! یافته حساس: {self.found_secrets}")
        elif msg_type == 'ssl_result':
            self.ssl_labels['صادرکننده'].config(text=data['issuer']); self.ssl_labels['موضوع'].config(text=data['subject']); self.ssl_labels['تاریخ انقضا'].config(text=data['expires_on']); days_left=data['days_left']; self.ssl_labels['روزهای باقیمانده'].config(text=str(days_left)); days_style = "success" if days_left > 30 else ("warning" if days_left > 15 else "danger"); self.ssl_labels['روزهای باقیمانده'].config(bootstyle=days_style)
        elif msg_type == 'headers_result':
            for header, is_present in data.items(): self.header_labels[header].config(text="✔ ایمن", bootstyle="success") if is_present else self.header_labels[header].config(text="❌ ناامن", bootstyle="danger")
        elif msg_type == 'cookie_detail': 
            secure_text, httponly_text = ("✔" if data['secure'] else "❌"), ("✔" if data['httponly'] else "❌"); self.cookie_tree.insert('', tk.END, values=(data['name'], secure_text, httponly_text, data['samesite']))
        elif msg_type == 'tech_profile': 
            self.server_var.set(data.get('Server', '...')); self.powered_by_var.set(data.get('X-Powered-By', '...'))
        elif msg_type == 'link': 
            self.link_count+=1; self.results_text.config(state='normal'); self.results_text.insert(tk.END, data + "\n"); self.results_text.config(state='disabled'); self.results_text.see(tk.END)
        elif msg_type == 'email': 
            self.email_count+=1; self.email_var.set(str(self.email_count)); self.found_emails.add(data)
        elif msg_type == 'generator': self.generator_var.set(data)

    def update_seo_treeview(self):
        for key, urls in self.seo_issues.items():
            issue_def = self.SEO_ISSUE_DEFINITIONS.get(key)
            if not issue_def: continue
            count = len(urls)
            recommendation = f"{issue_def['recommendation']} (در {count} صفحه یافت شد)"
            tags = ('danger',) if '❌' in issue_def['status'] else ('warning',)
            if self.seo_tree.exists(key): self.seo_tree.item(key, values=(issue_def['factor'], issue_def['status'], recommendation))
            else: self.seo_tree.insert('', tk.END, iid=key, values=(issue_def['factor'], issue_def['status'], recommendation), tags=tags)

    def open_link_from_list(self, event):
        try:
            line=self.results_text.get(f"@{event.x},{event.y} linestart", f"@{event.x},{event.y} lineend")
            if line.strip().startswith("http"): webbrowser.open_new_tab(line.strip()); self.status_label.config(text=f"در حال باز کردن: {line[:50]}...")
        except tk.TclError: pass

    def copy_to_clipboard(self):
        content = self.results_text.get(1.0, tk.END)
        if content.strip(): self.root.clipboard_clear(); self.root.clipboard_append(content); self.status_label.config(text="تمام لینک‌ها در کلیپ‌بورد کپی شد!")

    def show_found_emails(self):
        if not self.found_emails: self.status_label.config(text="هیچ ایمیلی برای نمایش وجود ندارد."); return
        top = bttk.Toplevel(master=self.root); top.title("ایمیل‌های پیدا شده"); top.geometry("500x400"); top.transient(self.root)
        email_text = scrolledtext.ScrolledText(top, wrap=tk.WORD, width=60, height=20, font=("Vazirmatn", 10)); email_text.pack(expand=YES, fill=BOTH, padx=10, pady=10)
        email_text.insert(tk.END, "\n".join(sorted(list(self.found_emails)))); email_text.config(state='disabled')

    def show_seo_issue_urls(self, event):
        selected_iid = self.seo_tree.focus()
        if not selected_iid: return
        if selected_iid in self.seo_issues:
            urls = sorted(list(self.seo_issues[selected_iid]))
            issue_def = self.SEO_ISSUE_DEFINITIONS.get(selected_iid)
            window_title = f"صفحات دارای مشکل: {issue_def['factor']}"
            top = bttk.Toplevel(master=self.root); top.title(window_title); top.geometry("700x500"); top.transient(self.root)
            url_text = scrolledtext.ScrolledText(top, wrap=tk.WORD, width=80, height=25, font=("Vazirmatn", 10)); url_text.pack(expand=YES, fill=BOTH, padx=10, pady=10)
            url_text.insert(tk.END, "\n".join(urls)); url_text.config(state='disabled')
        else: self.status_label.config(text="اطلاعاتی برای نمایش این مورد وجود ندارد.")

    def show_file_content(self, file_type):
        base_url = self.url_entry.get()
        if not base_url: return
        file_url = urljoin(base_url, f'/robots.txt' if file_type == 'robots' else f'/sitemap.xml')
        window_title = f"محتوای فایل {file_type}"
        try:
            response = requests.get(file_url, timeout=5); response.raise_for_status()
            top = bttk.Toplevel(master=self.root); top.title(window_title); top.geometry("600x500"); top.transient(self.root)
            content_text = scrolledtext.ScrolledText(top, wrap=tk.WORD, font=("Consolas", 10)); content_text.pack(expand=YES, fill=BOTH, padx=10, pady=10)
            content_text.insert(tk.END, response.text); content_text.config(state='disabled')
        except requests.RequestException as e: self.status_label.config(text=f"خطا در دریافت {file_url}: {e}")

    def save_as_txt(self):
        content = self.results_text.get(1.0, tk.END)
        if not content.strip(): self.status_label.config(text="خطا: نتیجه‌ای برای ذخیره وجود ندارد."); return
        try:
            filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], title="ذخیره لینک‌ها به صورت فایل متنی")
            if not filepath: return
            with open(filepath, 'w', encoding='utf-8') as f: f.write(content)
            self.status_label.config(text=f"لینک‌ها با موفقیت در {filepath} ذخیره شد.")
        except Exception as e: self.status_label.config(text=f"خطا در ذخیره‌سازی: {e}")

    def open_whois_tool(self):
        WhoisWindow(self).lift()

    def open_dns_tool(self):
        DnsWindow(self).lift()

    def open_port_scanner_tool(self):
        PortScannerWindow(self).lift()
    
    def open_subdomain_scanner_tool(self):
        SubdomainScannerWindow(self).lift()

    def open_encoder_tool(self):
        EncoderWindow(self).lift()
        
    def save_full_report(self):
        if self.host_labels['آدرس IP'].cget("text") == "...":
            messagebox.showwarning("گزارش خالی", "هیچ داده‌ای برای ایجاد گزارش وجود ندارد. لطفاً ابتدا یک سایت را تحلیل کنید.", parent=self.root)
            return
        try:
            filepath = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")], title="ذخیره گزارش کامل تحلیل", initialfile=f"report-{urlparse(self.url_entry.get()).hostname}.html")
            if not filepath: return
            report_html = self._generate_html_report(html.escape)
            with open(filepath, 'w', encoding='utf-8') as f: f.write(report_html)
            self.status_label.config(text=f"گزارش کامل با موفقیت در {filepath} ذخیره شد.")
            messagebox.showinfo("موفقیت", f"گزارش با موفقیت ذخیره شد.\nمسیر: {filepath}", parent=self.root)
        except Exception as e:
            self.status_label.config(text=f"خطا در ذخیره گزارش: {e}")
            messagebox.showerror("خطا", f"یک خطای غیرمنتظره هنگام ذخیره گزارش رخ داد:\n{e}", parent=self.root)

    def _generate_html_report(self, h):
        target_url, report_time = h(self.url_entry.get()), datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        css = """<style>@font-face {font-family: 'Vazirmatn';src: url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-Regular.woff2') format('woff2');font-weight: normal; font-style: normal;} body { font-family: 'Vazirmatn', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; direction: rtl; background-color: #22252a; color: #e9ecef; margin: 0; padding: 20px; line-height: 1.6;} .container { max-width: 1200px; margin: auto; } .header { background-color: #2c3038; padding: 25px; border-radius: 8px; text-align: center; margin-bottom: 25px; border: 1px solid #444;} .header h1 { color: #00bc8c; margin: 0 0 10px 0; font-size: 2em; } .header p { margin: 5px 0; color: #adb5bd; } .header a { color: #00bc8c; text-decoration: none; } .header a:hover { text-decoration: underline; } .section { background-color: #2c3038; border: 1px solid #444; border-radius: 8px; padding: 20px; margin-bottom: 20px;} .section h2 { color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 0; font-size: 1.5em;} .grid-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; } table { width: 100%; border-collapse: collapse; margin-top: 15px;} th, td { padding: 12px 15px; text-align: right; border-bottom: 1px solid #495057;} th { background-color: #343a40; color: #ced4da; font-weight: 600; } tr:nth-child(even) { background-color: #343a40; } .status-ok { color: #28a745; font-weight: bold; } .status-bad { color: #dc3545; font-weight: bold; } .status-warn { color: #ffc107; font-weight: bold; } .code, .list-details { background-color: #212529; color: #ddd; padding: 15px; border-radius: 5px; font-family: 'Consolas', 'Menlo', monospace; white-space: pre-wrap; word-wrap: break-word; max-height: 400px; overflow-y: auto; direction: ltr; text-align: left; border: 1px solid #444;} .footer { text-align: center; color: #6c757d; margin-top: 30px; font-size: 0.9em; } details { border: 1px solid #444; border-radius: 4px; padding: 10px; margin-bottom: 10px; } summary { cursor: pointer; font-weight: bold; color: #3498db; } summary:hover { color: #5dade2; }</style>"""
        secrets_rows = ''.join([f"<tr><td>{h(self.secrets_tree.item(i)['values'][0])}</td><td><code>{h(self.secrets_tree.item(i)['values'][1])}</code></td><td>{h(self.secrets_tree.item(i)['values'][2])}</td></tr>" for i in self.secrets_tree.get_children()])
        secrets_html = f"<table><tr><th>نوع</th><th>مقدار</th><th>منبع</th></tr>{secrets_rows}</table>" if secrets_rows else "<p>هیچ مورد حساسی یافت نشد.</p>"
        emails_html = f"<div class='code'>{'<br>'.join(sorted([h(e) for e in self.found_emails]))}</div>" if self.found_emails else "<p>هیچ ایمیلی یافت نشد.</p>"
        cookies_rows = ''.join([f"<tr><td>{h(self.cookie_tree.item(i)['values'][0])}</td> <td class='{'status-ok' if '✔' in str(self.cookie_tree.item(i)['values'][1]) else 'status-bad'}'>{h(str(self.cookie_tree.item(i)['values'][1]))}</td> <td class='{'status-ok' if '✔' in str(self.cookie_tree.item(i)['values'][2]) else 'status-bad'}'>{h(str(self.cookie_tree.item(i)['values'][2]))}</td> <td>{h(str(self.cookie_tree.item(i)['values'][3]))}</td> </tr>" for i in self.cookie_tree.get_children()])
        cookies_table = f"<table><tr><th>نام</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr>{cookies_rows}</table>" if cookies_rows else "<table><tr><td colspan='4' style='text-align:center;'>هیچ کوکی یافت نشد.</td></tr></table>"
        dir_brute_rows = ''.join([f"<tr><td><a href='{h(self.dir_brute_tree.item(i)['values'][0])}' target='_blank'>{h(self.dir_brute_tree.item(i)['values'][0])}</a></td> <td class='status-ok'>{h(str(self.dir_brute_tree.item(i)['values'][1]))}</td> <td>{h(str(self.dir_brute_tree.item(i)['values'][2]))}</td> </tr>" for i in self.dir_brute_tree.get_children()])
        dir_brute_html = f"<table><tr><th>مسیر</th><th>وضعیت</th><th>حجم</th></tr>{dir_brute_rows}</table>" if dir_brute_rows else "<p>هیچ مسیر قابل توجهی یافت نشد.</p>"
        if not self.seo_issues:
            seo_html = '<p>هیچ مشکل SEO یافت نشد.</p>'
        else:
            seo_table_rows = ''.join([f"<tr><td>{h(self.seo_tree.item(i)['values'][0])}</td> <td class='{'status-bad' if '❌' in str(self.seo_tree.item(i)['values'][1]) else 'status-warn'}'>{h(str(self.seo_tree.item(i)['values'][1]))}</td> <td>{h(self.seo_tree.item(i)['values'][2])}</td></tr>" for i in self.seo_tree.get_children()])
            seo_details = ''.join([f"<details><summary><strong>{h(self.SEO_ISSUE_DEFINITIONS.get(key, {}).get('factor', ''))}</strong> ({len(urls)} صفحه)</summary><div class='list-details'>{'<br>'.join(sorted([h(u) for u in urls]))}</div></details>" for key, urls in self.seo_issues.items()])
            seo_html = f"<table><tr><th>فاکتور</th><th>وضعیت</th><th>توضیحات</th></tr>{seo_table_rows}</table><h3 style='margin-top: 25px;'>لیست صفحات دارای مشکل:</h3>{seo_details}"
        body = f"""
        <!DOCTYPE html><html lang="fa"><head><meta charset="UTF-8"><title>گزارش تحلیل سایت {target_url}</title>{css}</head>
        <body><div class="container">
            <div class="header"><h1>گزارش جامع تحلیل وب‌سایت</h1><p><strong>آدرس هدف:</strong> <a href="{target_url}" target="_blank">{target_url}</a></p><p><strong>تاریخ گزارش:</strong> {report_time}</p></div>
            <div class="section"><h2>خلاصه یافته‌ها</h2><div class="grid-container"><p><strong>لینک‌های داخلی:</strong> {self.link_count}</p><p><strong>ایمیل‌ها:</strong> {self.email_count}</p><p><strong>Secrets:</strong> {self.found_secrets}</p><p><strong>مشکلات SEO:</strong> {len(self.seo_issues)}</p><p><strong>مسیرهای یافت شده:</strong> {len(self.dir_brute_tree.get_children())}</p></div></div>
            <div class="grid-container"><div class="section"><h2>اطلاعات هاست و دامنه</h2><table>{''.join([f"<tr><td>{k}</td><td><strong>{h(v.cget('text'))}</strong></td></tr>" for k, v in self.host_labels.items()])}</table></div><div class="section"><h2>اطلاعات گواهی SSL/TLS</h2><table>{''.join([f"<tr><td>{k}</td><td><strong>{h(v.cget('text'))}</strong></td></tr>" for k, v in self.ssl_labels.items()])}</table></div></div>
            <div class="grid-container"><div class="section"><h2>هدرهای امنیتی</h2><table>{''.join([f"<tr><td>{h(k)}</td><td class='{'status-ok' if 'ایمن' in v.cget('text') else 'status-bad'}'>{h(v.cget('text'))}</td></tr>" for k, v in self.header_labels.items()])}</table></div><div class="section"><h2>جزئیات کوکی‌ها</h2>{cookies_table}</div></div>
            <div class="section"><h2>نتایج اسکن دایرکتوری</h2>{dir_brute_html}</div>
            <div class="section"><h2>یافته‌های حساس</h2><h3>Secrets</h3>{secrets_html}<h3 style="margin-top:20px;">ایمیل‌های یافت‌شده</h3>{emails_html}</div>
            <div class="section"><h2>تحلیل SEO</h2>{seo_html}</div>
            <div class="section"><h2>لیست کامل لینک‌های داخلی ({self.link_count} مورد)</h2><div class="code">{h(self.results_text.get(1.0, tk.END)).replace(chr(10), '<br>')}</div></div>
            <div class="footer">گزارش تولید شده توسط Web Analysis Suite</div>
        </div></body></html>"""
        return body

    def fetch_and_display_traffic_chart(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("خطا", "لطفاً ابتدا یک آدرس وارد کنید.", parent=self.root)
            return
        hostname = urlparse(url).hostname
        if not hostname:
            messagebox.showerror("خطا", "آدرس وارد شده معتبر نیست.", parent=self.root)
            return

        self.status_label.config(text=f"در حال دریافت اطلاعات ترافیک برای {hostname}...")
        self.traffic_button.config(state="disabled")
        
        threading.Thread(target=self._traffic_chart_worker, args=(hostname,), daemon=True).start()

    def _traffic_chart_worker(self, hostname):
        data = self._scrape_traffic_data(hostname)
        self.after(0, self._show_chart_window, data, hostname)
        self.after(0, lambda: self.traffic_button.config(state="normal"))
        
    def _scrape_traffic_data(self, hostname):
        try:
            url = f"https://www.siteworthtraffic.com/report/{hostname}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            def extract_value(text_label):
                tag = soup.find(lambda t: t.name == "td" and text_label in t.text)
                if tag and tag.find_next_sibling("td"):
                    value_str = tag.find_next_sibling("td").text.strip()
                    numeric_part = re.search(r'[\d,.]+', value_str)
                    if numeric_part:
                        return float(numeric_part.group(0).replace(',', ''))
                return 0

            visitors = extract_value("Daily Unique Visitors")
            pageviews = extract_value("Daily Pageviews")
            revenue = extract_value("Daily Ad Revenue")
            
            return {"visitors": visitors, "pageviews": pageviews, "revenue": revenue}

        except Exception as e:
            print(f"Error scraping traffic data: {e}")
            self.after(0, lambda: self.status_label.config(text=f"خطا در دریافت اطلاعات ترافیک: {e}"))
            return None

    def _show_chart_window(self, data, hostname):
        self.status_label.config(text="آماده به کار...")
        if not data or (data['visitors'] == 0 and data['pageviews'] == 0):
            messagebox.showinfo("یافت نشد", f"اطلاعات ترافیک برای دامنه '{hostname}' پیدا نشد.", parent=self.root)
            return

        chart_window = bttk.Toplevel(master=self.root)
        chart_window.title(f"نمودار ترافیک برای {hostname}")
        chart_window.geometry("800x600")
        chart_window.transient(self.root)
        
        fig = plt.figure(facecolor='#2c3038')
        ax = fig.add_subplot(111, facecolor='#2c3038')
        
        labels = ['Visitors/Day', 'Pageviews/Day', 'Revenue/Day ($)']
        values = [data.get('visitors', 0), data.get('pageviews', 0), data.get('revenue', 0)]
        colors = ['#00bc8c', '#3498db', '#f39c12']

        bars = ax.bar(labels, values, color=colors)
        
        ax.set_ylabel('مقدار تخمینی', color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['top'].set_color('#2c3038')
        ax.spines['right'].set_color('#2c3038')
        
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2.0, yval, f'{yval:,.0f}', va='bottom', ha='center', color='white', fontweight='bold')

        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# --- بخش اصلی اجرای برنامه ---
if __name__ == "__main__":
    root = bttk.Window()
    app = SpiderApp(root)
    root.mainloop()
