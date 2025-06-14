# Scanner-Websites
ابزار دسکتاپ چندمنظوره برای تحلیل امنیتی، سئو و جمع‌آوری اطلاعات وب‌سایت‌ها، ساخته شده با پایتون و سلنیوم.
# Web Analysis Suite - مجموعه ابزار تحلیل وب

![Web Analysis Suite Screenshot](https://s33.picofile.com/file/8485037550/Screenshot_2025_06_10_215608.png)

یک ابزار دسکتاپ چندمنظوره با رابط کاربری گرافیکی (GUI) که برای تحلیل و ارزیابی امنیت و ساختار وب‌سایت‌ها طراحی شده است. این مجموعه با استفاده از Python و کتابخانه‌های قدرتمندی مانند Tkinter، TTKBootstrap، Selenium و Requests ساخته شده است.

---

### ⚠️ هشدار قانونی و اخلاقی


هرگونه سوءاستفاده، از جمله اسکن وب‌سایت‌ها بدون مجوز، یک **عمل غیرقانونی** است. مسئولیت کامل و تمامی عواقب حقوقی و کیفری ناشی از هرگونه استفاده غیرمجاز، **مستقیماً بر عهده شخص کاربر** است. توسعه‌دهنده هیچ‌گونه مسئولیتی در قبال استفاده نادرست شما از این برنامه بر عهده نمی‌گیرد.

---

### ✨ قابلیت‌ها و ویژگی‌ها

این مجموعه ابزار دارای قابلیت‌های متنوعی است که در پنل اصلی و ابزارهای جانبی ارائه می‌شوند:

#### تحلیل جامع (Main Analysis)
- **خزنده وب (Web Crawler):** قابلیت پیمایش لینک‌های داخلی سایت با دو موتور:
  - **Requests (ساده):** سریع و مناسب برای سایت‌های استاتیک.
  - **Selenium (پیشرفته):** پشتیبانی از جاوااسکریپت، دور زدن محدودیت‌ها (Stealth Mode) و مناسب برای سایت‌های داینامیک و پیچیده.
- **جمع‌آوری اطلاعات هاست:** نمایش IP، کشور، ISP، تاریخ ثبت و انقضای دامنه.
- **تحلیل گواهی SSL/TLS:** بررسی صادرکننده، موضوع و تاریخ انقضای گواهی.
- **تحلیل هدرهای امنیتی:** چک کردن وجود هدرهای مهم مانند CSP, HSTS, X-Frame-Options و...
- **بررسی کوکی‌ها:** نمایش جزئیات کوکی‌ها (Secure, HttpOnly, SameSite).
- **شناسایی تکنولوژی:** تشخیص سرور، `X-Powered-By` و `Generator`.
- **اسکنر فایل‌های حساس:** بررسی وجود `robots.txt` و `sitemap.xml`.
- **یافتن اطلاعات حساس (Secrets):** جستجو برای یافتن کلیدهای API، توکن‌ها و رمزهای عبور احتمالی در کد منبع صفحات.
- **تحلیل سئو (SEO):** بررسی فاکتورهای کلیدی سئو مانند تگ‌های `title`, `meta description`, `h1` و... و ارائه گزارش دقیق از مشکلات در صفحات مختلف.
- **نمودار تخمین ترافیک:** دریافت و نمایش نمودار تخمینی بازدید روزانه، نمایش صفحه و درآمد سایت.
- **ذخیره گزارش:** قابلیت ذخیره تمام نتایج تحلیل در یک فایل **HTML** زیبا و سازمان‌یافته.

#### ابزارهای جانبی (Tools Menu)
- **Whois Lookup:** دریافت اطلاعات کامل ثبت دامنه.
- **DNS Lookup:** جستجوی رکوردهای مختلف DNS (A, MX, NS, TXT, ...).
- **Port Scanner:** اسکن پورت‌های رایج و باز روی سرور هدف.
- **Subdomain Scanner:** پیدا کردن زیردامنه‌های متداول یک دامنه.
- **Encoder / Decoder:** ابزاری برای کدگذاری و کدگشایی متون با الگوریتم‌های Base64 و URL.

---

### 📦 نصب و راه‌اندازی

برای اجرای این برنامه، به **پایتون نسخه 3.8 یا بالاتر** نیاز دارید.

۱. ابتدا پروژه را از گیت‌هاب کلون کنید:
```bash
git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
cd your-repository-name
```

۲. وابستگی‌های پروژه را با استفاده از فایل `requirements.txt` نصب کنید:
```bash
pip install -r requirements.txt
```
> **نکته:** کتابخانه `webdriver-manager` به صورت خودکار `ChromeDriver` مورد نیاز برای Selenium را دانلود و مدیریت می‌کند. فقط کافیست مرورگر **Google Chrome** روی سیستم شما نصب باشد.

---

### 🚀 نحوه اجرا

پس از نصب وابستگی‌ها، برنامه را با دستور زیر اجرا کنید:
```bash
python applications.py
```
*(نام فایل اصلی را در صورت نیاز تغییر دهید)*

---

### 🤝 مشارکت

اگر تمایل به بهبود و توسعه این پروژه دارید، می‌توانید از طریق Fork کردن ریپازیتوری و ارسال Pull Request با ما همکاری کنید.

---

### 📄 مجوز (License)

این پروژه تحت مجوز [MIT](LICENSE) منتشر شده است.
