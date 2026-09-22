# nexSSH 🔐

### Linux SSH Security Auditor

**nexSSH** یک ابزار خط فرمان (CLI) سبک و متن‌باز برای **ممیزی امنیتی تنظیمات SSH در سیستم‌های Linux** است که با Python نوشته شده و به صورت **Single-File** اجرا می‌شود.

nexSSH تنظیمات SSH، مجوز فایل‌های مرتبط، وضعیت سرویس، تنظیمات شبکه و الگوریتم‌های رمزنگاری را بررسی می‌کند و نتیجه را به شکل یک گزارش امنیتی قابل‌فهم ارائه می‌دهد.

> **nexSSH فقط Audit می‌کند؛ هیچ چیزی را در سیستم تغییر نمی‌دهد.**

---

## ✨ Features

- 🔍 ممیزی امنیتی تنظیمات SSH
- 🔐 بررسی تنظیمات احراز هویت
- 🛡️ بررسی کنترل دسترسی و Forwarding
- 🔑 بررسی Permission فایل‌ها و دایرکتوری‌های مرتبط با SSH
- ⚙️ بررسی وضعیت سرویس SSH
- 🌐 بررسی Port و تنظیمات شبکه
- 🔒 بررسی الگوریتم‌های رمزنگاری SSH
- 📊 محاسبه Security Score از `0` تا `100`
- 🎨 خروجی رنگی و خوانا در Terminal
- 📄 تولید خودکار گزارش HTML
- 🧩 خروجی JSON برای استفاده در ابزارهای دیگر
- 🐧 مناسب برای توزیع‌های مختلف Linux
- 📦 بدون وابستگی خارجی
- 📄 Single-File
- 🔒 کاملاً Read-Only

---

## 🎯 Project Goal

SSH یکی از مهم‌ترین سرویس‌های مدیریت سیستم‌های Linux است.

یک تنظیم اشتباه در SSH می‌تواند سطح حمله یک سرور را افزایش دهد، مخصوصاً زمانی که تنظیمات پیش‌فرض بدون بررسی روی یک سیستم Production باقی مانده باشند.

هدف nexSSH این است که بدون ایجاد تغییر در سیستم، تنظیمات SSH را بررسی کند و مشکلات احتمالی را به شکلی ساده و قابل‌فهم در اختیار Administrator قرار دهد.

nexSSH برای **شناسایی، تحلیل و گزارش** طراحی شده است، نه برای تغییر خودکار تنظیمات.

---

## 🔎 Security Checks

nexSSH مجموعه‌ای از بررسی‌های امنیتی را در چند دسته انجام می‌دهد.

### 🔐 Authentication

بررسی تنظیمات مربوط به احراز هویت:

- ورود مستقیم `root`
- فعال بودن Password Authentication
- امکان استفاده از Empty Password
- فعال بودن Public Key Authentication
- تعداد تلاش‌های مجاز برای ورود
- Login Grace Time

---

### 🛡️ Access Control

بررسی کنترل دسترسی و قابلیت‌های Forwarding:

- X11 Forwarding
- TCP Forwarding
- Tunnel / Network Forwarding
- `AllowUsers`
- `DenyUsers`
- `AllowGroups`
- `DenyGroups`

---

### 🔑 File Permissions

بررسی Permission فایل‌ها و دایرکتوری‌های مرتبط با SSH:

- `/etc/ssh/sshd_config`
- `/etc/ssh/sshd_config.d/`
- دایرکتوری `.ssh`
- `authorized_keys`
- Permission کلیدهای خصوصی کاربران

> nexSSH محتوای کلیدهای خصوصی را نمی‌خواند و آن‌ها را در خروجی نمایش نمی‌دهد.

---

### ⚙️ Service

بررسی وضعیت سرویس SSH:

- فعال یا غیرفعال بودن سرویس
- فعال بودن سرویس هنگام Boot
- شناسایی سرویس SSH در سیستم

---

### 🌐 Network

بررسی تنظیمات شبکه SSH:

- Port مورد استفاده SSH
- تشخیص استفاده از پورت پیش‌فرض `22`
- بررسی Portهای Listening مرتبط با SSH

> استفاده از پورت غیرپیش‌فرض به تنهایی یک راهکار امنیتی کامل محسوب نمی‌شود و صرفاً یک مورد قابل گزارش است.

---

### 🔒 Cryptography

بررسی تنظیمات رمزنگاری SSH:

- `Ciphers`
- `MACs`
- `KexAlgorithms`
- SSH Protocol Version

هدف این بخش شناسایی الگوریتم‌ها و تنظیمات قدیمی یا ضعیف است.

---

## 🧠 How It Works

nexSSH برای پیدا کردن تنظیمات واقعی SSH چند مرحله را انجام می‌دهد.

### 1. Effective Configuration

ابتدا ابزار تلاش می‌کند تنظیمات مؤثر SSH را از طریق:

```bash
sshd -T
```

دریافت کند.

این روش به nexSSH اجازه می‌دهد تا به جای بررسی صرفاً متنی فایل Configuration، تنظیماتی را که OpenSSH واقعاً استفاده می‌کند بررسی کند.

اگر دریافت تنظیمات مؤثر امکان‌پذیر نباشد، ابزار فایل‌های Configuration را بررسی می‌کند:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*.conf
```

---

### 2. Security Checks

بعد از دریافت تنظیمات، Checkهای امنیتی اجرا می‌شوند.

در صورت پیدا شدن یک مشکل، یک **Finding** ایجاد می‌شود که می‌تواند شامل موارد زیر باشد:

- Severity
- عنوان مشکل
- مقدار فعلی
- توضیح
- پیشنهاد اصلاح

---

### 3. Security Score

nexSSH بر اساس Findingهای شناسایی‌شده یک Security Score بین:

```text
0 - 100
```

محاسبه می‌کند.

این امتیاز یک معیار داخلی برای نمایش سریع وضعیت Audit است و جایگزین استانداردهای رسمی امنیتی یا تست نفوذ نیست.

---

### 4. Reporting

نتایج Audit در Terminal نمایش داده می‌شوند.

همچنین در اجرای عادی، nexSSH یک گزارش HTML تولید می‌کند که شامل جزئیات کامل Findingها است.

---

## 🚨 Severity Levels

| Severity | Description |
|---|---|
| 🔴 `CRITICAL` | مشکل بسیار جدی با اولویت رسیدگی بالا |
| 🟠 `HIGH` | ریسک امنیتی بالا |
| 🟡 `MEDIUM` | ریسک متوسط که بهتر است بررسی و اصلاح شود |
| 🔵 `LOW` | بهبود امنیتی با ریسک پایین |
| ⚪ `INFO` | اطلاعات یا وضعیت بدون مشکل امنیتی مشخص |

---

## 📊 Security Score

nexSSH وضعیت کلی Audit را با یک امتیاز بین `0` تا `100` نمایش می‌دهد.

این امتیاز بر اساس Findingهای شناسایی‌شده و Severity آن‌ها محاسبه می‌شود.

هدف Security Score این است که Administrator بتواند در یک نگاه وضعیت کلی SSH را مشاهده کند.

> Security Score یک معیار داخلی nexSSH است و نباید به عنوان استاندارد رسمی امنیت یا تضمین امنیت سیستم در نظر گرفته شود.

---

## 📄 Output

nexSSH سه نوع خروجی اصلی دارد:

### Terminal

خروجی کوتاه و خوانا برای استفاده مستقیم در ترمینال.

Findingها بر اساس Severity نمایش داده می‌شوند.

### HTML

در اجرای عادی، فایل زیر ساخته می‌شود:

```text
nexssh_report.html
```

گزارش HTML شامل:

- Security Score
- خلاصه Audit
- تمام Findingها
- Severity
- مقدار فعلی تنظیمات
- توضیح مشکل
- پیشنهاد اصلاح

است.

اگر فایل گزارش قبلی وجود داشته باشد، نسخه جدید جایگزین آن می‌شود.

### JSON

با استفاده از `--json` می‌توان خروجی ساختاریافته دریافت کرد.

این خروجی برای استفاده در:

- SIEM
- Scriptها
- Dashboardها
- سیستم‌های Monitoring
- ابزارهای امنیتی دیگر

مناسب است.

---

## 🚀 Installation

nexSSH به هیچ Package یا Dependency خارجی نیاز ندارد.

نیازمندی اصلی:

```text
Python 3.11+
```

Repository را Clone کنید:

```bash
git clone https://github.com/7hekasra/nexSSH.git
cd nexSSH
```

سپس ابزار را اجرا کنید:

```bash
sudo python3 nexssh.py
```

---

## 💻 Usage

### Full Audit

اجرای کامل Audit و تولید گزارش HTML:

```bash
sudo python3 nexssh.py
```

---

### Authentication Audit

فقط بررسی بخش Authentication:

```bash
sudo python3 nexssh.py --auth
```

---

### JSON Output

دریافت خروجی به صورت JSON:

```bash
sudo python3 nexssh.py --json
```

---

### Custom HTML Report

ذخیره گزارش در مسیر دلخواه:

```bash
sudo python3 nexssh.py --report /tmp/report.html
```

---

### Disable HTML Report

اجرای Audit بدون ساخت گزارش HTML:

```bash
sudo python3 nexssh.py --no-report
```

---

## 🔒 Read-Only by Design

nexSSH از ابتدا با رویکرد **Read-Only** طراحی شده است.

ابزار:

- تنظیمات SSH را تغییر نمی‌دهد
- فایل‌های سیستم را ویرایش نمی‌کند
- سرویس SSH را Restart نمی‌کند
- پکیج نصب نمی‌کند
- Firewall را تغییر نمی‌دهد
- Rule جدیدی ایجاد نمی‌کند
- کلید خصوصی را نمی‌خواند
- محتوای حساس را چاپ نمی‌کند

nexSSH فقط وضعیت سیستم را بررسی می‌کند و نتیجه را گزارش می‌دهد.

**Read → Analyze → Report**

نه:

**Read → Change → Break**

---

## 🛡️ Safe Execution

برای انجام برخی بررسی‌ها، مخصوصاً Permission فایل‌ها و دایرکتوری‌های کاربران، اجرای ابزار با `sudo` توصیه می‌شود.

اجرای ابزار با دسترسی Administrator صرفاً برای **خواندن اطلاعات مورد نیاز Audit** استفاده می‌شود.

nexSSH از این دسترسی برای اعمال تغییرات روی سیستم استفاده نمی‌کند.

---

## 🐧 Supported Systems

nexSSH برای سیستم‌های Linux طراحی شده است.

توزیع‌های مورد هدف شامل:

- Debian
- Ubuntu
- Fedora
- RHEL
- CentOS
- Arch Linux
- و سایر توزیع‌های Linux دارای OpenSSH

رفتار برخی Checkها ممکن است بسته به نسخه OpenSSH، ساختار سیستم و Service Manager متفاوت باشد.

---

## 📦 Requirements

### Operating System

```text
Linux
```

### Python

```text
Python 3.11+
```

### SSH

```text
OpenSSH / sshd
```

### Permissions

برای برخی بررسی‌ها:

```text
root / sudo
```

### Dependencies

```text
No external dependencies
```

nexSSH فقط از Python Standard Library استفاده می‌کند.

---

## ⚠️ Limitations

nexSSH یک ابزار سبک برای Security Audit است و جایگزین کامل تست نفوذ یا ممیزی امنیتی حرفه‌ای نیست.

محدودیت‌های فعلی:

- فقط Linux را پشتیبانی می‌کند
- ابزار فقط Audit انجام می‌دهد
- برای برخی Checkها نیاز به `sudo` وجود دارد
- نتیجه برخی Checkها به نسخه OpenSSH وابسته است
- Security Score یک معیار داخلی پروژه است
- شناسایی یک تنظیم ناامن لزوماً به معنی وجود یک آسیب‌پذیری قابل بهره‌برداری نیست
- استفاده از پورت غیرپیش‌فرض SSH به تنهایی امنیت SSH را تضمین نمی‌کند

---

## 🗺️ Roadmap

قابلیت‌های احتمالی برای نسخه‌های آینده:

- [ ] CIS Benchmark Checks
- [ ] SSH Security Baseline
- [ ] Baseline Comparison
- [ ] Custom Security Policies
- [ ] بهبود تحلیل `sshd_config`
- [ ] HTML Report پیشرفته‌تر
- [ ] CSV Output
- [ ] Remote SSH Audit
- [ ] بررسی پیشرفته‌تر Cryptographic Algorithms
- [ ] Plugin-based Checks
- [ ] CI/CD Security Audit

---

## 🧩 Project Structure

nexSSH عمداً به صورت **Single-File** طراحی شده است.

```text
nexSSH/
└── nexssh.py
```

تمام منطق اصلی پروژه در یک فایل قرار دارد.

این طراحی باعث می‌شود:

- نصب ساده باشد
- انتقال ابزار بین سرورها راحت باشد
- Dependency خارجی وجود نداشته باشد
- اجرای ابزار سریع و ساده باشد

---

## 🔐 Security Philosophy

nexSSH بر پایه یک ایده ساده ساخته شده است:

```text
Read
  ↓
Analyze
  ↓
Report
```

ابزار باید بتواند وضعیت امنیتی SSH را بررسی کند، بدون اینکه خودش تغییری در سیستم ایجاد کند.

---

## 🤝 Contributing

Pull Request و Issue برای بهبود nexSSH، اضافه کردن Checkهای جدید، اصلاح Bugها و بهبود گزارش‌ها استقبال می‌شود.

اگر Check امنیتی جدیدی اضافه می‌کنید، بهتر است:

- هدف Check مشخص باشد
- Severity منطقی تعیین شود
- مقدار فعلی تنظیمات مشخص باشد
- توضیح واضحی برای مشکل ارائه شود
- پیشنهاد اصلاح ارائه شود
- Check هیچ تغییری در سیستم ایجاد نکند

---

## 📜 License

این پروژه به صورت متن‌باز توسعه داده می‌شود.

جزئیات License در فایل `LICENSE` قرار دارد.

---

## 🌐 Links

- **GitHub:** https://github.com/7hekasra
- **Telegram:** https://t.me/linuxfarci
- **Website:** https://linuxfarci.ir

---

## ❤️ Open Source

نرم‌افزار آزاد فقط درباره کد نیست؛ درباره این است که دانش و ابزارهایی که ساخته‌ایم، پشت یک دیوار قفل نشوند و دیگران هم بتوانند آن‌ها را ببینند، یاد بگیرند، تغییر دهند و بهترشان کنند.

> **Code is better when knowledge is free.**
