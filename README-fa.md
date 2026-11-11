<div align="center">

<img src="docs/img/ShahTunnel-Network.png" alt="نشان کهکشانی شاه‌تونل" width="100%">

# شاه‌تونل ۳٫۰٫۰

**GALACTIC EDITION · PROFILE-ISOLATED REVERSE TCP TUNNEL**

[![نسخه](https://img.shields.io/badge/version-3.0.0-168BFF?style=flat-square)](https://github.com/ShahNetLab/ShahTunnel)
[![نسخه ابزار ساخت](https://img.shields.io/badge/build-Go%201.26.1-00ADD8?style=flat-square&logo=go)](S1T-START.sh)
![سیستم‌عامل](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey?style=flat-square)

[English](README.md) · **فارسی**

[🌌 جریان شبکه](#network-flow) · [⚡ قابلیت‌ها](#capabilities) · [🚀 نصب](https://t.me/MediaZet)

</div>

---

<a id="capabilities"></a>

## قابلیت‌ها

| | قابلیت | کارکرد |
|:--:|---|---|
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **رله معکوس Hub و Agent** | Hub پورت عمومی TCP را می‌پذیرد؛ Agent اتصال خروجی می‌سازد و هر Mapping را به مقصد محلی می‌رساند. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **پروفایل‌های مستقل** | هر تونل فایل تنظیمات و سرویس systemd جدا دارد؛ عملیات مدیریت روی پروفایل انتخاب‌شده انجام می‌شود. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Laneهای انتقال تطبیقی** | چهار انتقال پیاده‌سازی‌شده به‌صورت جدا یا در حالت‌های Failover قابل استفاده‌اند. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **بازیابی مستقل Lane** | هر Lane جداگانه دوباره متصل می‌شود؛ خرابی یک Lane الزاماً Laneهای سالم را قطع نمی‌کند. پروفایل Agent جدید به‌صورت پیش‌فرض ۱۲ Lane مستقل دارد (حداکثر ۱۶). |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **چند Mapping پورت** | شناسه هر Mapping، Listener عمومی Hub را به مقصد محلی Agent متصل می‌کند و باید در دو سمت یکسان باشد. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **خروجی مستقل Agent** | خروجی Agent می‌تواند Direct، ‏WARP/MASQUE، ‏WARP/WireGuard یا Psiphon/SOCKS5 باشد. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **WARP اختصاصی Xray** | Inbound انتخاب‌شده به Sidecar محدود به Loopback کپی و از SOCKS5 محلی WARP عبور داده می‌شود. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **مسیر خودکار DNS در WARP** | Sidecar درخواست DNS کاربر را مدیریت می‌کند و درخواست DoH مربوط به Resolver را نیز از همان خروجی WARP می‌فرستد. |

## انتقال‌های Hub↔Agent

در زمان ساخت تونل یک حالت را انتخاب کنید. تنظیمات Hub و Agent باید با هم سازگار باشند.

| گزینه ویزارد | حالت | عملکرد |
|:--:|---|---|
| `1` | TCP/TLS | جریان TLS بین Hub و Agent. |
| `2` | WebSocket/TLS | انتقال جریان تونل در فریم‌های باینری WebSocket روی TLS. |
| `3` | HTTP/2 CONNECT | انتقال CONNECT روی TLS و پورت کنترل + ۱. |
| `4` | HTTP/1.1 CONNECT/TLS | انتقال CONNECT روی TLS و پورت کنترل + ۲. |
| `5` | HTTP CONNECT fallback | ابتدا HTTP/2 و در صورت نیاز HTTP/1.1. |
| `6` | Automatic fallback | ابتدا TCP/TLS و سپس WebSocket/TLS. |
| `7` | Full Adaptive Failover | هر چهار انتقال؛ هر Lane آخرین انتقال موفق خود را ترجیح می‌دهد. |
| `8` | External egress | در Agent انتخاب Cloudflare MASQUE، ‏WARP/WireGuard یا Psiphon/SOCKS5. |
| `9` | All-protocol adaptive | در Agent ترکیب هر چهار انتقال با Failover خروجی Direct/Psiphon. |

### روش‌های خروجی Agent

| روش | پیش‌نیاز / مسیر |
|---|---|
| `Direct` | اتصال Agent به Hub از مسیر عادی سرور. |
| `WARP / MASQUE` | تونل WARP با MASQUE یا Cloudflare Local Proxy باید از قبل فعال باشد. |
| `WARP / WireGuard` | تونل سیستمی WARP باید از قبل متصل باشد. |
| `Psiphon / SOCKS5` | فایل تنظیمات رسمی Psiphon ConsoleClient و Listener محلی SOCKS5 لازم است. |
| `Adaptive` | مسیر Failover خروجی Direct/Psiphon. |

> **دو گزینه ۹ متفاوت هستند:** گزینه `9` در ویزارد ساخت تونل یعنی All-protocol adaptive؛ گزینه `9` در منوی اصلی مدیریت، خروجی WARP مستقل Xray را برای Agent انتخاب‌شده فعال می‌کند.

## نصب

ShahTunnel از معماری **Hub / Agent** استفاده می‌کند. برنامه را روی سرور Hub و هر Agent نصب کنید. در صورت نیاز، یک سرور سوم نیز می‌تواند نقش Relay داشته باشد.

**پیش‌نیازها:** لینوکس `amd64` یا `arm64`، سرویس `systemd` و دسترسی root. نصب‌کننده ابزار Go نسخهٔ 1.26.1 را دریافت و با SHA-256 بررسی می‌کند، سپس باینری لینوکس را روی همان سرور می‌سازد.

**۱. نصب روی هر سرور**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

<div dir="rtl">

پس از نصب، منوی مدیریت باز می‌شود. برای ورود دوباره:

</div>

```bash
sudo shah-tunnel menu
```

<div dir="rtl">

**۲. ساخت Hub**

1. گزینه ساخت تونل جدید را انتخاب کنید و نقش **HUB** را بزنید.
2. پورت کنترل را تعیین کنید (پیش‌فرض `0.0.0.0:9443`) و انتقال مورد قبول Hub را انتخاب کنید.
3. نگاشت پورت‌های عمومی را بسازید. برای هر نگاشت یک شناسه مانند `main` یا `web` تعیین کنید.
4. **توکن Agent** و **اثر انگشت SHA-256 گواهی** را ذخیره کنید؛ Agent باید دقیقاً از همین دو مقدار استفاده کند.

**۳. ساخت Agent**

1. روی سرور مقصد، تونل جدید بسازید و نقش **AGENT** را انتخاب کنید.
2. آدرس Hub و پورت کنترل را وارد کنید و انتقال سازگار با Hub را برگزینید.
3. توکن و اثر انگشت گواهی Hub را وارد کنید.
4. همان شناسه‌های Mapping را بسازید و مقصد محلی هرکدام را وارد کنید؛ برای نمونه `127.0.0.1:443`.
5. پروفایل را ذخیره کنید. ShahTunnel سرویس مستقل آن را فعال می‌کند و Laneهای قطع‌شده را به‌صورت خودکار دوباره متصل می‌کند.

**۴. فایروال:** فقط پورت‌های لازم را باز کنید. Hub به پورت کنترل انتخاب‌شده، پورت CONNECT در صورت نیاز (`کنترل + ۱` برای HTTP/2 یا `کنترل + ۲` برای HTTP/1.1) و پورت‌های عمومی Mapping نیاز دارد. Agent اتصال خروجی را به Hub برقرار می‌کند و مقصدهای محلی در سمت Agent هستند.


</div>


## خروجی WARP مستقل برای هر تونل Xray

- **Agent جدید:** هنگام ساخت Agent با MASQUE، اگر Cloudflare Local Proxy شناسایی شود، ShahTunnel پیش از شروع Agent، Sidecar مستقل Xray و مسیر DNS مبتنی بر WARP را آماده می‌کند.
- **Agent موجود:** پروفایل Agent را در منوی مدیریت انتخاب کنید و گزینه **`[9] WARP egress`** را بزنید.
- **جداسازی:** فقط Inbound کپی‌شده از پروفایل انتخاب‌شده از SOCKS5 محلی WARP عبور می‌کند؛ سایر Inboundها و پروفایل‌ها Direct می‌مانند.
- **امنیت مسیر میزبان:** تنظیمات و سرویس اصلی Xray تحت مدیریت X-UI، سرویس SSH و Default Route سرور توسط این اتصال مستقل تغییر یا Restart نمی‌شوند.

این قابلیت به Listener محلی **Cloudflare WarpProxy / Local Proxy** از نوع SOCKS5 نیاز دارد. این قابلیت WARP سراسری سرور نیست. اگر Local Proxy در دسترس نباشد، مسیر اختصاصی بی‌صدا با Route سراسری جایگزین نمی‌شود.

## مدیریت روزمره

`sudo shah-tunnel menu` منوی مدیریت را باز می‌کند. عملیات روی پروفایل انتخاب‌شده انجام می‌شود:

| گزینه منو | عملکرد |
|:--:|---|
| `1` | ساخت پروفایل جدید Hub، Agent یا Relay. |
| `2` | شروع تونل انتخاب‌شده. |
| `3` | توقف تونل انتخاب‌شده. |
| `4` | راه‌اندازی مجدد تونل انتخاب‌شده. |
| `5` | نمایش وضعیت و لاگ‌های اخیر. |
| `6` | تنظیم Restart زمان‌بندی‌شده تونل‌های فعال. |
| `7` | حذف فقط یک پروفایل انتخاب‌شده. |
| `8` | حذف کامل ShahTunnel. |
| `9` | فعال‌سازی WARP مستقل برای Agent انتخاب‌شده. |

<div dir="rtl">

دستورهای کاربردی:

</div>

```bash
sudo shah-tunnel version
sudo shah-tunnel menu
sudo systemctl status 'ravanreverse@PROFILE.service' --no-pager -l
sudo journalctl -u 'ravanreverse@PROFILE.service' -n 80 --no-pager
```

<div dir="rtl">

به‌جای `PROFILE` نام Instance سرویس همان پروفایل را قرار دهید. برای بررسی ساده‌تر، گزینه **Status & Logs** در منوی مدیریت، وضعیت و ۴۰ لاگ اخیر را نشان می‌دهد.

## امنیت

- توکن Hub و اثر انگشت گواهی را محرمانه نگه دارید. Agent باید دقیقاً از مقادیر تولیدشده در Hub استفاده کند.
- در فایروال Hub فقط پورت کنترل/CONNECT انتخاب‌شده و پورت‌های عمومی Mapping موردنیاز را باز کنید.
- توکن، کلید خصوصی، فایل کامل تنظیمات یا لاگ بدون حذف اطلاعات حساس را در Issue یا تصویر عمومی منتشر نکنید.
- Sidecar اختصاصی WARP برای Inbound کپی‌شده روی Loopback گوش می‌دهد و جایگزین سرویس اصلی Xray تحت مدیریت X-UI نمی‌شود.
- ShahTunnel را فقط روی سرورها و سرویس‌هایی استفاده کنید که مالک آن هستید یا مجوز مدیریتشان را دارید. [سیاست امنیتی](SECURITY.md).

## عیب‌یابی

</div>

| مشکل | اولین بررسی |
|---|---|
| Agent متصل نمی‌شود | آدرس Hub، توکن، اثر انگشت گواهی، سازگاری حالت انتقال و پورت‌های فایروال را بررسی کنید. |
| HTTP/2 یا HTTP/1.1 CONNECT کار نمی‌کند | پورت TCP اضافه Hub را بررسی کنید (`کنترل + ۱` یا `کنترل + ۲`). |
| Mapping ترافیک را عبور نمی‌دهد | شناسه Mapping در Hub و Agent و دسترسی به مقصد محلی Agent را بررسی کنید. |
| WARP مستقل فعال نمی‌شود | مطمئن شوید Agent روی MASQUE است و Cloudflare Local Proxy پیش از گزینه `9` فعال است. |
| DNS گوگل/یوتیوب روی WARP مستقل مشکل دارد | وضعیت سرویس `shah-tunnel-xray-warp-<profile>.service` و لاگ‌های همان Sidecar را ببینید؛ مسیرهای میزبان را تغییر ندهید. |

---

<a id="network-flow"></a>

## Network Flow | جریان شبکه

<div dir="rtl">

مسیر انتقال Hub به Agent و خروجی اینترنت اختیاری هر پروفایل مستقل از یکدیگرند: تونل، Mappingهای TCP را به مقصد محلی Agent می‌رساند؛ مسیر اختیاری Xray فقط Inbound انتخاب‌شده را از خروجی SOCKS5 وایرپ همان پروفایل عبور می‌دهد.

</div>

```text
کاربر → پورت عمومی Hub → Laneهای احرازشده Agent → مقصد محلی Agent
Inbound انتخاب‌شده Xray → Sidecar محدود به Loopback → SOCKS5 وایرپ → اینترنت
```

<p align="center"><img src="docs/img/ShahTunnel-Network-Flow-v3-fa.png" alt="جریان شبکه ShahTunnel 3.0.0" width="100%"></p>

<div dir="rtl">

برای حمایت از ShahTunnel و دریافت خبرها عضو کانال شوید؛ ربات برای عملیات Cloudflare است.

</div>

<p align="center">
<a href="https://t.me/MediaZet"><img src="https://img.shields.io/badge/تلگرام-کانال%20%40MediaZet-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="عضویت در کانال تلگرام ShahTunnel"></a>
&nbsp;
<a href="https://t.me/cloudflare0_bot"><img src="https://img.shields.io/badge/تلگرام-ربات%20Cloudflare-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="ورود به ربات Cloudflare"></a>
</p>
