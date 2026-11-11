<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="نشان کهکشانی شاه‌تونل" width="360" />
</p>

<h1 align="center">SHAH TUNNEL | شاه تونل</h1>
<p align="center"><strong>V3.0.0 · تونل معکوس TCP · بازیابی تطبیقی چندلایه</strong></p>
<p align="center">شاه‌تونل اتصال‌های عمومی TCP را از طریق Hub و مسیرهای احراز هویت‌شدهٔ Agent به سرویس‌های مقصد نگاشت‌شده هدایت می‌کند. در نسخهٔ ۳، علاوه بر چهار انتقال داخلی قبلی، مسیر خروجی Agent می‌تواند از SOCKS5 رسمی Psiphon یا از WARP فعال با پروتکل MASQUE / WireGuard عبور کند.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · 🇮🇷 فارسی</p>

## مسیر شبکه | Network Flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow-v3-fa.svg" alt="مسیر شبکه نسخهٔ ۳ شامل هاب، ایجنت، چهار انتقال داخلی و مسیرهای خروجی مستقیم، WARP/MASQUE و Psiphon" width="100%" />
</p>

## قابلیت‌ها

- **چهار انتقال داخلی واقعی:** TCP/TLS، ‏WebSocket/TLS، ‏HTTP/2 CONNECT و ‏HTTP/1.1 CONNECT/TLS.
- **گزینهٔ ۸ ـ مسیر خروجی خارجی:** انتخاب Cloudflare WARP با پروتکل MASQUE، ‏WARP با WireGuard یا Psiphon ConsoleClient از طریق SOCKS5 محلی.
- **گزینهٔ ۹ ـ بازیابی تطبیقی چندلایه:** تلاش برای هر چهار انتقال داخلی؛ اگر WARP متصل باشد، مسیر فعال MASQUE یا WireGuard ابتدا راستی‌آزمایی می‌شود و در صورت شکست به Psiphon و سپس Direct می‌رود. اگر WARP فعال نباشد، آخرین مسیر موفق Direct/Psiphon در اولویت است؛ در شروع ترتیب Direct و سپس Psiphon خواهد بود.
- **امنیت:** TLS 1.3 بین Hub و Agent، احراز هویت توکن، تثبیت اثرانگشت SHA-256 و محدودکردن پراکسی Psiphon به loopback.
- **مدیریت:** پروفایل و سرویس systemd مجزا برای هر تانل؛ گزینه‌های اصلی منوی مدیریت و کارکردشان تغییر نکرده‌اند.

## منوی انتقال

گزینه‌های ۱ تا ۷ از نظر رفتار و شماره‌گذاری قبلی حفظ شده‌اند. گزینه‌های ۸ و ۹ فقط به انتخاب‌گر انتقال اضافه شده‌اند؛ گزینهٔ ۸ منوی اصلی مدیریت همچنان «حذف کامل نصب» است.

| گزینه | انتقال / راهبرد | عملکرد |
|---|---|---|
| `1` | TCP/TLS | جریان تونل روی TLS. |
| `2` | WebSocket/TLS | انتقال جریان در فریم‌های WebSocket داخل TLS. |
| `3` | HTTP/2 CONNECT | جریان CONNECT روی TLS و پورت TCP شمارهٔ کنترل + ۱. |
| `4` | HTTP/1.1 CONNECT/TLS | جریان CONNECT روی TLS و پورت TCP شمارهٔ کنترل + ۲. |
| `5` | HTTP CONNECT fallback | ابتدا HTTP/2 و در صورت شکست، HTTP/1.1. |
| `6` | Automatic fallback | ابتدا TCP/TLS و سپس WebSocket/TLS. |
| `7` | Full Adaptive Failover | هر چهار انتقال داخلی؛ آخرین انتقال موفق هر lane در اولویت قرار می‌گیرد. |
| `8` | External egress | در Agent یک زیرگزینه انتخاب می‌شود: MASQUE/WARP، WARP/WireGuard یا Psiphon/SOCKS5. Hub فقط سیاست انتقال داخلی را می‌پذیرد. |
| `9` | All-Protocol Adaptive | چهار انتقال داخلی روی WARP فعال (در صورت اتصال)، سپس Psiphon و Direct؛ با قطع WARP مسیر Psiphon جایگزین می‌شود و در نبود WARP آخرین مسیر موفق Direct/Psiphon اولویت دارد. |

### نکتهٔ مهم دربارهٔ WARP و SSH

کلاینت لینوکس Cloudflare WARP یک تونل سطح سیستم است. ShahTunnel در گزینه‌های MASQUE/WARP فقط موارد زیر را بررسی می‌کند: وجود `warp-cli`، وضعیت Connected، پروتکل ثبت‌شده در `warp-cli settings` و خروجی واقعی `warp=on`. خود برنامه **هیچ‌وقت** `warp-cli connect`، تغییر پروتکل، `disconnect` یا تغییر route سیستم را اجرا نمی‌کند؛ بنابراین برای شروع این گزینه لازم است WARP از قبل توسط مدیر سرور فعال شده باشد. وضعیت، پروتکل و خروجی واقعی WARP پیش از هر تلاش اتصال مجدد نیز دوباره بررسی می‌شوند تا هنگام قطع WARP، اتصال بی‌صدا از مسیر عادی میزبان خارج نشود.

فعال‌کردن WARP ممکن است default route سرور را تغییر دهد و نشست SSH را قطع کند. فرمان‌های زیر را از کنسول ارائه‌دهنده یا با دسترسی جایگزین/خارج از باند اجرا و اتصال SSH را جداگانه آزمایش کنید؛ از یک نشست SSH تنها برای تغییر مسیر پیش‌فرض استفاده نکنید:

```bash
warp-cli tunnel protocol set MASQUE
warp-cli connect
warp-cli status
warp-cli settings | grep -i protocol
curl -fsS https://www.cloudflare.com/cdn-cgi/trace | grep '^warp=on$'
```

برای WireGuard به جای MASQUE از `warp-cli tunnel protocol set WireGuard` استفاده کنید. راهنمای رسمی: [نصب WARP در Linux](https://developers.cloudflare.com/warp-client/get-started/linux/) و [حالت‌های WARP](https://developers.cloudflare.com/warp-client/warp-modes/).

### راه‌اندازی Psiphon

نسخهٔ رسمی Linux از `ConsoleClient` و فایل پیکربندی Client استفاده می‌کند. ShahTunnel باینری Psiphon را داخل ZIP کپی نمی‌کند؛ آن را فقط از [مخزن باینری رسمی Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries) دریافت کنید. در فایل JSON باید `LocalSocksProxyPort` با پورتی که در راه‌انداز Agent وارد می‌کنید برابر باشد؛ مقدار پیش‌فرض `1080` است. برنامه `ConsoleClient` را با دایرکتوری دادهٔ مختص همان پروفایل و bind روی رابط loopback اجرا می‌کند، سپس اتصال Hub را از SOCKS5 عبور می‌دهد. نصب‌کننده برای هر دو واحد systemd قدیمی و قالبی فقط اجازهٔ نوشتن در `/var/lib/shah-tunnel/psiphon` را با drop-in محدود اضافه می‌کند؛ `ProtectSystem=strict` همچنان فعال می‌ماند. به این ترتیب فقط اتصال خروجی Agent پراکسی می‌شود، نه SSH و نه کل سیستم.

### پورت‌های فایروال Hub

اگر پورت کنترل Hub برابر `9443` باشد:

- `9443/TCP`: ‏TCP/TLS و WebSocket/TLS.
- `9444/TCP`: ‏HTTP/2 CONNECT.
- `9445/TCP`: ‏HTTP/1.1 CONNECT/TLS.

برای گزینه‌های ۷، ۸ و ۹ هر سه پورت را روی Hub باز بگذارید، زیرا Agent ممکن است بین چهار انتقال داخلی جابه‌جا شود. WARP/MASQUE و Psiphon پورت ورودی جدیدی روی Hub اضافه نمی‌کنند.

## جزئیات Failover و محدودیت‌های لایه

- در گزینهٔ ۹، اگر WARP متصل باشد، مسیر فعال MASQUE یا WireGuard ابتدا با بررسی وضعیت، تنظیم پروتکل و خروجی زندهٔ `warp=on` راستی‌آزمایی می‌شود؛ سپس چهار انتقال داخلی روی آن امتحان می‌شود. در صورت شکست یا قطع WARP، مسیر Psiphon SOCKS5 و بعد Direct امتحان می‌شود. اگر WARP فعال نباشد، آخرین مسیر موفق Direct/Psiphon اولویت دارد و در شروع ترتیب Direct و سپس Psiphon است.
- MASQUE و WireGuard دو پروتکل خروجی Cloudflare WARP هستند و توسط سرویس `warp-svc` در سطح سیستم مدیریت می‌شوند؛ آن‌ها پراکسی مستقل per-socket نیستند. ShahTunnel بدون ریسک‌کردن مسیر SSH، پروتکل WARP را وسط کار عوض نمی‌کند. اگر WARP فعال باشد، مسیر فعلی سیستم به‌عنوان یک مسیر مجزا راستی‌آزمایی می‌شود؛ مطمئن شوید IP هاب در فهرست استثناهای Split Tunnel قرار نگرفته باشد.
- Psiphon در این پیاده‌سازی با SOCKS5 برای جریان TCP استفاده می‌شود؛ این لایه، انتقال UDP مستقل فراهم نمی‌کند.
- قطع هر lane مستقل بازیابی می‌شود؛ laneهای سالم و سرویس SSH دست‌کاری یا restart نمی‌شوند.

## مدیریت چند تانل و کارایی

- هر تانل با نام یکتا و فایل تنظیمات جداگانه ذخیره می‌شود؛ ساخت تانل جدید، تانل‌های قبلی را بازنویسی نمی‌کند.
- هر پروفایل سرویس systemd مستقل دارد. شروع، توقف، راه‌اندازی مجدد، وضعیت و حذف یک تانل فقط روی همان پروفایل عمل می‌کند.
- پنجرهٔ ارسال هر جریان تا ۶۴ فریم ۶۴ کیلوبایتی افزایش یافته است. بهبود سرعت واقعی همچنان به پهنای‌باند، RTT، اتلاف بسته، ازدحام، qdisc و محدودیت میزبان وابسته است و تضمین سرعت مشخص ممکن نیست.

## نصب و ارتقا

روی Linux amd64 یا arm64 دارای systemd با کاربر root اجرا کنید:

```bash
sudo bash S1T-START.sh
```

نصب‌کننده نسخهٔ `3.0.0` را از سورس همین پوشه build می‌کند، ابزار Go نسخهٔ پین‌شده را با SHA-256 بررسی می‌کند و از باینری قبلی نسخهٔ پشتیبان می‌گیرد. سرویس فعال موجود در زمان ارتقا restart نمی‌شود تا نشست‌های فعلی قطع نشوند. نام سرویس‌های قدیمی `ravanreverse.service` و `/etc/ravanreverse` برای سازگاری حفظ شده‌اند.

پردازه‌ای که همین الان اجراست تا زمان restart همچنان باینری قبلی را در حافظه نگه می‌دارد. برای فعال‌شدن نسخهٔ جدید، فقط سرویس ShahTunnel انتخاب‌شده را در زمان مناسب restart کنید؛ این کار نشست‌های عبوری همان تانل را قطع و دوباره وصل می‌کند، اما `sshd` را restart یا تغییر نمی‌دهد:

```bash
sudo systemctl restart ravanreverse.service
# یا برای پروفایل نام‌دار:
sudo systemctl restart 'ravanreverse@PROFILE.service'
```

## تست

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

این اسکریپت تست‌های انتقال‌های داخلی، آزمون SOCKS5، بررسی static و ساخت باینری‌های amd64/arm64 را انجام می‌دهد. تست WARP واقعی به کلاینت متصل و اینترنت فعال نیاز دارد؛ در محیط build آفلاین به‌عنوان تست زنده اجرا نمی‌شود.
