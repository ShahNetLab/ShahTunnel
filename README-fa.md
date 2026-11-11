<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="نشان کهکشانی شاه‌تونل" width="290" />
</p>

<h1 align="center">شاه‌تونل ۳٫۰٫۰</h1>
<p align="center"><strong>ویرایش کهکشانی · تونل معکوس TCP با جداسازی پروفایل</strong></p>
<p align="center">یک Hub، چند Agent، مسیرهای تطبیقی و خروجی‌های مستقل.</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a> &nbsp;·&nbsp;
  <a href="#network-flow">🌌 جریان شبکه</a> &nbsp;·&nbsp;
  <a href="#tunnel-capabilities">⚡ قابلیت‌ها</a> &nbsp;·&nbsp;
  <a href="https://t.me/MediaZet">🚀 نصب و راهنما در تلگرام</a>
</p>

<p align="center">
  <a href="https://t.me/MediaZet"><img src="https://img.shields.io/badge/Telegram_Channel-%40MediaZet-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="ورود به کانال تلگرام شاه‌تونل MediaZet" /></a>
  &nbsp;
  <a href="https://t.me/cloudflare0_bot"><img src="https://img.shields.io/badge/Cloudflare_Bot-%40cloudflare0_bot-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="ورود به ربات کلودفلر در تلگرام" /></a>
</p>
<p align="center"><sub>برای حمایت و دریافت خبرهای شاه‌تونل عضو کانال شوید؛ ربات برای انجام کارهای کلودفلر است.</sub></p>

<a id="network-flow"></a>
## 🌌 Network Flow | جریان شبکه

<p align="center"><strong>معماری کهکشانی جریان شبکه</strong><br/><sub>تونل معکوس · انتقال‌های تطبیقی · خروجی مستقل هر Agent</sub></p>
<p align="center"><img src="docs/img/ShahTunnel-Network-Flow-v3-fa.png" alt="نقشه جریان شبکه کهکشانی شاه‌تونل نسخه ۳٫۰٫۰" width="100%" /></p>

<a id="tunnel-capabilities"></a>
## ⚡ Tunnel capabilities | قابلیت‌های تونل

<table>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ رله معکوس Hub و Agent</h3>
<sub>Hub اتصال عمومی TCP را می‌پذیرد. Agent کانال خروجی احرازشده می‌سازد و جریان را به سرویس محلیِ متصل به Mapping می‌رساند.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ انتقال تطبیقی</h3>
<sub>انتقال‌های TCP/TLS، ‏WebSocket/TLS، ‏HTTP/2 CONNECT و ‏HTTP/1.1 CONNECT برای مسیر داخلی تونل.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ بازیابی مستقل Laneها</h3>
<sub>هر Lane جداگانه بازیابی می‌شود؛ خرابی یک Lane لزوماً مسیرهای سالم را قطع نمی‌کند.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ جداسازی پروفایل‌ها</h3>
<sub>هر پروفایل فایل تنظیمات و سرویس systemd مستقل دارد؛ عملیات فقط همان پروفایل را درگیر می‌کند.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ خروجی مستقل Agent</h3>
<sub>بر اساس حالت انتخابی: Direct، ‏WARP/MASQUE، ‏WARP/WireGuard یا Psiphon/SOCKS5.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ خروجی WARP اختصاصی Xray</h3>
<sub>فقط Inbound انتخاب‌شده در Sidecar مستقل و Loopback کپی می‌شود و از SOCKS5 محلی WARP عبور می‌کند.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ مسیر DNS خودکار</h3>
<sub>Sidecar درخواست DNS کاربر را مدیریت می‌کند و درخواست DoH مربوط به Resolver را نیز از خروجی WARP همان پروفایل می‌فرستد.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ حفاظت از مسیر میزبان</h3>
<sub>Default Route سرور، SSH و تنظیمات و سرویس اصلی Xray تحت مدیریت X-UI تغییر یا Restart نمی‌شوند.</sub>
</td>
</tr>
</table>

## 🚦 جدول انتقال‌های تونل

| گزینه | انتقال / راهبرد | عملکرد تونل |
|:--:|---|---|
| `1` | TCP/TLS | جریان رمزنگاری‌شده با TLS بین Hub و Agent. |
| `2` | WebSocket/TLS | حمل جریان تونل در فریم‌های باینری WebSocket روی TLS. |
| `3` | HTTP/2 CONNECT | جریان CONNECT روی TLS و پورت کنترل + ۱. |
| `4` | HTTP/1.1 CONNECT/TLS | جریان CONNECT روی TLS و پورت کنترل + ۲. |
| `5` | HTTP CONNECT fallback | ابتدا HTTP/2 و سپس HTTP/1.1. |
| `6` | Automatic fallback | ابتدا TCP/TLS و سپس WebSocket/TLS. |
| `7` | Full Adaptive Failover | هر چهار انتقال داخلی؛ هر Lane آخرین انتقال موفق خود را ترجیح می‌دهد. |
| `8` | External egress | انتخاب خروجی Agent: ‏WARP/MASQUE، ‏WARP/WireGuard یا Psiphon/SOCKS5. |
| `9` | WARP egress | خروجی Xray اختصاصی هر پروفایل از طریق SOCKS5 محلی WARP. |

## 🌐 خروجی WARP مستقل برای هر تونل Xray

<table>
<tr><td>
<h3>🔵✔ راه‌اندازی خودکار Agent جدید</h3>
<sub>هنگام ساخت Agent با MASQUE، اگر Cloudflare Local Proxy فعال باشد، ShahTunnel پیش از شروع Agent، Sidecar اختصاصی Xray و مسیر DNS آن را آماده می‌کند.</sub>
</td></tr>
<tr><td>
<h3>🔵✔ پروفایل‌های Agent موجود</h3>
<sub>از مسیر Manager → [9] WARP egress استفاده کنید. ShahTunnel، Inbound مرتبط با Mapping همان پروفایل را پیدا کرده و نسخه Loopback آن را ایجاد می‌کند.</sub>
</td></tr>
<tr><td>
<h3>🔵✔ محدوده جداسازی</h3>
<sub>Inboundها و پروفایل‌های دیگر Direct می‌مانند. سرویس Xray تحت مدیریت X-UI، SSH و Default Route میزبان تغییر یا Restart نمی‌شوند.</sub>
</td></tr>
</table>

**پیش‌نیاز WARP Local Proxy:** خروجی مستقل Xray به Listener محلی SOCKS5 در حالت Cloudflare ‏`WarpProxy` / ‏MASQUE نیاز دارد. این قابلیت به معنی عبور کل سرور از WARP نیست. اگر پراکسی محلی در دسترس نباشد، مسیر اختصاصی با Route سراسری جایگزین نمی‌شود.

## نصب

برای ورود به تلگرام، دریافت راهنمای نصب و اطلاع از انتشارها روی دکمه **🚀 نصب و راهنما در تلگرام** در بالای صفحه بزنید. دستور نصب لینوکس نیز در دسترس است:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

دستور را با دسترسی root روی سرور Linux دارای systemd و معماری amd64 یا arm64 اجرا کنید. نصب‌کننده سورس را دریافت کرده و باینری ShahTunnel را روی سرور Build می‌کند.

## بررسی انتقال‌ها

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

---

<p align="center"><strong>شاه‌تونل ۳٫۰٫۰ · ویرایش کهکشانی</strong><br/><sub>یک Hub، چند Agent، مسیرهای مستقل؛ شبکه‌ای که هوشمندانه به حرکت ادامه می‌دهد.</sub></p>
