<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="نشان کهکشانی شاه‌تونل" width="330" />
</p>

<h1 align="center">شاه‌تونل ۳٫۰٫۰</h1>
<p align="center"><strong>ویرایش کهکشانی · تونل معکوس TCP با جداسازی پروفایل</strong></p>
<p align="center">یک Hub، چند Agent، مسیرهای تطبیقی و خروجی‌های مستقل.</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a> · <a href="#network-flow">🌌 جریان شبکه</a> · <a href="#tunnel-capabilities">⚡ قابلیت‌ها</a> · <a href="#install">🚀 نصب</a>
</p>

## 🌌 Network Flow | جریان شبکه

<table>
<tr><td align="center"><strong>معماری کهکشانی جریان شبکه</strong><br/><sub>تونل معکوس امن · چهار انتقال داخلی · مسیریابی مستقل هر پروفایل</sub></td></tr>
<tr><td align="center"><img src="docs/img/ShahTunnel-Network-Flow-v3-fa.png" alt="نقشه جریان شبکه کهکشانی شاه‌تونل نسخه ۳٫۰٫۰" width="100%" /></td></tr>
</table>

## Tunnel capabilities | قابلیت‌های تونل

<table>
<tr>
<td width="50%" valign="top">
<h3>🔵 ☑️ ارتباط Hub و Agent</h3>
<p>Hub ورودی عمومی TCP را فراهم می‌کند. هر Agent کانال‌های خروجی احرازشده به Hub می‌سازد و جریان‌های دریافتی را به سرویس محلی متناظر با Mapping منتقل می‌کند.</p>
</td>
<td width="50%" valign="top">
<h3>🔵 ☑️ انتقال داخلی تطبیقی</h3>
<p>هر Lane می‌تواند از TCP/TLS، ‏WebSocket/TLS، ‏HTTP/2 CONNECT یا ‏HTTP/1.1 CONNECT/TLS استفاده کند. بازیابی در سطح Lane انجام می‌شود و مسیرهای سالم بی‌دلیل قطع نمی‌شوند.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵 ☑️ خروجی مستقل Agent</h3>
<p>خروجی اتصال Agent بر اساس حالت انتخابی می‌تواند Direct، ‏Cloudflare WARP از طریق MASQUE یا WireGuard، یا Psiphon از طریق پراکسی SOCKS5 محلی باشد.</p>
</td>
<td width="50%" valign="top">
<h3>🔵 ☑️ جداسازی چند پروفایل</h3>
<p>هر پروفایل ShahTunnel فایل تنظیمات و سرویس systemd مستقل دارد. شروع، توقف و بازیابی یک پروفایل فقط همان پروفایل را تحت تأثیر قرار می‌دهد.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵 ☑️ خروجی WARP اختصاصی Xray</h3>
<p>یک Sidecar مستقل فقط Inbound انتخاب‌شده را روی پورت Loopback کپی می‌کند و ترافیک آن را از پراکسی SOCKS5 محلی WARP عبور می‌دهد. Inboundهای دیگر Xray در مسیر اصلی خود باقی می‌مانند.</p>
</td>
<td width="50%" valign="top">
<h3>🔵 ☑️ DNS خودکار در مسیر WARP</h3>
<p>Sidecar درخواست DNS کاربران روی پورت ۵۳ را دریافت می‌کند، از DNS-over-HTTPS کلادفلر/گوگل استفاده می‌کند و ترافیک Resolver را نیز از همان خروجی WARP عبور می‌دهد.</p>
</td>
</tr>
</table>

## جدول انتقال‌های تونل

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
| `9` | All-Protocol Adaptive | هر چهار انتقال داخلی روی خروجی‌های در دسترس، همراه با بازیابی مستقل Laneها. |

## 🌐 خروجی WARP مستقل برای هر تونل Xray

<table>
<tr><td>
<h3>🔵 ☑️ راه‌اندازی خودکار Agent جدید</h3>
<p>هنگام ساخت Agent با MASQUE، اگر Cloudflare Local Proxy یا همان <code>WarpProxy</code> از قبل فعال باشد، ShahTunnel پیش از شروع Agent، Sidecar اختصاصی Xray و مسیر DNS آن را به‌صورت خودکار آماده می‌کند. نیازی به ویرایش دستی JSON یا اجرای دستور تکمیلی نیست.</p>
</td></tr>
<tr><td>
<h3>🔵 ☑️ پروفایل‌های Agent موجود</h3>
<p>برای Agent موجود از مسیر <strong>Manager → [9] WARP egress</strong> استفاده کنید. ShahTunnel Inbound مربوط به Mapping همان پروفایل را شناسایی می‌کند، نسخهٔ Loopback آن را می‌سازد و فقط مقصد محلی همان Agent را تغییر می‌دهد.</p>
</td></tr>
<tr><td>
<h3>🔵 ☑️ محدودهٔ جداسازی و بازگشت</h3>
<p>تنظیمات Xray تحت مدیریت X-UI و سرویس اصلی آن ویرایش یا Restart نمی‌شوند. Inboundها و پروفایل‌های دیگر، از جمله پروفایل گزینهٔ ۷، Direct باقی می‌مانند. SSH و Default Route سرور تغییر نمی‌کنند. با حذف پروفایل ShahTunnel، Sidecar اختصاصی همان پروفایل نیز حذف می‌شود.</p>
</td></tr>
</table>

**شرط استفاده از WARP Local Proxy:** خروجی مستقل Xray به حالت Cloudflare ‏`WarpProxy` / ‏MASQUE و Listener محلی SOCKS5 نیاز دارد. این قابلیت با عبور دادن کل سرور از WARP تفاوت دارد. ShahTunnel، WARP را روشن یا خاموش نمی‌کند، پروتکل آن را تغییر نمی‌دهد و Routeهای سیستم را دست‌کاری نمی‌کند. اگر Local Proxy در دسترس نباشد، مسیر اختصاصی به‌صورت پنهانی با Route سراسری جایگزین نمی‌شود.

## امنیت و پایداری

<table>
<tr>
<td width="50%" valign="top">🔵 ☑️ **TLS 1.3 و احراز هویت Token**<br/><sub>ارتباط احرازشدهٔ Hub و Agent با تثبیت اثرانگشت گواهی SHA-256.</sub></td>
<td width="50%" valign="top">🔵 ☑️ **بازیابی مستقل Laneها**<br/><sub>هر Lane می‌تواند بدون قطع Laneهای سالم بازیابی شود.</sub></td>
</tr>
<tr>
<td width="50%" valign="top">🔵 ☑️ **سرویس مستقل هر پروفایل**<br/><sub>تنظیمات و واحد systemd جداگانه برای هر پروفایل تونل.</sub></td>
<td width="50%" valign="top">🔵 ☑️ **حفاظت از Route میزبان**<br/><sub>WARP اختصاصی، Default Route سرور را تغییر نمی‌دهد و SSH را Restart نمی‌کند.</sub></td>
</tr>
</table>

## نصب

روی سرور Linux پشتیبانی‌شده (amd64 یا arm64) دارای systemd و با دسترسی root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

نصب‌کننده سورس را دریافت می‌کند و باینری ShahTunnel را روی همان سرور Build می‌کند.

## بررسی انتقال‌ها

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

---

<p align="center"><strong>شاه‌تونل ۳٫۰٫۰ · ویرایش کهکشانی</strong><br/><sub>یک Hub، چند Agent، مسیرهای مستقل؛ شبکه‌ای که هوشمندانه به حرکت ادامه می‌دهد.</sub></p>
