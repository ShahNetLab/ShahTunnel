# گزارش ادغام قابلیت‌های Nash در ShahTunnel

## جمع‌بندی تصمیم

هستهٔ ShahTunnel حفظ شده است؛ هیچ تغییری در پروتکل ارتباطی، ساختار پیام‌ها، احراز هویت، گواهی TLS یا منطق forwarding انجام نشده. قابلیت تازه به‌صورت یک ابزار جانبی و مستقل اضافه شده تا ریسک تغییر در مسیر ترافیک زنده صفر بماند.

## مقایسهٔ قابلیت‌ها

| حوزه | ShahTunnel | Nash | تصمیم |
|---|---|---|---|
| انتقال و Failover | چهار انتقال TCP/TLS، WebSocket/TLS، HTTP/2 CONNECT و HTTP/1.1 CONNECT با حالت adaptive | GRE و FRP معکوس | منطق انتقال Nash کپی نشد؛ دو معماری متفاوت‌اند و ShahTunnel از قبل Failover انتقالی دارد. |
| احیای سرویس | واحدهای systemd با `Restart=always` و زمان‌بندی restart | watchdog و timer | restart دومرحله‌ای اضافه نشد تا با systemd رقابت نکند و اتصال زنده را بی‌دلیل قطع نکند. |
| پایش منابع | آمار Runtime تونل | CPU، RAM، دیسک، uptime و وضعیت سرویس‌ها | به پنل محلی افزوده شد. |
| سلامت شبکه | وضعیت session و پورت‌های پیکربندی‌شده | TCP، ping و بررسی نودها | TCP probe برای آدرس‌های واقعی پروفایل‌ها افزوده شد؛ Ping معیار سلامت تونل قرار نگرفت. |
| لاگ‌ها | journalctl و منوی ترمینال | نمایش لاگ در پنل | مشاهدهٔ آخرین لاگ هر پروفایل در پنل اضافه شد. |
| مدیریت وب | ندارد | پنل وب همراه با actionهای مدیریتی | داشبورد فقط‌خواندنی اضافه شد؛ هیچ action برای restart/stop یا تغییر فایروال ندارد. |

## چه چیزی اضافه شد؟

- `tools/shah_panel.py`: سرور وب استاندارد Python، بدون وابستگی third-party.
- `tools/web/index.html`: رابط واکنش‌گرا و فارسی، با refresh خودکار پنج‌ثانیه‌ای.
- `tools/install-panel.sh`: نصب اختیاری پنل به‌صورت systemd service.
- `systemd/shah-tunnel-panel.service`: نمونهٔ واحد systemd سخت‌سازی‌شده.
- `tools/test_shah_panel.py`: تست‌های parser آدرس، مسیر Runtime، پورت‌های انتقال، و TCP probe.

پنل، فایل‌های تنظیمات را فقط می‌خواند. Token، Fingerprint و سایر مقادیر محرمانه را به API برنمی‌گرداند. listener آن روی `127.0.0.1` ثابت است؛ دسترسی از راه دور از طریق SSH port forwarding انجام می‌شود.

## چرا GRE و FRP از Nash کپی نشدند؟

فایل‌های Nash شامل توپولوژی عملیاتی مشخص، سرویس‌های FRP/Xray، مقادیر پورت و آدرس‌های وابسته به دو سرور، و کانفیگ‌های production/test است. انتقال مستقیم آن‌ها به installer عمومی می‌تواند پورت‌های نامتناسب باز کند، سرویس‌های موجود را جایگزین کند یا کلید/شناسهٔ محیط دیگری را وارد نصب شود.

از طرف دیگر، ShahTunnel یک Hub/Agent/Relay مستقل دارد و Agent خودش اتصال خروجی TLS را به Hub آغاز می‌کند. بنابراین انتقال FRP معکوس بدون طراحی مجدد مسیر و بدون مشخصات واقعی دو سمت، ارتقای قابل‌اعتماد محسوب نمی‌شود. قابلیت GRE نیز به پشتیبانی kernel، مجاز بودن IP protocol 47، routing، MTU و فایروال هر دو سرور وابسته است؛ این کار باید به‌عنوان ماژول اختیاری با پارامترهای واقعی همان محیط طراحی شود، نه با کپی کردن فایل‌های production.

## نحوهٔ استفاده

```bash
sudo bash tools/install-panel.sh
ssh -L 8091:127.0.0.1:8091 USER@SERVER
```

در مرورگر سیستم محلی: `http://127.0.0.1:8091`

حذف پنل:

```bash
sudo systemctl disable --now shah-tunnel-panel
sudo rm -f /etc/systemd/system/shah-tunnel-panel.service
sudo rm -rf /opt/shah-tunnel-panel
sudo systemctl daemon-reload
```

## راستی‌آزمایی انجام‌شده در بستهٔ تحویلی

- تست‌های Python پنل: ۸ تست موفق.
- `go test -count=20` و `go test -race -count=1`: موفق.
- Smoke test HTTP: health، API status، صفحهٔ HTML، عدم افشای Token، رد Host غیرمحلی با HTTP 421، و رد POST با HTTP 405 موفق.
- بررسی syntax اسکریپت‌های Bash: موفق.
- `go test ./S1T-CAPSULE`: موفق با Go 1.23.2.
- `go vet ./S1T-CAPSULE`: موفق.
- Build محلی Linux/amd64: موفق و نسخهٔ باینری `2.1.0` گزارش شد.

نصب واقعی واحد systemd روی VPS انجام نشده؛ فایل unit با `systemd-analyze verify` بررسی شده و اسکریپت نصب از نظر Bash syntax بررسی شده است.

توجه: اسکریپت `VERIFY-ALL-TRANSPORTS.sh` در مخزن اصلی، ابزار Go نسخهٔ دقیق 1.26.1 را الزام می‌کند؛ محیط بررسی حاضر Go 1.23.2 داشت، بنابراین همان اسکریپت پین‌شده اجرا نشد. تست‌ها و vet مستقیماً با toolchain موجود اجرا شدند.
