<p align="center">
  <img src="docs/img/shah-tunnel-logo.png" alt="لوگوی شاه تونل" width="220" />
</p>

<h1 align="center">SHAH TUNNEL | شاه تونل</h1>
<p align="center"><strong>نسخهٔ ۱.۶.۳ · تونل معکوس TCP · بازیابی تطبیقی مسیر</strong></p>
<p align="center">هدایت پورت‌های عمومی Hub به سرویس مقصد از طریق Agent، با ارتباط خصوصی TLS 1.3، احراز هویت توکن، تثبیت اثرانگشت گواهی و اتصال مجدد خودکار.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## مسیر شبکه | Network Flow

<p align="center">
  <img src="docs/img/a_polished_neon_cyberpunk_infographic_graphic_dar.png" alt="نمودار فارسی جریان شبکه شاه تونل، شامل کلاینت، هاب، پیوند خصوصی، ایجنت، مقصد و چهار مسیر انتقال" width="100%" />
</p>

## قابلیت‌ها

- **چهار روش انتقال پیاده‌سازی‌شده:** TCP/TLS، ‏WebSocket/TLS، ‏HTTP/2 CONNECT و ‏HTTP/1.1 CONNECT/TLS.
- **بازیابی خودکار:** اتصال مجدد با تأخیر افزایشی و jitter و ترجیح آخرین مسیر احراز هویت‌شدهٔ موفق برای هر lane.
- **امنیت:** TLS 1.3 در ارتباط خصوصی Hub↔Agent، احراز هویت توکن و تثبیت اثرانگشت SHA-256 گواهی.
- **هم‌زمانی:** دوازده lane مستقل به‌صورت پیش‌فرض، صف‌های محدود و انتخاب نشست با توجه به بار.
- **مدیریت:** منوی ترمینال، سرویس systemd، نمایش وضعیت و لاگ، نصب‌کننده و اسکریپت بررسی محلی.

## مدیریت چند تانل روی یک سرور

از منوی اصلی وارد **Tunnel Profiles** شوید. با گزینهٔ ساخت، نقش HUB یا AGENT یا RELAY را انتخاب کنید و سپس یک نام دلخواه برای تانل وارد کنید. هر تانل تنظیمات، وضعیت اجرا، گواهی و کلید TLS (برای HUB) و سرویس systemd مستقل خودش را دارد؛ بنابراین می‌توانید چند تانل را هم‌زمان روی یک سرور اجرا کنید. گزینه‌های Start، Stop، Restart و Status ابتدا تانل را با نام از شما می‌گیرند. از بخش مدیریت نیز می‌توانید یک تانل را با نام خودش حذف کنید؛ حذف یک تانل به فایل‌ها و سرویس تانل‌های دیگر دست نمی‌زند. پورت‌های رزروشدهٔ تانل‌های ذخیره‌شده پیش از ساخت تانل جدید بررسی می‌شوند تا از تداخل جلوگیری شود. تنظیم قدیمی موجود در مسیر `/etc/ravanreverse/config.json` نیز هنگام ساخت تانل جدید حفظ می‌شود.

## منوی انتقال

روی هر دو سمت Hub و Agent گزینهٔ سازگار را انتخاب کنید.

| گزینه | انتقال / راهبرد | عملکرد |
|---|---|---|
| `1` | TCP/TLS | جریان تونل روی اتصال TLS. |
| `2` | WebSocket/TLS | انتقال جریان در فریم‌های WebSocket داخل TLS. |
| `3` | HTTP/2 CONNECT | جریان CONNECT روی TLS و پورت TCP شمارهٔ کنترل + ۱. |
| `4` | HTTP/1.1 CONNECT/TLS | جریان CONNECT روی TLS و پورت TCP شمارهٔ کنترل + ۲. |
| `5` | HTTP CONNECT fallback | ابتدا HTTP/2 و در صورت شکست راه‌اندازی، HTTP/1.1 را امتحان می‌کند. |
| `6` | Automatic fallback | ابتدا TCP/TLS و سپس WebSocket/TLS. |
| `7` | Full Adaptive Failover | هر چهار انتقال را امتحان می‌کند و آخرین مسیر احراز‌شدهٔ موفق را برای هر lane ترجیح می‌دهد. |

### پورت‌های فایروال Hub

اگر پورت کنترل Hub برابر `9443` باشد:

- `9443/TCP`: مسیرهای TCP/TLS و WebSocket/TLS.
- `9444/TCP`: ‏HTTP/2 CONNECT در گزینه‌های ۳، ۵ و ۷.
- `9445/TCP`: ‏HTTP/1.1 CONNECT در گزینه‌های ۴، ۵ و ۷.

فقط پورت‌های لازم برای گزینهٔ انتخاب‌شده را باز کنید. هر چهار انتقال این نسخه از TCP استفاده می‌کنند.

## استفادهٔ مسئولانه و حریم خصوصی

ShahTunnel یک رلهٔ عمومی TCP است. آن را فقط برای سرورها و سرویس‌هایی پیکربندی کنید که مالک آن‌ها هستید یا مجوز صریح مدیریتشان را دارید. از آن برای دسترسی بدون مجوز به سامانه‌های اشخاص ثالث، انتقال ترافیک آزاردهنده یا مختل‌کردن سرویس‌ها استفاده نکنید. مسئولیت مقصدها و ترافیکی که عبور می‌دهید با مدیر سامانه است.

بخش نمایش اطلاعات سرور ممکن است برای تشخیص IPv4 عمومی و کشور سرور، درخواست HTTPS به سرویس‌های عمومی تشخیص IP و GeoIP از جمله ipify، icanhazip، checkip.amazonaws.com، ipinfo.io، ip.sb، ipapi.co و ipwho.is بفرستد. این سرویس‌ها می‌توانند IP عمومی سرور و فرادادهٔ درخواست را ببینند؛ درخواست‌های GeoIP شامل توکن تونل یا محتوای ترافیک تونل نیستند.

برای سازگاری با نصب‌های قبلی، تانل پیش‌فرض قدیمی همچنان از واحد `ravanreverse.service` و فایل `/etc/ravanreverse/config.json` استفاده می‌کند. تانل‌های نام‌دار جدید با واحد مستقل `ravanreverse@NAME.service` و فایل‌های داخل `/etc/ravanreverse/tunnels/NAME/` اجرا می‌شوند. نصب‌کننده فرمان `shah-tunnel` را نیز به‌صورت symlink فراهم می‌کند. این مسیرهای محلی را دستی تغییر ندهید.

## نصب

روی Linux amd64 یا arm64 با systemd و دسترسی HTTPS به GitHub، دستور را با کاربر root اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

نصب‌کننده باینری آمادهٔ متناسب با معماری سرور را مستقیماً از پوشهٔ `S1T-CAPSULE` همین مخزن دریافت می‌کند: `shah-tunnel-linux-amd64` یا `shah-tunnel-linux-arm64`. فایل‌ها در GitHub Releases قرار نمی‌گیرند. SHA-256 و سپس نسخه و معماری باینری بررسی می‌شود؛ در صورت مغایرت، نصب متوقف می‌شود. روی سرور ایران نیازی به دانلود Go، دریافت سورس کامل، یا کامپایل وجود ندارد. هنگام انتشار نسخهٔ جدید، هر دو باینری و فایل نصب‌کننده باید در مخزن به‌روزرسانی شوند. از باینری قبلی نسخهٔ پشتیبان نگه داشته می‌شود و سرویس فعال برای جلوگیری از قطع اتصال‌های جاری ری‌استارت نمی‌شود.

## ساخت و تست

برای اجرای اسکریپت تست، Go 1.26.1 باید از قبل روی سیستم موجود باشد؛ این اسکریپت ابزار Go را دانلود نمی‌کند. از ریشهٔ مخزن اجرا کنید:

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

یا بررسی‌های اصلی را مستقیم اجرا کنید:

```bash
gofmt -w S1T-CAPSULE/main.go S1T-CAPSULE/main_test.go
go test -race -count=20 ./S1T-CAPSULE
go vet ./S1T-CAPSULE
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-amd64 ./S1T-CAPSULE
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-arm64 ./S1T-CAPSULE
(cd dist && sha256sum shah-tunnel-linux-amd64 > shah-tunnel-linux-amd64.sha256)
(cd dist && sha256sum shah-tunnel-linux-arm64 > shah-tunnel-linux-arm64.sha256)
```
