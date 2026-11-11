# اصلاحیه ShahTunnel 3.0.0

## اصلاح اصلی: Cloudflare WARP Local Proxy / MASQUE

- تشخیص خودکار خط `Mode: WarpProxy on port PORT` از خروجی `warp-cli settings`.
- اعتبارسنجی WARP از طریق خود پراکسی loopback با endpoint `https://api.cloudflare.com/cdn-cgi/trace` و الزام پاسخ `warp=on`.
- عبور واقعی اتصال Agent به Hub از HTTP CONNECT روی پراکسی محلی WARP؛ این کار برای هر چهار انتقال داخلی TCP/TLS، WebSocket/TLS، HTTP/2 CONNECT و HTTP/1.1 CONNECT اعمال می‌شود.
- عدم استفاده از مسیر مستقیم در گزینه ۸ در صورت خرابی WARP؛ گزینه ۹ همچنان می‌تواند طبق سیاست خود به مسیرهای جایگزین برود.
- رد صریح ترکیب WireGuard با WARP Local Proxy؛ حالت Local Proxy فقط با MASQUE استفاده می‌شود.
- حفظ رفتار تونل سراسری WARP و عدم تغییر Route یا سرویس SSH توسط ShahTunnel.

## مستندات و نصب

- دستور نصب سریع از GitHub دوباره در README انگلیسی و فارسی اضافه شد:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

- راهنمای WARP Local Proxy، روش تست با `api.cloudflare.com/cdn-cgi/trace` و توضیح ایمنی SSH اصلاح شد.
- نمودارهای Network Flow انگلیسی و فارسی به‌روزرسانی شدند.

## بررسی‌های اجراشده در محیط ساخت

- `go test -count=20 ./S1T-CAPSULE` — موفق
- `go test -race -count=5 ./S1T-CAPSULE` — موفق
- `go vet ./S1T-CAPSULE` — موفق
- `bash -n S1T-START.sh install.sh VERIFY-ALL-TRANSPORTS.sh` — موفق
- ساخت Linux amd64 و arm64 — موفق
- پین و checksum رسمی Go 1.26.11 برای amd64/arm64 — به‌روزرسانی شد

این بررسی‌ها با Go 1.23.2 اجرا شدند (حداقل نسخهٔ اعلام‌شده در `go.mod` برابر Go 1.23 است). اسکریپت نصب به Go 1.26.11 ارتقا یافت و SHA-256 رسمی جداگانهٔ amd64 و arm64 را بررسی می‌کند. این نسخه در ۱۰ نوامبر ۲۰۲۶ منتشر شد و اصلاحات امنیتی جدیدی برای Go command، compiler، linker، cgo و net/http دارد. تست زنده با سرویس WARP واقعی و Hub واقعی روی VPS اجرا نشده است.
