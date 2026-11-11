# انتشار سورس ShahTunnel 3.0.0 (بدون باینری)

این مخزن عمداً فقط سورس و ابزار نصب را نگهداری می‌کند. هیچ فایل اجرایی کامپایل‌شده‌ای در GitHub یا ZIP سورس قرار ندهید.

## نصب کاربر نهایی

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

فرایند نصب:

1. دریافت `S1T-START.sh` از `raw.githubusercontent.com`.
2. دریافت آرشیو سورس از `https://codeload.github.com/ShahNetLab/ShahTunnel/tar.gz/refs/heads/main`.
3. دریافت Go toolchain نسخهٔ پین‌شده از توزیع رسمی Go و تطبیق SHA-256.
4. build محلی برای معماری همان VPS (`amd64` یا `arm64`).
5. نصب فایل ساخته‌شده فقط در `/usr/local/bin/ravanreverse`.

## فایل‌هایی که باید در Git ثبت شوند

- `S1T-START.sh` و `install.sh`
- `go.mod` و سورس `S1T-CAPSULE/`
- تست‌ها، READMEها، مستندات و دیاگرام‌ها

دایرکتوری `/dist/` و فایل‌های اجرایی محلی توسط `.gitignore` نادیده گرفته می‌شوند.
