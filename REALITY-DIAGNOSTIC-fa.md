# تشخیص امن خطای REALITY/EOF

این نسخه فقط پیام عمومی fallback را با دسته‌بندی خطای واقعی برمی‌گردانده از کتابخانه REALITY جایگزین می‌کند. توکن، کلید خصوصی، AuthKey یا IP اتصال را در این پیام جدید چاپ نمی‌کند. این بسته به‌تنهایی ادعای حل EOF ندارد؛ هدفش این است که سرور Hub علت دقیق رد ClientHello را ثبت کند.

## روش استفاده

1. در GitHub مخزن `ShahNetLab/ShahTunnel`، فایل `S1T-CAPSULE/reality_transport.go` را با نسخه همین مسیر از بسته جایگزین و Commit کنید.
2. روی **سرور ایران (Hub) فقط** نصب‌گر آنلاین را دوباره اجرا کنید تا سورس جدید کامپایل شود:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

3. روی سرور ایران اجرا کنید:

```bash
systemctl restart ravanreverse
journalctl -u ravanreverse --since '3 minutes ago' --no-pager | grep -E 'REALITY fallback reason|HUB listening'
```

4. درحالی‌که Agent خارج در حال تلاش برای اتصال است، خط `REALITY fallback reason` را بفرستید.

تفسیر معمول: `server name mismatch` یعنی SNI متفاوت است؛ `authentication failed or validation criteria not met` یعنی احراز بسته REALITY/زمان/Short ID مردود شده؛ `unsupported TLS version` یعنی نسخه TLS نامتوافق است.
