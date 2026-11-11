# روش انتشار در GitHub بدون آپلود باینری

این نسخه برای انتشار **سورس‌محور** آماده شده است. فایل اجرایی ShahTunnel نباید به GitHub یا GitHub Releases اضافه شود.

## ۱) جایگزینی فایل‌ها در clone مخزن

ZIP سورس را در مسیر cloneشدهٔ مخزن `ShahNetLab/ShahTunnel` استخراج کنید؛ فایل‌ها باید مستقیماً در ریشهٔ مخزن قرار بگیرند (نه داخل یک پوشهٔ تودرتوی `ShahTunnel-3.0.0`).

## ۲) حذف باینری‌های قبلاً trackشده از Git

`.gitignore` جلوی اضافه‌شدن خروجی‌های بعدی را می‌گیرد. اگر پوشهٔ `dist` قبلاً در Git ثبت شده است، آن را از index خارج کنید:

```bash
git rm -r --cached dist 2>/dev/null || true
```

این فرمان فایل‌های محلی را پاک نمی‌کند؛ فقط دیگر در commit بعدی track نمی‌شوند.

## ۳) بازبینی و انتشار

```bash
git status --short
# مطمئن شوید فایل اجرایی ELF/PE در تغییرات staged نیست.
git add -A
git status --short
git commit -m "Fix WARP local proxy and restore source-based installer"
git push origin main
```

قبل از commit، اگر در مخزن تغییرات شخصی دیگری دارید، آن‌ها را جداگانه بازبینی کنید.

## ۴) نصب کاربران

پس از push شدن فایل‌ها به شاخهٔ `main`، کاربران همان دستور قبلی را اجرا می‌کنند:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

این دستور فقط نصب‌کننده را از `raw.githubusercontent.com` می‌گیرد. نصب‌کننده سورس را از `codeload.github.com/ShahNetLab/ShahTunnel` دریافت می‌کند، Go را از endpointهای رسمی توزیع Go (با SHA-256 ثابت) می‌گیرد و باینری مناسب معماری VPS را روی خود سرور build می‌کند. فایل اجرایی فقط روی VPS در `/usr/local/bin/ravanreverse` نصب می‌شود.

**پس از push موفق سورس، نیاز به آپلود هیچ باینری در GitHub نیست.**
