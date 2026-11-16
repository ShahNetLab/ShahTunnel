ShahTunnel 6.0.0 — بهبود پایداری و هم‌زمانی خروجی Cloudflare WARP

نسخهٔ 6.0.0 مسیر خروجی WARP را در Agent قابل‌اعتمادتر می‌کند. این نسخه قبل از فعال‌کردن خروجی، اتصال واقعی SOCKS5 را آزمایش می‌کند و پاسخ Cloudflare Trace با warp=on یا warp=plus را لازم می‌داند؛ بازبودن پورت WarpProxy به‌تنهایی تأیید محسوب نمی‌شود.

اصلاحات مهم:
- برای خروجی WARP در Xray، Mux خاموش نگه داشته می‌شود تا جریان‌های TCP کاربران مستقل باشند.
- TCP Keepalive برای اتصال Xray به WarpProxy فعال شده است.
- حد file descriptor برابر ۱٬۰۴۸٬۵۷۶ و سقف ۱۶٬۳۸۴ Task برای سرویس مستقل Xray WARP تنظیم شده است. اگر حد فایل باز warp-svc کمتر از ۱۶٬۳۸۴ باشد، هشدار داده می‌شود و سرویس فعال Cloudflare خودکار Restart نمی‌شود.
- در صورت کمتر بودن منابع VPS از حداقل توصیه‌شدهٔ کلاینت Linux شرکت Cloudflare، هشدار ظرفیت نمایش داده می‌شود.
- بررسی سلامت SOCKS5 بدون Direct fallback انجام می‌شود؛ اگر WARP واقعاً خروجی ندهد، مسیر کاربران بی‌صدا به IP مستقیم سرور تغییر نمی‌کند.
- نسخهٔ برنامه، نصب‌کننده، بنر، نشان سرویس، آزمون‌ها و مستندات به 6.0.0 هماهنگ شده‌اند.
- قابلیت‌های موجود Direct، WARP/MASQUE و Psiphon حفظ شده‌اند.

نکتهٔ ظرفیت:
حداقل اعلام‌شده برای کلاینت WARP لینوکس ۳ vCPU و ۱ GiB RAM است؛ ۴ vCPU و ۲ GiB پیشنهاد می‌شود. این پیش‌نیاز کلاینت است، نه تضمین ۱۰۰ کاربر. خروجی WarpProxy بین کاربران همان پروفایل مشترک است و ظرفیت نهایی به پهنای‌باند، CPU، RAM، بار Packet، مسیر Hub/Agent و ظرفیت خروجی WARP بستگی دارد. تست واقعی را مرحله‌ای با افزایش تعداد کاربران انجام دهید.

نصب از مخزن:
روش جایگزین نصب (بدون raw.githubusercontent.com):
set -o pipefail
curl -fsSL --connect-timeout 10 --max-time 30 \
  -H 'Accept: application/vnd.github+json' \
  -H 'User-Agent: ShahTunnel-bootstrap' \
  'https://api.github.com/repos/ShahNetLab/ShahTunnel/contents/S1T-START.sh?ref=main' \
| python3 -c 'import sys,json,base64; d=json.load(sys.stdin); sys.stdout.buffer.write(base64.b64decode(d["content"]))' \
| bash

برای ظرفیت ۱۰۰ کاربر، روی دو سرور Hub و Agent تست مرحله‌ای انجام دهید و CPU، RAM، پهنای‌باند، Packet loss، TCP retransmits و لاگ Sidecar را ثبت کنید. هیچ عدد ثابتی از تعداد کاربر بدون مشخصات سخت‌افزار و تست بار قابل تضمین نیست.
