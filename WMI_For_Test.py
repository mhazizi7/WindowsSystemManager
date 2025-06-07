import wmi
import subprocess

# ساخت کانکشن WMI
c = wmi.WMI()

# اجرای ipconfig با استفاده از subprocess (چون ipconfig خودش جزو کوئری‌های WMI نیست)
result = subprocess.run(["ipconfig"], capture_output=True, text=True)

# نمایش خروجی
print(result.stdout)


