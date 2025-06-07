import winrm

# ساخت سشن به سمت ماشین ویندوز مقصد
session = winrm.Session('http://192.168.1.5:5985/wsman', auth=('test', 'test'))

# اجرای دستور ipconfig
result = session.run_cmd('tasklist')
#result = session.run_cmd('ipconfig')

# نمایش خروجی
print(result.std_out.decode())
