from datetime import datetime

olddate = int(datetime.now().timestamp()) - 60

dt = datetime.now()
print(dt.weekday())
print(dt.hour)
print(dt.minute)
if dt.weekday() == 6 and dt.hour == 20 and dt.minute == 7 and int(dt.timestamp()) - olddate > (60 * 60):
    print('yes!')
else:
    print('no')

