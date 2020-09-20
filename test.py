from datetime import datetime
import msgpack
from prettyprinter import pprint
from pytz import timezone



def killtime(ktime):
    dt = datetime.today()
    dt = timezone('UTC').localize(dt)
    dt = dt.astimezone(timezone('US/Pacific'))
    bb = ktime.split(':')
    if len(bb) < 2:
        return None
    if not bb[0].isnumeric():
        return None
    hour = bb[0]
    minute = bb[1][:2]
    if not minute.isnumeric():
        return None
    loc = bb[1][2:]
    if loc.upper() != "AM" and loc.upper() != "PM" and loc.upper() != "P" and loc.upper() != "A":
        return None
    if loc.upper() == 'A':
        loc = 'AM'
    elif loc.upper() == 'P':
        loc = 'PM'
    nts = f'{dt.month}-{dt.day}-{dt.year} {hour}:{minute} {loc.upper()}'
    try:
        inp = datetime.strptime(nts, '%m-%d-%Y %I:%M %p')
    except:
        return None
    ndt = timezone('US/Pacific').localize(inp)
    return ndt.timestamp()

print(killtime('1:01p'))




#dt = timezone('UTC').localize(dt)
#c = dt.astimezone(timezone('US/Eastern'))

#print(str(c))

