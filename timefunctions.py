from datetime import datetime

from pytz import timezone

intervals = (
    ("years", 31536000),
    ("months", 2592000),
    # ('weeks', 604800),  # 60 * 60 * 24 * 7
    ("days", 86400),  # 60 * 60 * 24
    ("hours", 3600),  # 60 * 60
    ("minutes", 60),
    ("seconds", 1),
)


def apply_timezone(date_obj, tz):
    date_obj = timezone('UTC').localize(date_obj)
    return date_obj.astimezone(timezone(tz))


def _epoch_to_dto(epoch):
    fixedepoch = int(str(epoch)[:10])
    return datetime.fromtimestamp(fixedepoch)


def epochtopst(epoch, fmt='dt'):
    dt = _epoch_to_dto(epoch)
    dt = timezone('UTC').localize(dt)
    dt = dt.astimezone(timezone('US/Pacific'))
    if fmt == 'dt':
        return dt
    elif fmt == 'str' or fmt == 'string':
        return dt.strftime('%A, %b %d, %I:%M %p')


def servertime(stime):
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
    return int(ndt.timestamp())


def convert_time(dtime, timeonly=False, dateonly=False, tz=None):
    if isinstance(dtime, str) or isinstance(dtime, int):
        date_obj = _epoch_to_dto(dtime)
    else:
        date_obj = dtime
    if tz is not None:
        date_obj = apply_timezone(date_obj, tz)
    if timeonly:
        return date_obj.strftime('%-I:%M%p')
    elif dateonly:
        return date_obj.strftime('%m/%d/%y')
    else:
        return date_obj.strftime('%m/%d/%y %-I:%M%p')


def fix_item_time(rawtime, servertimezone):
    date_obj = datetime.strptime(rawtime, '%Y-%m-%dT%H:%M:%S.000Z')
    date_obj = timezone('UTC').localize(date_obj)
    date_obj = date_obj.astimezone(timezone(servertimezone))
    return date_obj.strftime('%m/%d/%y %I:%M %p')


def fix_news_time(rawtime, servertimezone):
    date_obj = datetime.strptime(rawtime, '%a, %d %b %Y %H:%M:%S -0500')
    date_obj = timezone('America/New_York').localize(date_obj)
    date_obj = date_obj.astimezone(timezone(servertimezone))
    return date_obj.strftime('%A, %b %d, %Y')


def elapsedTime(start_time, stop_time, append=False, granularity=1):
    result = []
    start_time = int(str(start_time)[:10])
    stop_time = int(str(stop_time)[:10])
    if start_time > stop_time:
        seconds = int(start_time) - int(stop_time)
    else:
        seconds = int(stop_time) - int(start_time)
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip("s")
            result.append("{} {}".format(int(value), name))
    if append:
        return ", ".join(result[:granularity]) + f" {append}"
    else:
        return ", ".join(result[:granularity])
