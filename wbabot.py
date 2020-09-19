#!/usr/bin/env python3.8
import signal
from asyncio import sleep
from configparser import ConfigParser
from datetime import datetime
from os import _exit, path, stat
from pathlib import Path
from sys import argv, exit, stdout

import boto3
import discord
import msgpack
import uvloop
from discord.ext import commands
from discord.utils import get
from fuzzywuzzy import fuzz
from loguru import logger as log
from prettyprinter import pprint
from pushover import Client, init

from processlock import PLock
from timefunctions import convert_time, elapsedTime

WORLD_BOSSES = {'Azuregos': 'Azhara', 'Kazzak': "Blasted Lands", "Ysondre": None, 'Emeriss': None, 'Taerar': None, 'Lethon': None}
DRAGON_ZONES = {1: 'Ashenvale', 2: 'Feralas', 3: 'The Hinterlands', 4: 'Duskwood'}

fuzzy_command_error = 75

SUCCESS_COLOR = 0x00FF00
FAIL_COLOR = 0xFF0000
INFO_COLOR = 0x0088FF
HELP_COLOR = 0xFF8800

configfile = '/etc/wbalert.cfg'
serverfile = '/home/ip/wbalert_server.cfg'
signals = (0, 'SIGHUP', 'SIGINT', 'SIGQUIT', 4, 5, 6, 7, 8, 'SIGKILL', 10, 11, 12, 13, 14, 'SIGTERM')


def signal_handler(signal, frame):
    log.warning(f'Termination signal [{signals[signal]}] caught. Closing web sessions...')
    log.info(f'Exiting.')
    exit(0)


signal.signal(signal.SIGTERM, signal_handler)  # Graceful Shutdown
signal.signal(signal.SIGHUP, signal_handler)  # Reload/Restart
signal.signal(signal.SIGINT, signal_handler)  # Hard Exit
signal.signal(signal.SIGQUIT, signal_handler)  # Hard Exit

head_dir = Path(".") / ".git" / "HEAD"
with head_dir.open("r") as f:
    content = f.read().splitlines()
for line in content:
    if line[0:4] == "ref:":
        BRANCH = line.partition("refs/heads/")[2]

if BRANCH != 'develop':
    processlock = PLock()
    processlock.lock()

if not path.exists(configfile) or stat(configfile).st_size == 0:
    log.error(f"Config file: {configfile} doesn't exist or is empty. Exiting.")
    exit(1)

systemconfig = ConfigParser()
systemconfig.read(configfile)

configtemplate = {}

for section, options in configtemplate.items():
    if not systemconfig.has_section(section):
        log.error(f'Error: Missing configuration section {section} in config file: {configfile}. Exiting.')
        exit(1)
    else:
        for option in options:
            if not systemconfig.has_option(section, option):
                log.error(f'Error: Missing config option {option} in {section} in config file: {configfile}. Exiting.')
                exit(1)

logfile = Path(systemconfig.get("general", "logfile"))
discordkey = systemconfig.get("general", "discord_key")
# discordkey_dev = systemconfig.get("general", "discord_devkey")
superadmin_id = systemconfig.get("general", "superadmin_id")
prefix = systemconfig.get("general", "command_prefix")
aws_key = systemconfig.get("general", "aws_key")
aws_secret = systemconfig.get("general", "aws_secret")
topic_arn = systemconfig.get("general", "topic_arn")
userdatafile = systemconfig.get("general", "userdata_file")
announce_chan = systemconfig.get("general", "announce_chan")
everyone_id = systemconfig.get("general", "everyone_id")
pushover_token = systemconfig.get("general", "pushover_token")
throttle_min = systemconfig.get("general", "throttle_min")
log_channel = systemconfig.get("general", "log_channel")
log_to_chan = systemconfig.get("general", "log_to_chan")

consoleformat = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green>| <level>{level: <8}</level> | <level>{message}</level> |<cyan>{function}</cyan>:<cyan>{line}</cyan>"
logformat = "{time:YYYY-MM-DD HH:mm:ss.SSS}| {level: <8} | {message} |{function}:{line}"

log.remove()

log.level("TRACE", color="<fg 245>")

if len(argv) > 1 or BRANCH == "develop":
    ll = "TRACE"
    log.add(sink=stdout, level=ll, format=consoleformat, colorize=True)
    if BRANCH == "develop":
        devfile = logfile.stem + "-dev" + logfile.suffix
        logfile = logfile.parent / devfile
else:
    ll = "TRACE"

log.add(sink=str(logfile), level=ll, buffering=1, enqueue=True, backtrace=True, format=logformat, diagnose=True, serialize=False, delay=False, colorize=False, rotation="5 MB", retention="1 month", compression="tar.gz")

log.debug(f'System configuration loaded successfully from {configfile}')
log.debug(f'Logfile started: {logfile}')

if BRANCH == 'develop':
    log.warning(f'World Boss Broadcasting System is starting in DEV MODE!')
else:
    log.info(f'World Boss Broadcasting System is starting in PRODUCTION MODE!')

bot = commands.Bot(command_prefix=prefix, case_insensitive=True)
bot.remove_command("help")
log.debug('Discord class initalized')

sns = boto3.client("sns", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, region_name='us-east-1')
log.debug('AWS SNS client initalized')

init(pushover_token)
log.debug('Pushover client initalized')

running_addme = {}
running_alert = {}
running_removeme = {}

# init new db
# data = {'0': str(int(datetime.now().timestamp()))}
# msgpack.dump(data, open(userdatafile, 'wb'))
userdata = msgpack.load(open(userdatafile, 'rb'))
log.info(f'Userdata loaded from {userdatafile}')

optout_list = sns.list_phone_numbers_opted_out()['phoneNumbers']


def saveuserdata():
    msgpack.dump(userdata, open(userdatafile, 'wb'))
    log.trace(f'Userdata saved to {userdatafile}')


def usersub(number):
    if number in sns.list_phone_numbers_opted_out()['phoneNumbers']:
        log.warning(f'Number [{number}] found in OptOut list, trying to remove')
        sns.opt_in_phone_number(phoneNumber=str(number))
    respo = sns.subscribe(TopicArn=topic_arn, Protocol='sms', Endpoint=number, ReturnSubscriptionArn=True)
    if 'SubscriptionArn' in respo:
        return respo['SubscriptionArn']
    else:
        log.error(respo)
        return False


def userunsub(uid):
    sns.unsubscribe(SubscriptionArn=userdata[uid]['subarn'])


async def checkoptouts():
    for opt in optout_list:
        for user, udata in userdata.items():
            if opt == udata['number']:
                log.info(f'Opted out number found [{udata["number"]}], removing user subsciption')
                del userdata[user]
    await sleep(60 * 60)


async def pubmsg(message, user, worldboss, zone):
    userdata['0'] = str(int(datetime.now().timestamp()))
    userdata['1'] = {'boss': worldboss, 'zone': zone}
    saveuserdata()
    msg = f"Everyone log in now and get to {zone.title()}\n**{len(userdata)-2}** players are being notified"
    embed = discord.Embed(title=f"{worldboss.title()} is UP in {zone.title()}!", description=msg, color=SUCCESS_COLOR)
    embed.set_footer(text=f'Type {prefix}alert addme to get World Boss alerts\nWorld Boss Broadcast System')
    channel = bot.get_channel(int(announce_chan))
    for guild in bot.guilds:
        everyone = get(guild.roles, id=int(everyone_id))
    await channel.send(everyone.mention)
    await channel.send(embed=embed)
    smsmsg = f'{worldboss.title()} is up in {zone.title()}!\nLog in now if possible\n\nReply STOP to end these notifications permenantly'
    log.debug(f'Sending AWS SNS notification to topic [{topic_arn}]')
    try:
        snsresponse = sns.publish(TopicArn=topic_arn, Message=smsmsg)
    except:
        log.exception('Error in AWS SNS topid send')
    pomsg = f'{worldboss.title()} is up in {zone.title()}!\nLog in now if possible'
    for uid, udata in userdata.items():
        if uid != '0' and uid != '1':
            if udata['alert'] == '1':
                log.debug(f'Sending discord PM notification to [{uid}]')
                duser = bot.get_user(int(uid))
                await duser.send(embed=embed)
                await sleep(.1)
            elif udata['alert'] == '2':
                log.debug(f'Sending pushover notification to [{uid}]')
                try:
                    Client(udata['pushover_id']).send_message(pomsg, title="World Boss Alert")
                    await sleep(1)
                except:
                    log.exception('Error in pushover send')
    await logchan(message, user, worldboss, zone)
    return snsresponse


async def logchan(message, user, worldboss, zone, *args):
    if log_to_chan != 'False':
        log.debug('Sending alert entry to log channel')
        channel = bot.get_channel(int(log_channel))
        msg = f'{worldboss.title()} was up in {zone.title()} at {convert_time(userdata["0"], tz="US/Pacific")}'
        await channel.send(msg)


def fuzzybosslookup(boss):
    ratios = {}
    for b in WORLD_BOSSES:
        ratio = fuzz.ratio(b, boss.title())
        ratios[b] = ratio
    v = list(ratios.values())
    k = list(ratios.keys())
    if max(v) >= fuzzy_command_error:
        if max(v) != 100:
            log.trace(f'Fuzzy boss lookup: {sorted(ratios.items())}')
            log.info(f'Fuzzy boss fixed [{boss.title()} -> {k[v.index(max(v))]}] [{max(v)}%]')
        return k[v.index(max(v))]
    else:
        log.debug(f'Fuzzy boss lookup failed: {sorted(ratios.items())}')
        return None


async def user_info(message):
    if type(message.channel) == discord.channel.DMChannel:
        for guild in bot.guilds:
            member = discord.utils.get(guild.members, id=message.author.id)
            if member:
                is_admin_role = False
                is_user_role = False
                admin_id = systemconfig.get("general", "admin_role_id")
                user_id = systemconfig.get("general", "user_role_id")
                for role in member.roles:
                    if str(role.id) == str(admin_id):
                        is_admin_role = True
                    if str(role.id) == str(user_id):
                        is_user_role = True
                if str(message.author.id) == str(superadmin_id):
                    is_superadmin = True
                else:
                    is_superadmin = False
                return {'user_id': message.author.id, 'user_name': message.author.name, 'guild_id': guild.id, 'guild_name': guild.name, 'channel': 'DMChannel', 'is_member': True, 'is_user': is_user_role, 'is_admin': is_admin_role, 'is_superadmin': is_superadmin}
            else:
                return {'user_id': message.author.id, 'user_name': message.author.name, 'guild_id': None, 'guild_name': None, 'channel': 'DMChannel', 'is_member': False, 'is_user': False, 'is_admin': False, 'is_superadmin': is_superadmin}
    else:
        is_admin_role = False
        is_user_role = False
        admin_id = systemconfig.get("general", "admin_role_id")
        user_id = systemconfig.get("general", "user_role_id")
        member = discord.utils.get(message.author.guild.members, id=message.author.id)
        for role in member.roles:
            if str(role.id) == str(admin_id):
                is_admin_role = True
            if str(role.id) == str(user_id):
                is_user_role = True
            if str(message.author.id) == str(superadmin_id):
                is_superadmin = True
            else:
                is_superadmin = False
        return {'user_id': message.author.id, 'user_name': message.author.name, 'guild_id': message.author.guild.id, 'guild_name': message.author.guild.name, 'channel': message.channel.id, 'is_member': True, 'is_user': is_user_role, 'is_admin': is_admin_role, 'is_superadmin': is_superadmin}


def logcommand(message, user):
    if type(message.channel) == discord.channel.DMChannel:
        dchan = "Direct Message"
    else:
        dchan = message.channel
    log.log("INFO", f"Request [{message.content}] from [{message.author}] in [#{dchan}]")


async def fake_typing(message):
    await message.channel.trigger_typing()


def error_embed(message):
    return discord.Embed(description="Resource unavailable, please try again later.", color=FAIL_COLOR)


async def bad_command(message, user, *args):
    msg = f'`{message.content}` is not a valid command.\nTry `{prefix}alert help` for a list of commands'
    embed = discord.Embed(description=msg, color=FAIL_COLOR)
    await messagesend(message, embed, user)


async def messagesend(message, embed, user, pm=False):
    try:
        if type(message.channel) == discord.channel.DMChannel or pm:
            return await message.author.send(embed=embed)
        elif type(message.channel) != discord.channel.DMChannel and pm:
            await message.delete()
            return await message.author.send(embed=embed)
        else:
            return await message.channel.send(embed=embed)
    except:
        log.exception("Critical error in message send")


@bot.event
async def on_ready():
        log.log("SUCCESS", f"Discord logged in as {bot.user.name} id {bot.user.id}")
        activity = discord.Activity(type=discord.ActivityType.listening, name=f"{prefix}alert")
        try:
            await bot.change_presence(status=discord.Status.online, activity=activity)
        except:
            log.error("Exiting")


@bot.event
async def on_message(message):
    if message.author.id != bot.user.id:
        user = await user_info(message)
        if user['guild_id'] is None:
            pass
        else:
            if user['user_id'] in running_addme:
                if message.content.lower() == 'cancel' or message.content.lower() == 'stop':
                    title = 'Alert setup cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    del running_addme[user['user_id']]
                    await messagesend(message, embed, user)
                elif running_addme[user['user_id']]['step'] == 1:
                    await addme_r1(message, user)
                elif running_addme[user['user_id']]['step'] == 2:
                    await addme_r2(message, user)
                elif running_addme[user['user_id']]['step'] == 3:
                    await addme_r3(message, user)
            elif user['user_id'] in running_removeme:
                if message.content.lower() == 'cancel' or message.content.lower() == 'stop':
                    title = 'Alert setup cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    del running_removeme[user['user_id']]
                    await messagesend(message, embed, user)
                elif running_removeme[user['user_id']]['step'] == 1:
                    await removeme_r1(message, user)
            elif user['user_id'] in running_alert:
                if message.content.lower() == 'cancel' or message.content.lower() == 'stop':
                    title = 'Alert cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    del running_alert[user['user_id']]
                    await messagesend(message, embed, user)
                elif running_alert[user['user_id']]['step'] == 1:
                    await alert_r1(message, user)
                elif running_alert[user['user_id']]['step'] == 2:
                    await sendit(message, user)
            else:
                args = message.content[1:].split(' ')
                if type(message.channel) == discord.channel.DMChannel:
                    if user['is_user'] or user['is_admin']:
                        if args[0].startswith('dd'):
                            await addme(message, user, *args)
                        elif args[0].startswith('emove'):
                            await removeme(message, user, *args)
                        elif args[0].startswith('top'):
                            await removeme(message, user, *args)
                        elif args[0].startswith('tatus'):
                            await status(message, user, *args)
                        elif args[0].startswith('otal'):
                            await total(message, user, *args)
                        elif args[0].startswith('lert'):
                            await status(message, user, *args)
                        elif args[0].startswith('hange'):
                            await addme(message, user, *args)
                        elif args[0].startswith('elp'):
                            await help(message, user, *args)
                        elif args[0].startswith('ast'):
                            await last(message, user, *args)
                        elif args[0].startswith('est') and user['is_superadmin']:
                            await test(message, user, *args)
                        elif args[0].startswith('orceremove') and user['is_superadmin']:
                            await forceremove(message, user, *args)
                if message.content.lower().startswith(f'{prefix}alert'):
                    if user['is_user'] or user['is_admin']:
                        args.pop(0)
                        if len(args) == 0:
                            await status(message, user, *args)
                        else:
                            if args[0] == 'addme' or args[0] == 'add' or args[0] == 'change' or args[0] == 'changeme':
                                await addme(message, user, *args)
                            elif args[0] == 'removeme' or args[0] == 'remove' or args[0] == 'stop':
                                await removeme(message, user, *args)
                            elif args[0] == 'status':
                                await status(message, user, *args)
                            elif args[0] == 'last':
                                await last(message, user, *args)
                            elif args[0] == 'total':
                                await total(message, user, *args)
                            elif args[0] == 'test' and user['is_superadmin']:
                                await test(message, user, *args)
                            elif args[0] == 'forceremove' and user['is_superadmin']:
                                await forceremove(message, user, *args)
                            else:
                                await alert(message, user, *args)


async def alert(message, user, *args):
    logcommand(message, user)
    if user['user_id'] not in running_alert:
        now = int(datetime.now().timestamp())
        expiretime = int(userdata['0']) + int(throttle_min) * 60
        if expiretime > now:
            log.info(f"Failed alert trigger [{int((expiretime - now)/60)} min] left still {user['user_name']} from {user['guild_name']}")
            title = f'You must wait {int((expiretime - now)/60)} min before sending another alert'
            msg = f'Last World Boss alert was {userdata["1"]["boss"]} in {userdata["1"]["zone"]}\n{convert_time(userdata["0"], tz="US/Pacific")} Server time, {elapsedTime(int(datetime.now().timestamp()), int(userdata["0"]))} ago'
            embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
        else:
            user['step'] = 1
            running_alert[user['user_id']] = user
            await alert1(message, user, *args)


async def alert1(message, user, *args):
    if user['user_id'] in running_alert:
        boss = fuzzybosslookup(args[0])
        if boss is None:
            del running_alert[user['user_id']]
            title = f'World Boss {args[0].title()} does not exist'
            msg = f'Valid options are:\n'
            for wboss in WORLD_BOSSES:
                msg = msg + f'**{wboss}**\n'
            embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
        else:
            log.info(f"Starting ALERT TRIGGER for {user['user_name']} from {user['guild_name']}")
            user['wboss'] = boss.title()
            user['step'] = 1
            running_alert[user['user_id']] = user
            if WORLD_BOSSES[boss] is None:
                await alert2(message, user, boss, *args)
            else:
                await alertfinalize(message, user, boss, WORLD_BOSSES[boss], *args)


async def alert2(message, user, boss, *args):
    if user['user_id'] in running_alert:
        title = f'Select which zone {running_alert[user["user_id"]]["wboss"]} is in:'
        msg = ''
        for num, zone in DRAGON_ZONES.items():
            msg = msg + f'**{num}**: {zone.title()}\n'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        embed.set_footer(text="Type your selection number below")
        lastmsg = await messagesend(message, embed, user, pm=False)
        user['lastmsg'] = lastmsg
        user['wboss'] = boss
        user['step'] = 1
        running_alert[user['user_id']] = user


async def alert_r1(message, user, *args):
    resp = message.content
    lastmsg = running_alert[user['user_id']]['lastmsg']
    if type(lastmsg.channel) != discord.channel.DMChannel:
        await lastmsg.delete()
    if resp.isnumeric():
        if resp == '0' and int(resp) < len(DRAGON_ZONES):
            log.warning(f"Invalid answer to start setup again [{message.content}]")
            msg = 'Invalid response.  Select a number for the zone listed'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
            await alert2(message, user, *args)
        else:
            await alertfinalize(message, user, running_alert[user['user_id']]['wboss'], DRAGON_ZONES[int(resp)], *args)


async def alertfinalize(message, user, boss, zone, *args):
    if type(message.channel) != discord.channel.DMChannel:
        await message.delete()
    user['step'] = 2
    user['wbzone'] = zone.title()
    user['wboss'] = boss.title()
    running_alert[user['user_id']] = user
    title = f'You are about send a World Boss Alert!'
    msg = f'**{boss.title()}** in **{zone.title()}**\nEveryone subscribed will get an alert to log on now!\n`Are you sure?\n\n**1**: Yes, Send it!\n**2**: No, Cancel alert'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    embed.set_footer(text='Type your number selection below')
    lastmsg = await messagesend(message, embed, user, pm=False)
    user['lastmsg'] = lastmsg
    running_alert[user['user_id']] = user


async def sendit(message, user):
    resp = message.content
    lastmsg = running_alert[user['user_id']]['lastmsg']
    if type(message.channel) != discord.channel.DMChannel:
        await message.delete()
    if type(lastmsg.channel) != discord.channel.DMChannel:
        await lastmsg.delete()
    if resp != '1' and resp != '2':
        log.warning(f"Invalid answer to start setup again [{message.content}]")
        msg = 'Invalid response.  Select 1 or 2'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, pm=False)
        await alertfinalize(message, user)
    else:
        if resp == '1':
            await pubmsg(message, user, running_alert[user['user_id']]['wboss'], running_alert[user['user_id']]['wbzone'])
            del running_alert[user['user_id']]
        elif resp == '2':
            log.warning(f"World boss alert has been cancelled")
            del running_alert[user['user_id']]
            title = 'Alert Cancelled'
            embed = discord.Embed(title=title, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)


async def addme(message, user, *args):
    logcommand(message, user)
    uid = str(user['user_id'])
    if user['user_id'] not in running_addme:
        log.info(f"Starting Addme for {user['user_name']} from {user['guild_name']}")
        user['step'] = 1
        running_addme[user['user_id']] = user
        if uid in userdata:
            if userdata[uid]['alert'] == '1':
                atype = 'Discord PM'
            elif userdata[uid]['alert'] == '3':
                atype = 'Text Message'
            elif userdata[uid]['alert'] == '2':
                atype = 'Pushover Notification'
            title = f'You are already setup for {atype} alerts\nWould you like to change something?'
            msg = f'**1**: Yes\n**2**: No'
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            await messagesend(message, embed, user, pm=True)
        else:
            title = f"Welcome to the World Boss Broadcasting System!"
            msg = "Type `cancel` at any time to cancel setup"
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            await messagesend(message, embed, user, pm=True)
            await addme2(message, user, *args)


async def addme_r1(message, user, *args):
    resp = message.content
    if resp != '1' and resp != '2':
        log.warning(f"Invalid answer to start setup again [{message.content}]")
        msg = 'Invalid response.  Select 1 or 2'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, pm=True)
        await addme(message, user, *args)
    elif resp == '1':
        await addme2(message, user, *args)
    elif resp == '2':
        title = f'Alert setup has been cancelled'
        msg = f'Type `{prefix}alert addme` in the future to run the setup wizard again'
        embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
        del running_addme[user['user_id']]
        await messagesend(message, embed, user, pm=True)


async def addme2(message, user, *args):
    user['step'] = 2
    running_addme[user['user_id']] = user
    title = 'Choose how you would like to be notified of World Boss alerts:'
    msg = '**1**: Discord Private Message (Can show as a notification with the mobile discord app)\n**2**: Pushover Notification (Free mobile push notification service [Link](https://pushover.net/))\n**3**: Text Message to cell phone'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    embed.set_footer(text="Type your selection number below")
    await messagesend(message, embed, user, pm=True)


async def addme_r2(message, user, *args):
    resp = message.content
    uid = str(user['user_id'])
    if resp != '1' and resp != '2' and resp != '3':
        msg = 'Invalid selection. Please answer 1, 2 or 3'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, pm=True)
        await addme2(message, user, *args)
    else:
        if resp == '1':
            userdata[uid] = {'alert': '1', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
            await addmefinish(message, user, *args)
        elif resp == '3':
            userdata[uid] = {'alert': '3', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
            await addme3(message, user, *args)
        elif resp == '2':
            userdata[uid] = {'alert': '2', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
            await addme3(message, user, *args)


async def addme3(message, user, *args):
    user['step'] = 3
    running_addme[user['user_id']] = user
    uid = str(user['user_id'])
    if userdata[uid]['alert'] == '3':
        title = 'Please enter the cell phone number you would like texts sent to'
        msg = 'Area code and number with no spaces or special characters\nExample: 5551214480'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        embed.set_footer(text='Type your phone number below')
    elif userdata[uid]['alert'] == '2':
        title = 'Please paste your pushover user key'
        msg = 'You sign up for a free account [here](https://pushover.net/signup) to get a user key'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        embed.set_footer(text='Paste your pushover user key below')
    await messagesend(message, embed, user, pm=True)


async def addme_r3(message, user, *args):
    resp = message.content
    uid = str(user['user_id'])
    if userdata[uid]['alert'] == '3':
        if len(resp) != 10 or not resp.isnumeric():
            log.warning(f"Invalid answer to start setup again [{message.content}]")
            msg = 'Invalid number. Enter area code and number, no spaces, no special characters: 5551214480'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=True)
            await addme3(message, user, *args)
        else:
            respo = usersub(f'+1{resp}')
            userdata[uid] = {'alert': '3', 'number': f'+1{resp}', 'pushover_id': 'None', 'subarn': respo}
            await addmefinish(message, user, *args)
    elif userdata[uid]['alert'] == '2':
        if len(resp) < 20:
            log.warning(f"Invalid answer to start setup again [{message.content}]")
            msg = "Invalid pushover user key.\nPaste the 'Your User Key' in the top right of your pushover account page"
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=True)
            await addme3(message, user, *args)
        else:
            userdata[uid] = {'alert': '2', 'number': 'None', 'pushover_id': resp}
            await addmefinish(message, user, *args)


async def addmefinish(message, user, *args):
    uid = str(user['user_id'])
    if userdata[uid]['alert'] == '2':
        atype = "Pushover notification"
    elif userdata[uid]['alert'] == '3':
        atype = "Text Message"
        usersub(userdata[uid]['number'])
    elif userdata[uid]['alert'] == '1':
        atype = "Discord PM"
    saveuserdata()
    title = 'Alert setup complete!'
    msg = f'You will now receive a {atype} when someone triggers a World Boss alert.\nType `{prefix}alert addme` to change your notification type\nType `{prefix}alert removeme` to remove yourself from notifications.'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    del running_addme[user['user_id']]
    await messagesend(message, embed, user, pm=True)


async def removeme(message, user, *args):
    logcommand(message, user)
    uid = str(user['user_id'])
    if user['user_id'] not in running_removeme:
        log.info(f"Starting removeme for {user['user_name']} from {user['guild_name']}")
        user['step'] = 1
        running_removeme[user['user_id']] = user
        if uid in userdata:
            if userdata[uid]['alert'] == '2':
                atype = "Pushover notification"
            elif userdata[uid]['alert'] == '3':
                atype = "Text Message"
            elif userdata[uid]['alert'] == '1':
                atype = "Discord PM"
            title = f'You are setup to receive {atype} alerts\nWhat would you like to do?'
            msg = f"**1**: Remove yourself from alerts permenantly\n**2**: Change how you get alerts\n**3**: Don't change anything"
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            embed.set_footer(text='Type your selection number below')
            await messagesend(message, embed, user, pm=True)
        else:
            title = f"You are not setup to receive any alerts"
            msg = f'Type `{prefix}alert addme` to be notified of World Boss alerts'
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            del running_removeme[user['user_id']]
            await messagesend(message, embed, user, pm=True)


async def removeme_r1(message, user, *args):
    resp = message.content
    uid = str(user['user_id'])
    if resp != '1' and resp != '2' and resp != '3':
        log.warning(f"Invalid answer to start setup again [{message.content}]")
        msg = 'Invalid response.  Select 1, 2 or 3'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, pm=True)
        await removeme(message, user, *args)
    elif resp == '2':
        del running_removeme[user['user_id']]
        await addme2(message, user, *args)
    elif resp == '3':
        title = f'Nothing has been changed'
        msg = f'Type `{prefix}alert addme` in the future to change alert settings\nType `{prefix}alert removeme` to stop alerts'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        del running_removeme[user['user_id']]
        await messagesend(message, embed, user, pm=True)
    elif resp == '1':
        del running_removeme[user['user_id']]
        if userdata[uid]['alert'] == '3':
            userunsub(uid)
        del userdata[uid]
        saveuserdata()
        title = f'You have been removed from receiving any alerts'
        msg = f'Type `{prefix}alert addme` in the future to setup alerts again"'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        await messagesend(message, embed, user, pm=True)


async def total(message, user, *args):
    title = f'There are {len(userdata)-2} players setup for World Boss alerts'
    discordcount = 0
    pushovercount = 0
    textcount = 0
    for each, udata in userdata.items():
        if each != '0' and each != '1':
            if udata['alert'] == '1':
                discordcount = discordcount + 1
            elif udata['alert'] == '2':
                pushovercount = pushovercount + 1
            elif udata['alert'] == '3':
                textcount = textcount + 1
    msg = f'**{discordcount}** players receiving Discord PM alerts\n**{pushovercount}** players receiving Pushover notification alerts\n**{textcount}** players receiving Text Message alerts'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    await messagesend(message, embed, user, pm=False)


async def status(message, user, *args):
    logcommand(message, user)
    uid = str(user['user_id'])
    if uid not in userdata:
        title = f'You are not setup to receive World Boss alerts'
    else:
        if userdata[uid]['alert'] == '2':
            atype = "Pushover notification"
        elif userdata[uid]['alert'] == '3':
            atype = "Text Message"
        elif userdata[uid]['alert'] == '1':
            atype = "Discord PM"
        title = f'You are setup to receive World Boss alerts via {atype}'
    msg = ''
    if user['is_admin']:
        msg = msg + f"Type `{prefix}alert <bossname>` to trigger a World Boss sightng alert\n"
    msg = msg + f'Type `{prefix}alert addme` change your alert settings\n'
    if uid in userdata:
        msg = msg + f'Type `{prefix}alert removeme` to remove yourself from World Boss alerts'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    embed.set_footer(text=f'Last World Boss alert was {userdata["1"]["boss"]} in {userdata["1"]["zone"]}\n{convert_time(userdata["0"], tz="US/Pacific")} Server time, {elapsedTime(int(datetime.now().timestamp()), int(userdata["0"]))} ago')
    await messagesend(message, embed, user, pm=False)


async def last(message, user, *args):
    logcommand(message, user)
    title = f'Last World Boss sighting alert was {userdata["1"]["boss"]} in {userdata["1"]["zone"]}'
    msg = f'{convert_time(userdata["0"], tz="US/Pacific")} Server time, {elapsedTime(int(datetime.now().timestamp()), int(userdata["0"]))} ago'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    await messagesend(message, embed, user, pm=False)


async def help(message, user, *args):
    logcommand(message, user)
    embed = discord.Embed(title="World Boss Brodcast System Commands:", color=HELP_COLOR)
    embed.add_field(name=f"**`{prefix}alert`**", value=f"Your World Boss alert status", inline=False)
    embed.add_field(name=f"**`{prefix}alert addme`**", value=f"Add yourself to be notified of World Boss alerts", inline=False)
    embed.add_field(name=f"**`{prefix}alert removeme`**", value=f"Remove yourself from World Boss alerts", inline=False)
    embed.add_field(name=f"**`{prefix}alert last`**", value=f"The last World Boss sighting alert", inline=False)
    embed.add_field(name=f"**`{prefix}alert help`**", value=f"This help mesage", inline=False)
    if user['is_admin']:
        embed.add_field(name=f"**`{prefix}alert <bossname>`**", value=f"Trigger a World Boss sighting alert!", inline=False)
    await message.author.send(embed=embed)


async def forceremove(message, user, *args):
        uid = str(user['user_id'])
        if uid in userdata:
            if userdata[uid]['alert'] == '3':
                userunsub(uid)
            del userdata[uid]
            saveuserdata()
            title = f'User has been removed from receiving any alerts'
        else:
            title = f'User ID [{uid}] not in user alert database'
        embed = discord.Embed(title=title, color=INFO_COLOR)
        await messagesend(message, embed, user, pm=True)


async def test(message, user, *args):
    logcommand(message, user)
    pprint(userdata)
    pprint(user)
    # blizcli = BlizzardAPI(bliz_int_client, bliz_int_secret, .get("server", "server_region"))
    # await blizcli.authorize()
    # pprint(await blizcli.realm_list())


def main():
    if BRANCH != 'develop':
        uvloop.install()
        bot.run(discordkey)
    else:
        uvloop.install()
        bot.run(discordkey_dev)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.info(f'Termination signal [KeyboardInterrupt] Closing web sessions.')
        log.info(f'Exiting.')
        exit(0)
        try:
            exit(0)
        except SystemExit:
            _exit(0)
    except:
        log.exception(f'Main Exception Caught!')
