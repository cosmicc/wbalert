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
from timefunctions import convert_time, elapsedTime, killtime, epochtopst
from apifetch import BlizzardAPI

WORLD_BOSSES = {'Azuregos': 'Azhara', 'Kazzak': "Blasted Lands", "Ysondre": None, 'Emeriss': None, 'Taerar': None, 'Lethon': None}
DRAGON_ZONES = {1: 'Ashenvale', 2: 'Feralas', 3: 'The Hinterlands', 4: 'Duskwood'}

SPAWN_TIMES = {'Azuregos': {'resetmin': 43200, 'resetmax': 172800, 'spawnmin': 259200, 'spawnmax': 432000}, 'Kazzak': {'resetmin': 43200, 'resetmax': 172800, 'spawnmin': 259200, 'spawnmax': 432000}, "Ysondre": {'resetmin': 108000, 'resetmax': 130500, 'spawnmin': 259200, 'spawnmax': 432000}, 'Emeriss': {'resetmin': 108000, 'resetmax': 130500, 'spawnmin': 259200, 'spawnmax': 432000}, 'Taerar': {'resetmin': 108000, 'resetmax': 130500, 'spawnmin': 259200, 'spawnmax': 432000}, 'Lethon': {'resetmin': 108000, 'resetmax': 130500, 'spawnmin': 259200, 'spawnmax': 432000}}

fuzzy_command_error = 75

SUCCESS_COLOR = 0x00FF00
FAIL_COLOR = 0xFF0000
INFO_COLOR = 0x0088FF
HELP_COLOR = 0xFF8800

E_NUM = {1: '1️⃣', 2: '2️⃣', 3: '3️⃣', 4: '4️⃣', 5: '5️⃣', 6: '6️⃣'}
E_YES = '✅'
E_NO = '❌'

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
    configfile = '/etc/wbalert.cfg'
    processlock = PLock()
    processlock.lock()
else:
    configfile = '/etc/wbalert-dev.cfg'

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
superadmin_id = systemconfig.get("general", "superadmin_id")
prefix = systemconfig.get("general", "command_prefix")
aws_key = systemconfig.get("general", "aws_key")
aws_secret = systemconfig.get("general", "aws_secret")
topic_arn = systemconfig.get("general", "topic_arn")
userdatafile = systemconfig.get("general", "userdata_file")
announce_chan = systemconfig.get("general", "announce_chan")
announce_chan2 = systemconfig.get("general", "announce_chan2")
everyone_id = systemconfig.get("general", "everyone_id")
everyone_id2 = systemconfig.get("general", "everyone_id2")
pushover_token = systemconfig.get("general", "pushover_token")
throttle_min = systemconfig.get("general", "throttle_min")
log_channel = systemconfig.get("general", "log_channel")
log_to_chan = systemconfig.get("general", "log_to_chan")
bliz_clientid = systemconfig.get("general", "bliz_clientid")
bliz_secret = systemconfig.get("general", "bliz_secret")
announce_server_up = systemconfig.get("general", "announce_server_up")


consoleformat = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green>| <level>{level: <8}</level> | <level>{message}</level> |<cyan>{function}</cyan>:<cyan>{line}</cyan>"
logformat = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green>| <level>{level: <8}</level> | <level>{message}</level> |<cyan>{function}:{line}</cyan>"

log.remove()

log.level("TRACE", color="<fg 245>")
log.level("COMPLETE", no=21, color="<fg 129>", icon="¤")
log.level("START", no=21, color="<fg 219>", icon="¤")
log.level("REQUEST", no=20, color="<fg 221>", icon="¤")
log.level("TRIGGER", no=20, color="<light-cyan>", icon="¤")
log.level("SERVER", no=20, color="<fg 231>", icon="¤")

if len(argv) > 1 or BRANCH == "develop":
    ll = "TRACE"
    log.add(sink=stdout, level=ll, format=consoleformat, colorize=True)
    if BRANCH == "develop":
        devfile = logfile.stem + "-dev" + logfile.suffix
        logfile = logfile.parent / devfile
else:
    ll = "TRACE"

log.add(sink=str(logfile), level=ll, buffering=1, enqueue=True, backtrace=True, format=logformat, diagnose=True, serialize=False, delay=False, colorize=True, rotation="5 MB", retention="1 month", compression="tar.gz")

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
serverup = True

# init new db
# data = {'0': str(int(datetime.now().timestamp())), '1': {'boss': None, 'zone': None}, '2': {'Azuregos': None, 'Kazzak': None, "Ysondre": None, 'Emeriss': None, 'Taerar': None, 'Lethon': None} , '3': 1600783800}
# msgpack.dump(data, open(userdatafile, 'wb'))

userdata = msgpack.load(open(userdatafile, 'rb'))
log.info(f'Userdata loaded from {userdatafile}')

# if '0' not in userdata:
#    userdata['0'] = str(int(datetime.now().timestamp()))
# if '1' not in userdata:
#    userdata['1'] = {'boss': None, 'zone': None}
# if '2' not in userdata:
#    userdata['2'] = {'Azuregos': None, 'Kazzak': None, "Ysondre": None, 'Emeriss': None, 'Taerar': None, 'Lethon': None}
# userdata['3'] = 1600783800

optout_list = sns.list_phone_numbers_opted_out()['phoneNumbers']


async def is_serverup():
    global serverup
    log.trace(f'Running server up check API call')
    blizcli = BlizzardAPI(bliz_clientid, bliz_secret, 'US')
    await blizcli.authorize()
    serverstatus = await blizcli.realm_status('4398')
    await blizcli.close()
    if 'error' in serverstatus or serverstatus is None:
        log.warning(f"Blizzard API server query error: {serverstatus['error']}")
        return None
    else:
        if serverstatus['status']['type'] == 'UP':
            if not serverup:
                dt = datetime.now()
                log.log("SERVER", "Server query return server back UP")
                log.info(f'Updating Server reset time to [{epochtopst(int(dt.timestamp()), fmt="string")}]')
                userdata['3'] = int(dt.timestamp())
                saveuserdata()
                if announce_server_up == 'True':
                    title = f'Server has come back online on {epochtopst(int(dt.timestamp()), fmt="string")}'
                    embed = discord.Embed(title=title, color=SUCCESS_COLOR)
                    channel = bot.get_channel(int(announce_chan))
                    await channel.send(embed=embed)
            serverup = True
            return True
        else:
            if serverup:
                log.log("SERVER", 'Server query returned server is DOWN')
                if announce_server_up == 'True':
                    title = f'Server has gone offline for maintenance on {epochtopst(int(dt.timestamp()), fmt="string")}'
                    embed = discord.Embed(title=title, color=SUCCESS_COLOR)
                    channel = bot.get_channel(int(announce_chan))
                    await channel.send(embed=embed)
            serverup = False
            return False


async def maintloop():
    while True:
        # log.trace('Running maintenance loop')
        now = int(datetime.now().timestamp())
        try:
            for user, udata in running_alert.copy().items():
                if udata['timer'] + 30 < now:
                    if udata['step'] < 2:
                        log.warning(f'Alert timeout override for [{udata["user_name"]}]')
                        worldboss = udata['boss']
                        zone = udata['zone']
                        channel = udata['message'].channel
                        del running_alert[user]
                        await pubmsg(user, channel, worldboss, zone)
                    else:
                        log.warning(f'Running alert timeout for [{udata["user_name"]}]')
                        title = f'World Boss Alert has been cancelled'
                        embed = discord.Embed(title=title, color=FAIL_COLOR)
                        message = udata['message']
                        if type(message.channel) == discord.channel.DMChannel:
                            u = bot.get_user(int(user))
                            await u.send(embed=embed)
                        else:
                            await udata['message'].delete()
                            await message.channel.send(embed=embed)
                        del running_alert[user]
        except:
            log.exception('Error in auto running alert removal')

        try:
            for user, udata in running_addme.copy().items():
                if udata['timer'] + (60 * 30) < now:
                    log.warning(f'Running addme timeout for [{udata["user_name"]}]')
                    title = f'Alert addme wizard has been cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    u = bot.get_user(int(user))
                    await u.send(embed=embed)
                    del running_addme[user]
        except:
            log.exception('Error in auto running addme removal')

        try:
            for user, udata in running_removeme.copy().items():
                if udata['timer'] + (60 * 30) < now:
                    log.warning(f'Running removeme timeout for [{udata["user_name"]}]')
                    title = f'Alert removeme wizard has been cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    u = bot.get_user(int(user))
                    await u.send(embed=embed)
                    del running_removeme[user]
        except:
            log.exception('Error in auto running removeme removal')

        dt = datetime.now()
        if dt.weekday() == 1 and (dt.hour >= 13 and dt.hour <= 15):
            await is_serverup()
        await sleep(50)

bot.loop.create_task(maintloop())


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


async def pubmsg(user, channel, worldboss, zone):
    log.debug(f'Executing pubmsg routine for [{worldboss}] in [{zone}]')
    userdata['0'] = str(int(datetime.now().timestamp()))
    userdata['1'] = {'boss': worldboss, 'zone': zone}
    saveuserdata()
    msg = f"**{len(userdata)-4}** players are being notified\nType {prefix}alert addme to get World Boss alerts"
    embed = discord.Embed(title=f"{worldboss.title()} is UP in {zone.title()}, Log in Now!", description=msg, color=SUCCESS_COLOR)
    embed.set_footer(text=f'World Boss Broadcast System')
    channel = bot.get_channel(int(announce_chan))
    channel2 = bot.get_channel(int(announce_chan2))
    try:
        for guild in bot.guilds:
            everyone = get(guild.roles, id=int(everyone_id))
            everyone2 = get(guild.roles, id=int(everyone_id2))
    except:
        log.exception('Error while parsing guild roles')
    try:
        await channel.send(everyone.mention)
        await channel.send(embed=embed)
    except:
        log.exception('Error while sending channel1 notification')
    if channel2 is not None:
        try:
            await channel2.send(everyone2.mention)
            await channel2.send(embed=embed)
        except:
            log.exception('Error while sending channel2 notification')
    smsmsg = f'{worldboss.title()} is up in {zone.title()}!\n\nReply STOP to end these notifications permanently'
    log.debug(f'Sending AWS SNS notification to topic [{topic_arn}]')
    try:
        snsresponse = sns.publish(TopicArn=topic_arn, Message=smsmsg)
    except:
        log.exception('Error in AWS SNS topid send')
    # pprint(snsresponse) ###################################################################
    pomsg = f'{worldboss.title()} is up in {zone.title()}!'
    pmmsg = f'{worldboss.title()} is up in {zone.title()}!\nType !alert remove to stop these alerts'
    for uid, udata in userdata.items():
        if uid != '0' and uid != '1' and uid != '2' and uid != '3':
            if udata['alert'] == '1':
                log.debug(f'Sending discord PM notification to [{uid}]')
                try:
                    duser = bot.get_user(int(uid))
                    await duser.send(pmmsg)
                except:
                    log.exception('Error in pm send')
                await sleep(.1)
            elif udata['alert'] == '2':
                log.debug(f'Sending pushover notification to [{uid}]')
                if BRANCH != 'develop':
                    try:
                        Client(udata['pushover_id']).send_message(pomsg, title="World Boss Alert")
                        await sleep(1)
                    except:
                        log.exception('Error in pushover send')
                else:
                    log.warning('Skipping actual pushover notifications due to DEV MODE')
    await logchan(user, channel, worldboss, zone)


async def logchan(user, chan, worldboss, zone, *args):
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


def getnextspawn(boss, getmax=False):
    bosstimes = SPAWN_TIMES[boss.title()]
    lastreset = int(userdata['3'])
    lasttime = userdata['2'][boss.title()]
    nextreset = int(userdata['3']) + 604800
    if lasttime is None:
        lasttime = lastreset
    else:
        lasttime = int(lasttime)
    if lastreset == lasttime:
        if getmax:
            spawnmin = bosstimes['resetmax']
        else:
            spawnmin = bosstimes['resetmin']
    else:
        if getmax:
            spawnmin = bosstimes['spawnmax']
        else:
            spawnmin = bosstimes['spawnmin']
    if (lasttime + spawnmin) < nextreset:
        return epochtopst(lasttime + spawnmin)
    else:
        return epochtopst(nextreset + bosstimes['resetmin'])


async def user_info(message):
    if type(message.channel) == discord.channel.DMChannel:
        for guild in bot.guilds:
            member = discord.utils.get(guild.members, id=message.author.id)
            if member:
                is_admin_role = False
                is_user_role = False
                admin_id = systemconfig.get("general", "admin_role_id")
                user_id = systemconfig.get("general", "user_role_id")
                user_id2 = systemconfig.get("general", "user_role_id2")
                for role in member.roles:
                    if str(role.id) == str(admin_id):
                        is_admin_role = True
                    if str(role.id) == str(user_id) or str(role.id) == str(user_id2):
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
        user_id2 = systemconfig.get("general", "user_role_id2")
        member = discord.utils.get(message.author.guild.members, id=message.author.id)
        for role in member.roles:
            if str(role.id) == str(admin_id):
                is_admin_role = True
            if str(role.id) == str(user_id) or str(role.id) == str(user_id2):
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
    log.log("REQUEST", f"Request [{message.content}] from [{message.author}] in [#{dchan}]")


async def fake_typing(message):
    await message.channel.trigger_typing()


def error_embed(message):
    return discord.Embed(description="Resource unavailable, please try again later.", color=FAIL_COLOR)


async def bad_command(message, user, *args):
    msg = f'`{message.content}` is not a valid command.\nTry `{prefix}alert help` for a list of commands'
    embed = discord.Embed(description=msg, color=FAIL_COLOR)
    await messagesend(message, embed, user)


async def messagesend(message, embed, user, pm=False, noembed=False):
    try:
        if type(message.channel) == discord.channel.DMChannel or pm:
            if noembed:
                return await message.author.send(embed)
            else:
                return await message.author.send(embed=embed)
        elif type(message.channel) != discord.channel.DMChannel and pm:
            await message.delete()
            if noembed:
                return await message.author.send(embed)
            else:
                return await message.author.send(embed=embed)
        else:
            if noembed:
                return await message.channel.send(embed)
            else:
                return await message.channel.send(embed=embed)
    except:
        log.exception("Critical error in message send")


@bot.event
async def on_raw_reaction_add(ctx):
    if ctx.user_id != bot.user.id:
        chan = bot.get_channel(ctx.channel_id)
        if ctx.user_id in running_addme:
            if ctx.message_id == running_addme[ctx.user_id]['message'].id:
                if ctx.emoji.name == E_NO:
                    embed = discord.Embed(title='No changes have been made', color=FAIL_COLOR)
                    await chan.send(embed=embed)
                    del running_addme[ctx.user_id]
                if running_addme[ctx.user_id]['step'] == 1:
                    if ctx.emoji.name == E_YES:
                        await addme2(ctx.user_id, chan)
                elif running_addme[ctx.user_id]['step'] == 2:
                    if ctx.emoji.name == E_NUM[1]:
                        userdata[str(ctx.user_id)] = {'alert': '1', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
                        await addmefinish(ctx.user_id, chan)
                    elif ctx.emoji.name == E_NUM[2]:
                        userdata[str(ctx.user_id)] = {'alert': '2', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
                        await addme3(ctx.user_id, chan)
                    elif ctx.emoji.name == E_NUM[3]:
                        userdata[str(ctx.user_id)] = {'alert': '3', 'number': 'None', 'pushover_id': 'None', 'subarn': 'None'}
                        await addme3(ctx.user_id, chan)
        if ctx.user_id in running_removeme:
            if ctx.message_id == running_removeme[ctx.user_id]['message'].id:
                if ctx.emoji.name == E_NO:
                    embed = discord.Embed(title='No changes have been made', color=FAIL_COLOR)
                    await chan.send(embed=embed)
                    del running_removeme[ctx.user_id]
                elif ctx.emoji.name == E_NUM[1]:
                    del running_removeme[ctx.user_id]
                    if userdata[str(ctx.user_id)]['alert'] == '3':
                        userunsub(str(ctx.user_id))
                    del userdata[str(ctx.user_id)]
                    saveuserdata()
                    title = f'You have been removed from receiving any alerts'
                    msg = f'Type `{prefix}alert addme` in the future to setup alerts again'
                    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
                    await chan.send(embed=embed)
                elif ctx.emoji.name == E_NUM[2]:
                    await addme2(ctx.user_id, chan)
        if len(running_alert) > 0:
            for key, each in running_alert.copy().items():
                if ctx.message_id == each['message'].id:
                    if ctx.emoji.name == E_NO:
                        pprint(ctx)
                        if ctx.guild_id is not None:
                            await running_alert[key]['message'].delete()
                        embed = discord.Embed(title='Alert cancelled', color=FAIL_COLOR)
                        await chan.send(embed=embed)
                        running_alert.clear()
                    elif ctx.emoji.name == E_YES:
                        if ctx.guild_id is not None:
                            await running_alert[key]['message'].delete()
                        await sendit(ctx.user_id, chan)
                    elif ctx.emoji.name == E_NUM[1]:
                        running_alert[key]['zone'] = DRAGON_ZONES[1]
                        if ctx.guild_id is not None:
                            await running_alert[key]['message'].delete()
                        await alertfinalize(ctx.user_id, chan)
                    elif ctx.emoji.name == E_NUM[2]:
                        running_alert[key]['zone'] = DRAGON_ZONES[2]
                        if ctx.guild_id is not None:
                            await running_alert[key]['message'].delete()
                        await alertfinalize(ctx.user_id, chan)
                    elif ctx.emoji.id == E_NUM[3]:
                        running_alert[key]['zone'] = DRAGON_ZONES[3]
                        if ctx.guild_name is not None:
                            await running_alert[key]['message'].delete()
                        await alertfinalize(ctx.user_id, chan)
                    elif ctx.emoji.id == E_NUM[4]:
                        running_alert[key]['zone'] = DRAGON_ZONES[4]
                        if ctx.guild_name is not None:
                            await running_alert[key]['message'].delete()
                        await alertfinalize(ctx.user_id, chan)


@bot.event
async def on_ready():
        log.log("SUCCESS", f"Discord logged in as [{bot.user.name}] id [{bot.user.id}]")
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
        elif user['is_user'] or user['is_admin']:
            args = message.content[1:].split(' ')
            if type(message.channel) == discord.channel.DMChannel:
                if user['user_id'] in running_addme:
                    if running_addme[user['user_id']]['step'] == 3:
                        await addme_r3(message, user['user_id'], message.channel)
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
                    elif args[0] == 'killed' or args[0] == 'kill':
                        await killed(message, user, *args)
                    elif args[0] == 'timer' or args[0] == 'timers' or args[0] == 'scout':
                        await timers(message, user, *args)
                    elif args[0] == 'test' and user['is_superadmin']:
                        await test(message, user, *args)
                    elif args[0] == 'forceremove' and user['is_superadmin']:
                        await forceremove(message, user, *args)
                    else:
                        await alert(message, user, *args)
            elif message.content.lower().startswith(f'{prefix}kill'):
                args.pop(0)
                await killed(message, user, *args)
            elif message.content.lower().startswith(f'{prefix}time') or message.content.lower().startswith(f'{prefix}scout'):
                args.pop(0)
                await timers(message, user, *args)


async def killed(message, user, *args):
    logcommand(message, user)
    if len(args) > 0:
        boss = fuzzybosslookup(args[0])
        if boss is not None:
            if len(args) == 1:
                downtime = int(datetime.now().timestamp())
            elif len(args) == 2:
                downtime = killtime(args[1])
            elif len(args) == 3:
                arg = f'{args[1]}{args[2]}'
                downtime = killtime(arg)
            else:
                msg = f'Too many arguments. example: `{prefix}killed <bossname> 9:35PM`'
                await messagesend(message, msg, user, noembed=True)
                return None
            if downtime is not None:
                log.info(f'{boss} kill time updated to {epochtopst(downtime,fmt="string")}')
                ud = userdata['2']
                ud[boss] = downtime
                saveuserdata()
                ns = downtime + SPAWN_TIMES[boss]['spawnmin']
                msg = f'{boss} kill recorded: {epochtopst(downtime,fmt="string")} Server Time\nNext spawn window starts at {epochtopst(ns,fmt="string")}'
                await messagesend(message, msg, user, noembed=True)
            else:
                msg = f'Cannot determine the time entered. example: `{prefix}killed <bossname> 9:35PM`'
                await messagesend(message, msg, user, noembed=True)
                return None
        else:
            msg = f'World boss name incorrect. example: `{prefix}killed <bossname> 9:35PM`'
            await messagesend(message, msg, user, noembed=True)
            return None
    else:
            msg = f'Must supply World Boss name. example: `{prefix}killed <bossname> 9:35PM`'
            await messagesend(message, msg, user, noembed=True)
            return None


async def timers(message, user, *args):
    logcommand(message, user)
    now = int(datetime.now().timestamp())
    title = 'World Boss spawn estimates'
    embed = discord.Embed(title=title, color=INFO_COLOR)
    for boss in SPAWN_TIMES:
        nexttime = int(getnextspawn(boss).timestamp())
        nextlongtime = int(getnextspawn(boss, getmax=True).timestamp())
        if nexttime < now:
            msg = f'Spawn window started {elapsedTime(now, nexttime, granularity=3)} ago\n'
            msg = msg + f'Last possible spawn in {elapsedTime(now, nextlongtime, granularity=3)}'
            embed.add_field(name=f'{boss} in spawn window now', value=msg, inline=False)
        else:
            msg = f'Next earliest spawn in {elapsedTime(now, nexttime, granularity=3)}\non {epochtopst(nexttime, fmt="string")} Server Time'
            embed.add_field(name=f'{boss} waiting for spawn window to open', value=msg, inline=False)
    embed.set_footer(text=f'Last server reset recorded {epochtopst(int(userdata["3"]), fmt="string")}')
    await messagesend(message, embed, user, *args)


async def alert(message, user, *args):
    logcommand(message, user)
    nuid = user['user_id']
    if nuid not in running_alert:
        now = int(datetime.now().timestamp())
        expiretime = int(userdata['0']) + int(throttle_min) * 60
        if expiretime > now:
            log.info(f"Failed alert trigger [{int((expiretime - now)/60)} min] left still {user['user_name']} from {user['guild_name']}")
            title = f'You must wait {int((expiretime - now)/60)} min before sending another alert'
            msg = f'Last World Boss alert was {userdata["1"]["boss"]} in {userdata["1"]["zone"]}\n{convert_time(userdata["0"], tz="US/Pacific")} Server time, {elapsedTime(int(datetime.now().timestamp()), int(userdata["0"]))} ago'
            embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
        elif len(running_alert) > 0:
            log.info(f"Failed alert trigger alert already running for {user['user_name']} from {user['guild_name']}")
            title = f'Someone else is running an alert now, please wait 30 seconds'
            embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
        else:
            user['step'] = 1
            user['timer'] = int(datetime.now().timestamp())
            running_alert[nuid] = user
            await alert1(message, user, *args)


async def alert1(message, user, *args):
    nuid = user['user_id']
    if nuid in running_alert:
        boss = fuzzybosslookup(args[0])
        if boss is None:
            del running_alert[nuid]
            title = f'World Boss {args[0].title()} does not exist'
            msg = f'Valid options are:\n'
            for wboss in WORLD_BOSSES:
                msg = msg + f'**{wboss}**\n'
            embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, pm=False)
        else:
            log.log("TRIGGER", f"Starting ALERT TRIGGER for [{user['user_name']}] from [{user['guild_name']}]")
            running_alert[nuid]['boss'] = boss.title()
            if WORLD_BOSSES[boss] is None:
                running_alert[nuid] = user
                await alert2(message, user, *args)
            else:
                running_alert[nuid]['zone'] = WORLD_BOSSES[boss]
                await alertfinalize(nuid, message.channel)


async def alert2(message, user, *args):
    if user['user_id'] in running_alert:
        running_alert[user['user_id']]['step'] = 2
        title = f'Select which zone {running_alert[user["user_id"]]["boss"]} is in:'
        msg = ''
        for num, zone in DRAGON_ZONES.items():
            msg = msg + f'{E_NUM[num]} {zone.title()}\n'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        moji = await messagesend(message, embed, user, pm=False)
        running_alert[user['user_id']]['message'] = moji
        for num in DRAGON_ZONES:
            await moji.add_reaction(E_NUM[num])


async def alertfinalize(user, channel):
    title = f'You are about send a World Boss Alert!'
    msg = f'**{running_alert[user]["boss"].title()}** in **{running_alert[user]["zone"].title()}**\nEveryone subscribed will get an alert to log on now!\nAre you sure you want to do this?\n\n{E_YES} Yes, Send it!\n{E_NO} No, Cancel alert'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    moji = await channel.send(embed=embed)
    running_alert[user]['message'] = moji
    await moji.add_reaction(E_YES)
    await moji.add_reaction(E_NO)


async def sendit(user, channel):
    await pubmsg(user, channel, running_alert[user]['boss'], running_alert[user]['zone'])


async def addme(message, user, *args):
    logcommand(message, user)
    uid = str(user['user_id'])
    if user['user_id'] not in running_addme:
        user['timer'] = int(datetime.now().timestamp())
        log.info(f"Starting Addme for [{user['user_name']}] from [{user['guild_name']}]")
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
            msg = f'{E_YES} Yes\n{E_NO} No'
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            moji = await messagesend(message, embed, user, pm=True)
            running_addme[user['user_id']]['message'] = moji
            await moji.add_reaction(E_YES)
            await moji.add_reaction(E_NO)
        else:
            await addme2(user['user_id'], message.channel)


async def addme2(user, channel):
    if user not in running_addme:
        log.trace('missing running_addme user, using running_removeme user')
        running_addme[user] = running_removeme[user]
        del running_removeme[user]
    running_addme[user]['step'] = 2
    title = 'Welcome to the World Boss Broadcast System!\nChoose how you would like to be notified of World Boss alerts:'
    msg = f'{E_NUM[1]}  Discord Private Message (Can show as a notification with the mobile discord app)\n{E_NUM[2]}  Pushover Notification (Free mobile push notification service [Link](https://pushover.net/))\n{E_NUM[3]}  Text Message to cell phone\n{E_NO}  Cancel changes'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    moji = await channel.send(embed=embed)
    running_addme[user]['message'] = moji
    await moji.add_reaction(E_NUM[1])
    await moji.add_reaction(E_NUM[2])
    await moji.add_reaction(E_NUM[3])
    await moji.add_reaction(E_NO)


async def addme3(user, channel):
    running_addme[user]['step'] = 3
    if userdata[str(user)]['alert'] == '3':
        title = 'Please enter the cell phone number you would like texts sent to'
        msg = 'Area code and number with no spaces or special characters\nExample: 5551214480'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        embed.set_footer(text='Type your phone number below or cancel to cancel setup')
    elif userdata[str(user)]['alert'] == '2':
        title = 'Please paste your pushover user key'
        msg = 'You sign up for a free account [here](https://pushover.net/signup) to get a user key'
        embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
        embed.set_footer(text='Paste your pushover user key below or canel to cancel setup')
    await channel.send(embed=embed)


async def addme_r3(message, user, channel):
    resp = message.content
    uid = str(user)
    if userdata[uid]['alert'] == '3':
        if len(resp) == 11 and resp.isnumeric():
            if resp[0] == '1':
                resp = resp[1:]
        if len(resp) != 10 or not resp.isnumeric():
            log.warning(f"Invalid answer to start setup again [{message.content}]")
            msg = 'Invalid number. Enter area code and number, no spaces, no special characters: 5551214480'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await channel.send(embed=embed)
            await addme3(user, channel)
        else:
            respo = usersub(f'+1{resp}')
            userdata[uid]['alert'] = '3'
            userdata[uid]['number'] = f'+1{resp}'
            userdata[uid]['pushover_id'] = 'None'
            userdata[uid]['subarn'] = respo
            await addmefinish(user, channel)
    elif userdata[uid]['alert'] == '2':
        if len(resp) < 20:
            log.warning(f"Invalid answer to start setup again [{message.content}]")
            msg = "Invalid pushover user key.\nPaste the 'Your User Key' in the top right of your pushover account page"
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await channel.send(embed=embed)
            await addme3(user, channel)
        else:
            userdata[uid]['alert'] = '2'
            userdata[uid]['number'] = 'None'
            userdata[uid]['pushover_id'] = resp
            await addmefinish(user, channel)


async def addmefinish(user, channel):
    if userdata[str(user)]['alert'] == '2':
        atype = "Pushover notification"
    elif userdata[str(user)]['alert'] == '3':
        atype = "Text Message"
        usersub(userdata[str(user)]['number'])
    elif userdata[str(user)]['alert'] == '1':
        atype = "Discord PM"
    saveuserdata()
    title = 'Alert setup complete!'
    msg = f'You will now receive a {atype} when someone triggers a World Boss alert.\nType `{prefix}alert addme` to change your notification type\nType `{prefix}alert removeme` to remove yourself from notifications.'
    embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
    log.info(f"Completed Addme for [{running_addme[user]['user_name']}] from [{running_addme[user]['guild_name']}]")
    del running_addme[user]
    await channel.send(embed=embed)


async def removeme(message, user, *args):
    logcommand(message, user)
    uid = str(user['user_id'])
    if user['user_id'] not in running_removeme:
        user['timer'] = int(datetime.now().timestamp())
        log.info(f"Starting removeme for [{user['user_name']}] from [{user['guild_name']}]")
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
            msg = f"{E_NUM[1]}  Remove yourself from getting alerts\n{E_NUM[2]} Change how you get alerts\n{E_NO}: Don't change anything"
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            moji = await messagesend(message, embed, user, pm=True)
            running_removeme[user['user_id']]['message'] = moji
            await moji.add_reaction(E_NUM[1])
            await moji.add_reaction(E_NUM[2])
            await moji.add_reaction(E_NO)
        else:
            title = f"You are not setup to receive any alerts"
            msg = f'Type `{prefix}alert addme` to be notified of World Boss alerts'
            embed = discord.Embed(title=title, description=msg, color=INFO_COLOR)
            del running_removeme[user['user_id']]
            await messagesend(message, embed, user, pm=True)


async def total(message, user, *args):
    title = f'There are {len(userdata)-4} players setup for World Boss alerts'
    discordcount = 0
    pushovercount = 0
    textcount = 0
    for each, udata in userdata.items():
        if each != '0' and each != '1' and each != '2' and each != '3':
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
    embed.add_field(name=f"**`{prefix}alert total`**", value=f"Total players registered for World Boss alerts", inline=False)
    embed.add_field(name=f"**`{prefix}timers`** or **`{prefix}scout`**", value=f"Estimated spawn times for each World Boss", inline=False)
    embed.add_field(name=f"**`{prefix}killed <bossname> <time>`**", value=f"Update World Boss killed time", inline=False)
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
    # log.success(userdata)
    log.info(user)
    log.success(f'{len(running_addme)} {running_addme}')
    log.info(f'{len(running_removeme)} {running_removeme}')
    log.success(f'{len(running_alert)} {running_alert}')
    #log.info(f'{userdata["2"]}')
    #title = f'Pick some shit :one:'
    #embed = discord.Embed(title=title, color=INFO_COLOR)
    #embed.add_field(name='entry :two:', value='value :three:')

    #moji = await messagesend(message, embed, user, pm=True)

    #await moji.add_reaction(E_YES)
    #await moji.add_reaction(E_NO)

    # blizcli = BlizzardAPI(bliz_int_client, bliz_int_secret, .get("server", "server_region"))
    # await blizcli.authorize()
    # pprint(await blizcli.realm_list())


def main():
        uvloop.install()
        bot.run(discordkey)


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
