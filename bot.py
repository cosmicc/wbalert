#!/usr/bin/env python3.8
import signal
from configparser import ConfigParser
from os import _exit, path, stat
from pathlib import Path
from sys import argv, exit, stdout
import discord
from discord.ext import commands
from fuzzywuzzy import fuzz
from loguru import logger as log
from prettyprinter import pprint
import uvloop
from processlock import PLock
import boto3
import msgpack


WORLD_BOSSES = {'Azuregos': 'Azhara', 'Lord Kazzak': "Blasted Lands", "Ysondre": '', 'Emeriss': '', 'Taerar': '', 'Lethon': ''}
DRAGON_ZONES = ['Ashenvale', 'Feralas', 'Hinterlands', 'Duskwood']


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
guildconfig = ConfigParser()
guildconfig.read(configfile)

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
discordkey = systemconfig.get("discord", "api_key")
discordkey_dev = systemconfig.get("discord", "dev_key")
superadmin_id = systemconfig.get("discord", "superadmin_id")
prefix = systemconfig.get("discord", "command_prefix")
aws_key = systemconfig.get("general", "aws_key")
aws_secret = systemconfig.get("general", "aws_secret")
topic_arn = systemconfig.get("general", "topic_arn")
userdatafile = systemconfig.get("general", "userdata_file")

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
    ll = "INFO"

log.add(sink=str(logfile), level=ll, buffering=1, enqueue=True, backtrace=True, format=logformat, diagnose=True, serialize=False, delay=False, colorize=False, rotation="5 MB", retention="1 month", compression="tar.gz")

log.debug(f'System configuration loaded successfully from {configfile}')
log.debug(f'Logfile started: {logfile}')

if BRANCH == 'develop':
    log.warning(f'World Boss Broadcasting System is starting in DEV MODE!')
else:
    log.info(f'World Boss Broadcasting System is starting in PRODUCTION MODE!')

bot = commands.Bot(command_prefix="!", case_insensitive=True)
bot.remove_command("help")
log.debug('Discord class initalized')

sns = boto3.client("sns", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, region_name='us-east-1')
log.debug('AWS SNS client initalized')

running_addme = {}
running_alert = {}

# data = {'329658352969973760': {'alert': 2, 'number': '5864808574'}}
# msgpack.dump(data, open(userdatafile, 'wb'))
userdata = msgpack.load(open(userdatafile, 'rb'))
log.info(f'Userdata loaded from {userdata_file}')

optedout_list = sns.ListNumbersOptedOut()


def saveuserdata():
    msgpack.dump(userdata, open(userdatafile, 'wb'))


def is_registered(uid):
    if uid in userdata:
        return True
    else:
        return False


def usersub(uid, alerttype, number):
    if not is_registered(uid):
        if alerttype == 2:
            if number in sns.ListPhoneNumbersOptedOut():
                sns.opt_in_phone_number(number)
            subarn = sns.subscribe(TopicArn=topic_arn, Protocol='sms', Endpoint=number, ReturnSubscriptionArn=True)
            userdata[uid] = {'alert': alerttype, 'number': f'+1{number}', 'subarn': subarn}
            saveuserdata()
            return True
        elif alerttype == 1:
            userdata[uid] = {'alert': alerttype, 'number': 'None', 'subarn': 'None'}
            saveuserdata()
            return True
    else:
        return False


def userunsub(uid):
    if is_registered(uid):
        if userdata[uid]['alert'] == 2:
            sns.unsubscribe(SubscriptionArn=userdata[uid]['subarn'])
        del userdata[uid]
        saveuserdata()
        return True
    else:
        return False


async def checkoptouts():
    for opt in sns.ListPhoneNumbersOptedOut():
        for user, udata in userdata.items():
            if opt == udata['number']:
                log.info(f'Opted out number found [{udata["number"]}], removing user subsciption')
                del userdata[user]
    await sleep(60 * 60)


def pubmsg(worldboss, zone):
    msg = "Log in now if you can"
    embed = discord.Embed(title=f"{worldboss.title()} is UP in {zone.title()}!", description=msg, color=SUCCESS_COLOR)
    embed.set_footer(name='World Boss Broadcasting System\nType !wba to sign up for World Boss alerts.')
    message = f'{worldboss.title()} is up in {zone.title()}!\nLog in now if you can.\n\nReply STOP to end these notifications permenantly'
    snsresponse = sns.publish(TopicArn=topic_arn, Message=message)
    for uid, udata in userdata.items():
        if udata['alert'] == 1:
            pass
            # Send Discord PM
    return snsresponse


async def user_info(message):
    if type(message.channel) == discord.channel.DMChannel:
        for guild in bot.guilds:
            member = discord.utils.get(guild.members, id=message.author.id)
            if member:
                is_admin_role = False
                is_user_role = False
                admin_id = guildconfig.get("discord", "admin_role_id")
                user_id = guildconfig.get("discord", "user_role_id")
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
        admin_id = guildconfig.get("discord", "admin_role_id")
        user_id = guildconfig.get("discord", "user_role_id")
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
    log.log("INFO", f"Request [{message.content}] from [{message.author}] in [#{dchan}] from [{user['guild_name']}]")


async def fake_typing(message):
    await message.channel.trigger_typing()


def error_embed(message):
    return discord.Embed(description="Resource unavailable, please try again later.", color=FAIL_COLOR)


async def bad_command(message, user, guildconfig, *args):
    pref = guildconfig.get("discord", "command_prefix")
    strargs = ''
    for each in args:
        strargs = strargs + f"{each} "
    if len(args) == 1:
        msg = f'`{message.content}` is not a valid command.\nMaybe you mean `{pref}player {strargs}` or `{pref}item {strargs}`\nOr try `{pref}help for a list of commands`'
    else:
        msg = f'`{message.content}` is not a valid command.\nMaybe you mean `{pref}item {strargs}`\nOr try `{pref}help` for a list of commands'
    embed = discord.Embed(description=msg, color=FAIL_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def messagesend(message, embed, user, guildconfig, respo=None):
    try:
        if respo is not None:
            await respo.delete()
        if type(message.channel) == discord.channel.DMChannel:
            return await message.author.send(embed=embed)
        elif guildconfig.get('discord', 'pm_only') == "True" or (guildconfig.get('discord', 'limit_to_channel') != "Any" and str(message.channel.id) != guildconfig.get('discord', 'limit_to_channel_id')):
            await message.delete()
            return await message.author.send(embed=embed)
        else:
            return await message.channel.send(embed=embed)
    except:
        log.exception("Critical error in message send")


@bot.event
async def on_ready():
        log.log("SUCCESS", f"Discord logged in as {bot.user.name} id {bot.user.id}")
        activity = discord.Activity(type=discord.ActivityType.listening, name="!wba")
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
                await fake_typing(message)
                if message.content.lower() == 'cancel':
                    title = 'Cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    del running_setup[user['user_id']]
                    await messagesend(message, embed, user)
                elif running_addme[user['user_id']]['step'] == 1:
                    await response1(message, user)
                elif running_addme[user['user_id']]['step'] == 2:
                    await response2(message, user)
                elif running_addme[user['user_id']]['step'] == 3:
                    await response3(message, user)
            if user['user_id'] in running_alert:
                await fake_typing(message)
                if message.content.lower() == 'cancel':
                    title = 'Alert cancelled'
                    embed = discord.Embed(title=title, color=FAIL_COLOR)
                    del running_alert[user['user_id']]
                    await messagesend(message, embed, user)
                elif running_alert[user['user_id']]['step'] == 1:
                    await response1(message, user)
                elif running_alert[user['user_id']]['step'] == 2:
                    await response2(message, user)
                elif running_alert[user['user_id']]['step'] == 3:
                    await response3(message, user)
            else:
                if message.content.startswith(prefix):
                    if user['is_user'] or user['is_admin']:
                        await fake_typing(message)
                        args = message.content[1:].split(' ')
                        ccmd = args[0].lower()
                        if ccmd in ['alert']:
                            args.pop(0)
                            await alertstart(message, user, *args)
                        elif ccmd in ["addme", "alertme"]:
                            args.pop(0)
                            await adduser(message, user, *args)
                        elif ccmd in ["help", "commands", "helpme"]:
                            args.pop(0)
                            await help(message, user, *args)
                        elif ccmd in ["test"] and user['is_admin']:
                            args.pop(0)
                            await test(message, user, *args)
                        else:
                            await bad_command(message, user, *args)
                else:
                    if type(message.channel) == discord.channel.DMChannel:
                        await fake_typing(message)
                        await help(message, user)


    
async def setup(message, user, guildconfig, *args):
    logcommand(message, user)
    if user['user_id'] not in running_setup:
        log.info(f"Starting Setup for {user['user_name']} from {user['guild_name']}")
        user['setupstep'] = 1
        running_setup[user['user_id']] = user
        if guildconfig.get("discord", "setupran") == "True":
            title = f'Setup has already been ran for server: {user["guild_name"]}\nWould you like to run it again?'
            msg = f'**1**: Yes\n**2**: No'
            embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
            await messagesend(message, embed, user, guildconfig)
        else:
            title = f"Welcome to the WowInfoClassic setup wizard for server: {user['guild_name']}"
            msg = "Type cancel at any time to cancel setup"
            embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup2(message, user, guildconfig, *args)


async def response1(message, user, guildconfig, *args):
    resp = message.content
    if resp != '1' and resp != '2':
        log.warning(f"Invalid answer to start setup again [{message.content}]")
        msg = 'Invalid response.  Select 1 or 2'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup(message, user, guildconfig, *args)
    elif resp == '1':
        await setup2(message, user, guildconfig, *args)
    elif resp == '2':
        title = f'Setup wizard has been cancelled for server: {user["guild_name"]}'
        msg = f'Type {guildconfig.get("discord", "command_prefix")}setup in the future to run the setup wizard again'
        embed = discord.Embed(title=title, description=msg, color=FAIL_COLOR)
        del running_setup[user['user_id']]
        await messagesend(message, embed, user, guildconfig)


async def setup2(message, user, guildconfig, *args):
    user['setupstep'] = 2
    running_setup[user['user_id']] = user
    title = 'Select your World of Warcraft Classic server region:'
    msg = '**1**: US\n**2**: EU'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response2(message, user, guildconfig, *args):
    resp = message.content
    if resp != '1' and resp != '2':
        msg = 'Invalid selection. Please answer 1 or 2'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup2(message, user, guildconfig, *args)
    else:
        if resp == '1':
            guildconfig.set('server', 'server_region', 'US')
        elif resp == '2':
            guildconfig.set('server', 'server_region', 'EU')
        await guildconfig.write()
        await setup3(message, user, guildconfig, *args)


async def setup3(message, user, guildconfig, *args):
    user['setupstep'] = 3
    running_setup[user['user_id']] = user
    title = 'Select your World of Warcraft Classic server:'
    blizcli = BlizzardAPI(bliz_int_client, bliz_int_secret, guildconfig.get("server", "server_region"))
    await blizcli.authorize()
    realms = await blizcli.realm_list()
    await blizcli.close()
    num = 1
    slist = {}
    for realm in realms['realms']:
        if not realm['name']['en_US'].startswith('US') and not realm['name']['en_US'].startswith('EU'):
            slist[num] = {'name': realm['name']['en_US'], 'slug': realm['slug'], 'id': realm['id']}
            num = num + 1
    msg = ''
    user['serverlist'] = sorted(slist.items())
    running_setup[user['user_id']] = user
    for sname, sval in sorted(slist.items()):
        msg = msg + f'**{sname}**: {sval["name"]}\n'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response3(message, user, guildconfig, *args):
    resp = message.content
    try:
        int(resp)
    except:
        msg = 'Invalid server selection'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup3(message, user, guildconfig, *args)
    else:
        setup_user = running_setup[user['user_id']]
        slist = setup_user['serverlist']
        if (int(resp) - 1) > len(slist) or (int(resp) - 1) < 1:
            msg = 'Invalid server selection'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup3(message, user, guildconfig, *args)
        else:
            svr = slist[int(resp) - 1][1]
            blizcli = BlizzardAPI(bliz_int_client, bliz_int_secret, guildconfig.get("server", "server_region"))
            await blizcli.authorize()
            svr_info = await blizcli.realm_info(svr['slug'])
            await blizcli.close()
            guildconfig.set('server', 'server_name', svr_info['name']['en_US'])
            guildconfig.set('server', 'server_timezone', svr_info['timezone'])
            guildconfig.set('server', 'server_id', svr_info['id'])
            guildconfig.set('server', 'server_region_name', svr_info['region']['name']['en_US'])
            guildconfig.set('server', 'server_region_id', svr_info['region']['id'])
            guildconfig.set('server', 'server_locale', svr_info['locale'])
            guildconfig.set('server', 'server_type', svr_info['type']['type'])
            guildconfig.set('server', 'server_category', svr_info['category']['en_US'])
            guildconfig.set('server', 'server_slug', svr_info['slug'])
            await guildconfig.write()
            await setup4(message, user, guildconfig, *args)


async def setup4(message, user, guildconfig, *args):
    user['setupstep'] = 4
    running_setup[user['user_id']] = user
    title = 'Select your World of Warcraft Classic faction:'
    msg = '**1**: Alliance\n**2**: Horde'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response4(message, user, guildconfig, *args):
    resp = message.content
    if resp != '1' and resp != '2':
        msg = 'Invalid selection.  Please answer 1 or 2'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup2(message, user, guildconfig, *args)
    else:
        if resp == '1':
            guildconfig.set('server', 'faction', 'Alliance')
        elif resp == '2':
            guildconfig.set('server', 'faction', 'Horde')
        await guildconfig.write()
        await setup5(message, user, guildconfig, *args)


async def setup5(message, user, guildconfig, *args):
    user['setupstep'] = 5
    running_setup[user['user_id']] = user
    title = "Please enter your World of Warcraft Classic Guild's name:"
    embed = discord.Embed(title=title, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response5(message, user, guildconfig, *args):
    resp = message.content.title()
    guildconfig.set('server', 'guild_name', resp)
    await guildconfig.write()
    await setup6(message, user, guildconfig, *args)


async def setup6(message, user, guildconfig, *args):
    user['setupstep'] = 6
    running_setup[user['user_id']] = user
    msg = ''
    title = "Select which discord role is allowed to change bot settings (admin):"
    rguild = None
    for guild in bot.guilds:
        member = discord.utils.get(guild.members, id=message.author.id)
        if member:
            rguild = guild
            break
    num = 1
    roles = {}
    for role in rguild.roles:
        if role.name != '@everyone':
            roles[num] = role
            msg = msg + f'**{num}**: {role.name}\n'
            num = num + 1
    user['roles'] = roles
    running_setup[user['user_id']] = user
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response6(message, user, guildconfig, *args):
    resp = message.content
    try:
        int(resp)
    except:
        msg = 'Invalid role selection'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup6(message, user, guildconfig, *args)
    else:
        if int(resp) > (len(running_setup[user['user_id']]['roles'])) or int(resp) < 1:
            msg = 'Invalid role selection'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup6(message, user, guildconfig, *args)
        else:
            srole = running_setup[user['user_id']]['roles'][int(resp)]
            guildconfig.set('discord', 'admin_role_id', srole.id)
            guildconfig.set('discord', 'admin_role', srole.name)
            await guildconfig.write()
            await setup7(message, user, guildconfig, *args)


async def setup7(message, user, guildconfig, *args):
    user['setupstep'] = 7
    running_setup[user['user_id']] = user
    msg = ''
    title = "Select which discord role that should be allowed to use bot commands:"
    rguild = None
    for guild in bot.guilds:
        member = discord.utils.get(guild.members, id=message.author.id)
        if member:
            rguild = guild
            break
    num = 1
    roles = {}
    for role in rguild.roles:
        roles[num] = role
        msg = msg + f'**{num}**: {role.name}\n'
        num = num + 1
    user['roles'] = roles
    running_setup[user['user_id']] = user
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response7(message, user, guildconfig, *args):
    resp = message.content
    try:
        int(resp)
    except:
        msg = 'Invalid role selection'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup7(message, user, guildconfig, *args)
    else:
        if int(resp) > (len(running_setup[user['user_id']]['roles'])) or int(resp) < 1:
            msg = 'Invalid role selection'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup7(message, user, guildconfig, *args)
        else:
            srole = running_setup[user['user_id']]['roles'][int(resp)]
            guildconfig.set('discord', 'user_role_id', srole.id)
            guildconfig.set('discord', 'user_role', srole.name)
            await guildconfig.write()
            await setup8(message, user, guildconfig, *args)


async def setup8(message, user, guildconfig, *args):
    user['setupstep'] = 8
    running_setup[user['user_id']] = user
    title = 'Select where the bot should respond:'
    msg = '**1**: Private Message Only (No Channels)\n**2**: Private Message & 1 Specific Channel Only\n**3**: Private Message & Any Channel'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response8(message, user, guildconfig, *args):
    resp = message.content
    if resp != '1' and resp != '2' and resp != '3':
        msg = 'Invalid selection.  Please answer 1, 2, or 3'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup8(message, user, guildconfig, *args)
    else:
        if resp == '1':
            guildconfig.set('discord', 'pm_only', 'True')
            guildconfig.set('discord', 'limit_to_channel', 'None')
            await guildconfig.write()
            await setup10(message, user, guildconfig, *args)
        elif resp == '2':
            guildconfig.set('discord', 'pm_only', 'False')
            await guildconfig.write()
            await setup9(message, user, guildconfig, *args)
        elif resp == '3':
            guildconfig.set('discord', 'pm_only', 'False')
            guildconfig.set('discord', 'limit_to_channel', 'Any')
            await guildconfig.write()
            await setup10(message, user, guildconfig, *args)


async def setup9(message, user, guildconfig, *args):
    user['setupstep'] = 9
    running_setup[user['user_id']] = user
    msg = ''
    num = 1
    channels = {}
    title = 'Select which channel to limit the bot to:'
    for guild in bot.guilds:
        member = discord.utils.get(guild.members, id=message.author.id)
        if member:
            for channel in guild.text_channels:
                channels[num] = channel
                msg = msg + f'**{num}**: {channel}\n'
                num = num + 1
    user['channels'] = channels
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response9(message, user, guildconfig, *args):
    resp = message.content
    try:
        int(resp)
    except:
        msg = 'Invalid channel selection'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup9(message, user, guildconfig, *args)
    else:
        if int(resp) > (len(running_setup[user['user_id']]['channels'])) or int(resp) < 1:
            msg = 'Invalid channel selection'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup9(message, user, guildconfig, *args)
        else:
            chan = running_setup[user['user_id']]['channels'][int(resp)]
            guildconfig.set('discord', 'limit_to_channel_id', chan.id)
            guildconfig.set('discord', 'limit_to_channel', chan.name)
            await guildconfig.write()
            await setup10(message, user, guildconfig, *args)


async def setup10(message, user, guildconfig, *args):
    user['setupstep'] = 10
    running_setup[user['user_id']] = user
    title = 'Paste your Warcraft Logs API Key:'
    msg = ''
    if guildconfig.get("warcraftlogs", "api_key") != "None":
        msg = 'Type "keep" to keep your existing API key\n\n'
    msg = msg + 'If you do not have a Warcraft Logs API key, get one from here:\n[Warcraft Logs User Profile](https://classic.warcraftlogs.com/profile)\nBottom of the page under Web API, you must hava a valid free Warcraft Logs account.'
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response10(message, user, guildconfig, *args):
    if guildconfig.get("warcraftlogs", "api_key") != "None" and message.content.lower() == "keep":
        await setup11(message, user, guildconfig, *args)
    else:
        if len(message.content.lower()) != 32:
            msg = "That does not appear to be a valid API key"
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup10(message, user, guildconfig, *args)
        else:
            guildconfig.set('warcraftlogs', 'api_key', message.content)
            await guildconfig.write()
            await setup11(message, user, guildconfig, *args)


async def setup11(message, user, guildconfig, *args):
    user['setupstep'] = 11
    running_setup[user['user_id']] = user
    title = 'Paste your Blizzard API Client ID:'
    msg = ''
    if guildconfig.get("blizzard", "client_id") != "None":
        msg = 'Type "keep" to keep your existing client id\n\n'
    msg = msg + """If you do not have a Blizzard API client created, create one here:\n[Blizzard API Clients](https://develop.battle.net/access/clients)\nClick "Create Client", Then fill out the info (entries don't matter), to get a Blizzard Client ID & Secret"""
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response11(message, user, guildconfig, *args):
    if guildconfig.get("blizzard", "client_id") != "None" and message.content.lower() == "keep":
        await setup12(message, user, guildconfig, *args)
    else:
        if len(message.content.lower()) != 32:
            msg = "That does not appear to be a valid Client ID"
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup11(message, user, guildconfig, *args)
        else:
            guildconfig.set('blizzard', 'client_id', message.content)
            await guildconfig.write()
            await setup12(message, user, guildconfig, *args)


async def setup12(message, user, guildconfig, *args):
    user['setupstep'] = 12
    running_setup[user['user_id']] = user
    title = 'Paste your Blizzard API Client SECRET:'
    msg = ''
    if guildconfig.get("blizzard", "client_secret") != "None":
        msg = 'Type "keep" to keep your existing client secret\n\n'
    msg = msg + """From same Blizzard API client created above"""
    embed = discord.Embed(title=title, description=msg, color=SUCCESS_COLOR)
    await messagesend(message, embed, user, guildconfig)


async def response12(message, user, guildconfig, *args):
    if guildconfig.get("blizzard", "client_secret") != "None" and message.content.lower() == "keep":
        await setup13(message, user, guildconfig, *args)
    else:
        if len(message.content.lower()) != 32:
            msg = "That does not appear to be a valid Client Secret"
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup12(message, user, guildconfig, *args)
        else:
            guildconfig.set('blizzard', 'client_secret', message.content)
            await guildconfig.write()
            await setup13(message, user, guildconfig, *args)


async def setup13(message, user, guildconfig, *args):
    user['setupstep'] = 13
    running_setup[user['user_id']] = user
    title = "Select a command prefix for bot commands:"
    embed = discord.Embed(title=title, color=SUCCESS_COLOR)
    for num, cmd in COMMAND_PREFIXES.items():
        embed.add_field(name=f"{num}: {cmd[0]}", value=f"{cmd[1]}")
    await messagesend(message, embed, user, guildconfig)


async def response13(message, user, guildconfig, *args):
    resp = message.content
    try:
        int(resp)
    except:
        msg = f'Invalid selection.  Please select 1 through {len(COMMAND_PREFIXES)}'
        embed = discord.Embed(description=msg, color=FAIL_COLOR)
        await messagesend(message, embed, user, guildconfig)
        await setup13(message, user, guildconfig, *args)
    else:
        if int(resp) < 1 or int(resp) > len(COMMAND_PREFIXES):
            msg = f'Invalid selection.  Please select 1 through {len(COMMAND_PREFIXES)}'
            embed = discord.Embed(description=msg, color=FAIL_COLOR)
            await messagesend(message, embed, user, guildconfig)
            await setup13(message, user, guildconfig, *args)
        else:
            guildconfig.set('discord', 'command_prefix', COMMAND_PREFIXES[int(resp)][0])
            await guildconfig.write()
            del running_setup[user['user_id']]
            guildconfig.set("discord", "setupran", "True")
            guildconfig.set("discord", "setupadmin", user['user_name'])
            guildconfig.set("discord", "setupadmin_id", user['user_id'])
            await guildconfig.write()
            title = 'WowInfoClassic setup wizard complete!'
            embed = discord.Embed(title=title, color=SUCCESS_COLOR)
            await messagesend(message, embed, user, guildconfig)


async def help(message, user, guildconfig, *args):
    logcommand(message, user)
    command_prefix = guildconfig.get("discord", "command_prefix")
    if guildconfig.get("discord", "pm_only") == "True":
        msg = "Commands can be privately messaged directly to the bot, the reply will be in a private message."
    elif guildconfig.get("discord", "limit_to_channel") == 'Any':
        msg = "Commands can be privately messaged directly to the bot or in any channel, the reply will be in the channel you sent the command from."
    else:
        msg = f'Commands can be privately messaged directly to the bot or in the #{guildconfig.get("discord", "limit_to_channel")} channel, the reply will be in the #{guildconfig.get("discord", "limit_to_channel")} channel or a private message'
    embed = discord.Embed(title="WoW Info Classic Bot Commands:", description=msg, color=HELP_COLOR)
    embed.add_field(name=f"**`{command_prefix}raids [optional instance name]`**", value=f"Last 5 raids for the guild, [MC,ONY,BWL,ZG,AQ20,AQ40]\nLeave instance name blank for all", inline=False)
    embed.add_field(name=f"**`{command_prefix}player <character name>`**", value=f"Character information from last logged encounters", inline=False)
    embed.add_field(name=f"**`{command_prefix}gear <character name>`**", value=f"Character gear from last logged encounters", inline=False)
    embed.add_field(name=f"**`{command_prefix}price <item name>`**", value=f"Price and information for an item", inline=False)
    embed.add_field(name=f"**`{command_prefix}item <item name>`**", value=f"Same as price command", inline=False)
    embed.add_field(name=f"**`{command_prefix}server`**", value=f"Status and info of the World of Warcraft Classic server", inline=False)
    embed.add_field(name=f"**`{command_prefix}news`**", value=f"Latest World of Warcraft Classic News", inline=False)
    embed.add_field(name=f"**`{command_prefix}help`**", value=f"This help message", inline=False)
    if user['is_admin']:
        embed.add_field(name=f"**`{command_prefix}setup`**", value=f"Run the bot setup wizard (admins only)", inline=False)
        embed.add_field(name=f"**`{command_prefix}settings`**", value=f"Current bot settings (admins only)", inline=False)

    msg = f'Commands can also be abbreviated with just the first letter, i.e. {command_prefix}h for help'
    embed.set_footer(text=msg)
    await message.author.send(embed=embed)


async def test(message, user, guildconfig, *args):
    logcommand(message, user)
    # blizcli = BlizzardAPI(bliz_int_client, bliz_int_secret, guildconfig.get("server", "server_region"))
    # await blizcli.authorize()
    # pprint(await blizcli.realm_list())
    pprint(guildconfig._sections)


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
