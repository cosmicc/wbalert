from configparser import ConfigParser

import boto3
import msgpack
from prettyprinter import pprint

configfile = '/etc/wbalert.cfg'

systemconfig = ConfigParser()
systemconfig.read(configfile)


logfile = systemconfig.get("general", "logfile")
aws_key = systemconfig.get("general", "aws_key")
aws_secret = systemconfig.get("general", "aws_secret")
topic_arn = systemconfig.get("general", "topic_arn")
userdatafile = systemconfig.get("general", "userdata_file")

sns = boto3.client("sns", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, region_name='us-east-1')

WORLD_BOSSES = {'Azuregos': 'Azhara', 'Lord Kazzak': "Blasted Lands", "Ysondre": '', 'Emeriss': '', 'Taerar': '', 'Lethon': ''}
DRAGON_ZONES = ['Ashenvale', 'Feralas', 'Hinterlands', 'Duskwood']

#data = {'329658352969973760': {'alert': 2, 'number': '5864808574'}}
#msgpack.dump(data, open(userdatafile, 'wb'))

userdata = msgpack.load(open(userdatafile, 'rb'))
pprint(userdata)
print(type(userdata))

def clisub(sns, uid, number, topic_arn):
    sns.subscribe(TopicArn=topic_arn, Protocol='sms', Endpoint=number)


def pubmsg(sns, topic_arn, message):
    return sns.publish(TopicArn=topic_arn, Message=message)

msg = f'Azuregos is up in Azhara!\nLog in now if you can.\n\nReply STOP to end these notifications.'

#print(pubmsg(sns, topic_arn, msg))
