from peewee import *
import os

import time


db = SqliteDatabase(os.path.join(os.path.dirname(__file__),'../U1/client.db'))
db = SqliteDatabase('../U1/client.db')

db.connect()


class User(Model):
    uname = CharField(unique=True)
    xpublicKey = CharField()
    ypublicKey = CharField()
    privateKey = CharField()

    class Meta:
        database = db

class Peers(Model):
    uname = CharField(unique=True)
    xpublicKey = TextField()
    ypublicKey = TextField()

    class Meta:
        database = db



class NewMessages(Model):
    user = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db



class ReceivedMessages(Model):
    user = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db





class SentMessages(Model):
    user = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db



db.connect(reuse_if_open=True)

db.create_tables([User,Peers,NewMessages,ReceivedMessages,SentMessages])


# u = User.create(uname='u2',xpublicKey='efes',ypublicKey='efeadavcs',privateKey='efesqewfqe')
# u.save()


# p1 = Peers(uname='1adam',xpublicKey='1efes',ypublicKey='1efeadavcs',privateKey='1efesqewfqe')
# p1.save()


# p2 = Peers(uname='2adam',xpublicKey='2efes',ypublicKey='21efeadavcs',privateKey='21efesqewfqe')
# p2.save()



# p3 = Peers(uname='3adam',xpublicKey='31efes',ypublicKey='31efeadavcs',privateKey='31efesqewfqe')
# p3.save()



# p4 = Peers(uname='4adam',xpublicKey='41efes',ypublicKey='41efeadavcs',privateKey='41efesqewfqe')
# p4.save()


# nm = NewMessages(user=p4,message="hello",timestamp=time.time())
# nm.save()


u = Peers.select().where(Peers.uname=='4adam')
print(u[0].xpublicKey)



from network_client import Chat

c = Chat()
c.send_msg('u2','hello')