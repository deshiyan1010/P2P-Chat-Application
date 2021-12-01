import socket
import threading
import json
import time

from cryptotools import AESCipher, EllipticCurveCryptography


from peewee import *
import os

db = SqliteDatabase(os.path.join(os.path.dirname(__file__),'server.db'))
db.connect(reuse_if_open=True)



class Peers(Model):
    uname = CharField(unique=True)
    xpublicKey = CharField()
    ypublicKey = CharField()

    class Meta:
        database = db


db.create_tables([Peers])


peer_obj = Peers.select().where(Peers.uname=='u2')[0]

print(peer_obj)
