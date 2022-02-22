import socket
import threading
import json
import time

from cryptotools import AESCipher, EllipticCurveCryptography
from netdata import SERV_PORT,SERV_IP

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




class Server:

    def __init__(self):
        self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serv.bind((SERV_IP, SERV_PORT))
        self.serv.listen(5)
        self.addr_dict = {}


    def start(self):
        while True:
            conn, addr = self.serv.accept()
            while True:
                rdict = json.loads(conn.recv(4096).decode('utf-8'))
                if not rdict:
                    continue
                else:
                    break
            print(rdict)
            if "register" in rdict.keys():
                self.register(conn,rdict["register"],conn.getsockname()[0],rdict["port"],rdict["xpub"],rdict["ypub"])

            if "getpeer" in rdict.keys():
                self.getpeerinfo(conn,rdict["getpeer"])

            if "purge" in rdict.keys():
                self.purgeuser(rdict['purge'])



    def register(self,conn,uname,ip,port,xpub,ypub):
        
        try:
            peer = Peers.select().where(Peers.uname==uname)


            if len(peer)==0:
                peer = Peers(uname=uname,xpublicKey=xpub,ypublicKey=ypub)
                peer.save()
            elif(peer[0].xpublicKey==str(xpub) and peer[0].ypublicKey==str(ypub)):
                print("Found user in DB")
            else:
                1/0
                
            self.addr_dict[uname] = (ip,port,time.time())
            conn.send(bytes(json.dumps({'status':'1'}),'utf-8'))

        except Exception as e:
            print(e)
            conn.send(bytes(json.dumps({'status':'0'}),'utf-8'))

    def getpeerinfo(self,conn,peer):
        print(self.addr_dict)
        peer_details = self.addr_dict.get(peer,None)

        if peer_details != None:
            peer_obj = Peers.select().where(Peers.uname==peer)[0]
            conn.send(bytes(json.dumps({'ip':peer_details[0],'port':peer_details[1],'timestamp':peer_details[2],'xpub':peer_obj.xpublicKey,'ypub':peer_obj.ypublicKey}),'utf-8'))
        else:
            conn.send(bytes(json.dumps({'ip':None,'port':None,'timestamp':None,'xpub':None,'ypub':None}),'utf-8'))

    def purgeuser(self,uname):
        try:
            del self.addr_dict[uname]
        except:
            pass


if __name__=="__main__":
    serv = Server()
    serv.start()
