from enum import unique
import socket
import json
import threading
import time
import atexit
from peewee import *
import os

from cryptotools import AESCipher, EllipticCurveCryptography



db = SqliteDatabase(os.path.join(os.path.dirname(__file__),'client.db'))
db.connect(reuse_if_open=True)


class User(Model):
    uname = CharField(unique=True)
    xpublicKey = CharField()
    ypublicKey = CharField()
    privateKey = CharField()

    class Meta:
        database = db

class Peers(Model):
    uname = CharField(unique=True)
    xpublicKey = CharField()
    ypublicKey = CharField()

    class Meta:
        database = db



class NewMessages(Model):
    uname = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db



class ReceivedMessages(Model):
    uname = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db





class SentMessages(Model):
    uname = ForeignKeyField(Peers)
    message = TextField()
    timestamp = TimestampField()

    class Meta:
        database = db

db.create_tables([User,Peers,NewMessages,ReceivedMessages,SentMessages])


def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper




class Chat:


    def __init__(self):

        self.newMessageR = False
        
        self.ecc = EllipticCurveCryptography()
        self.aes = AESCipher()

        self.sending_port = self.get_free_tcp_port()
        self.receiving_port = self.get_free_tcp_port()

        self.sending_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiving_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sending_sock.bind(('',self.sending_port)) 
        self.receiving_sock.bind(('',self.receiving_port))


        self.receiving_sock.listen(5)


        self.add_dict = {}
        self.messages = {}

        try:
            self.username = User.select()[0].uname
            self.xpub_key = int(User.select()[0].xpublicKey)
            self.ypub_key = int(User.select()[0].ypublicKey)
            self.pvt_key = int(User.select()[0].privateKey)

        except:
            self.username = input('Username: ')
            self.xpub_key,self.ypub_key,self.pvt_key = self.ecc.generate_ecc_pair()
            create_user = User(uname=self.username,xpublicKey=self.xpub_key,ypublicKey=self.ypub_key,privateKey=self.pvt_key)
            create_user.save()


        
        self.connect()
        self.startcli()
        atexit.register(self.purge)

    def pollForNewMessage(self):
        nm = self.newMessageR
        self.newMessageR = False
        return nm


    def get_free_tcp_port(self):

        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(('', 0))
        _, port = tcp.getsockname()
        tcp.close()
        return port 
    
    def receive(self,conn):
        while True:
            from_server = json.loads(conn.recv(4096).decode('utf-8'))
            if not from_server:
                continue
            else:
                break
        return from_server


    def connect(self):
        self.sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_to_server.connect(('0.0.0.0', 8081))


        uj = json.dumps({'register':self.username,'port':self.receiving_port,'xpub':self.xpub_key,'ypub':self.ypub_key})
        self.sock_to_server.send(bytes(uj,'utf-8'))


        from_server = self.receive(self.sock_to_server)


        if from_server['status']==0:
            print("Username taken...")
            exit()
        
        self.sock_to_server.close()
        


    def getpeerinfo(self,uname):
        self.sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_to_server.connect(('0.0.0.0', 8081))

        uj = json.dumps({'getpeer':uname})

        self.sock_to_server.send(bytes(uj,'utf-8'))

        while True:
            from_server = json.loads(self.sock_to_server.recv(4096).decode('utf-8'))

            if not from_server:
                continue
            else:
                break
        print("Peer info: ", from_server)

        try:
            p = Peers(uname=uname,xpublicKey=from_server['xpub'],ypublicKey=from_server['ypub'])
            p.save()
        except:
            pass


        if None not in from_server.values():
            self.sending_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sending_sock.connect((from_server['ip'], from_server['port']))
            from_server['sock'] = self.sending_sock
            from_server['ke_done'] = False
            self.add_dict[uname] = from_server
            return True
        else:
            print("No such user found")
            return False
        
    @threaded
    def acc_connection(self):

        while True:
            conn, addr = self.receiving_sock.accept()
            rthread = threading.Thread(target=self.get_msg,kwargs={'c':conn})
            rthread.start()


    @threaded
    def get_msg(self,c):

        while True:
            msg_dict = self.receive(c)

            xpub,ypub = self.pub_keys(msg_dict['from_uname'])

            if self.ecc.verify(xpub,ypub,msg_dict['enc_msg'],*msg_dict['signed_digest']):
                print("Sign verified")

            else:
                print("Verification failed")


            dec_msg = self.decrypt(msg_dict['from_uname'],msg_dict['enc_msg'])
            print("Message received: ",dec_msg)

            print("Msg Dict: ",msg_dict)
            
            
            if self.add_dict.get(msg_dict['from_uname'],None) is None:
                self.getpeerinfo(msg_dict['from_uname'])

            user_obj = Peers.select().where(Peers.uname==msg_dict['from_uname'])[0]
            msg_obj = NewMessages(uname=user_obj,message=dec_msg,timestamp=time.time())
            msg_obj.save()

            self.newMessageR = True


    def send_msg(self,uname,msg):

        if self.add_dict.get(uname,None) is None:
                self.getpeerinfo(uname)

        uinfo = self.add_dict[uname]

        enc_msg = self.encrypt(uname,msg)
        signed_digest = self.ecc.sign(self.pvt_key,enc_msg)
        
        # if uinfo['ke_done']==False:
        #     self.send_key(uinfo['sock'])
        #     self.receive_key(uinfo['sock'])
        #     uinfo['ke_done'] = True
        
        uinfo['sock'].send(bytes(json.dumps({'from_uname':self.username,'enc_msg':enc_msg,'signed_digest':signed_digest}),'utf-8'))

        user_obj = Peers.select().where(Peers.uname==uname)[0]
        msg_obj = SentMessages(uname=user_obj,message=msg,timestamp=time.time())
        msg_obj.save()


    def encrypt(self,uname,msg):

        xpub,ypub = self.pub_keys(uname)

        shared_key = self.ecc.create_shared_key((xpub,ypub),self.pvt_key)

        enc_msg = self.aes.encrypt(msg,shared_key[0])

        return enc_msg

    def decrypt(self,uname,enc_msg):
        
        xpub,ypub = self.pub_keys(uname)

        shared_key = self.ecc.create_shared_key((xpub,ypub),self.pvt_key)

        dec_msg = self.aes.decrypt(enc_msg,shared_key[0])

        return dec_msg


    def pub_keys(self,uname):
        try:
            peer_info = Peers.select().where(Peers.uname==uname)[0]
            xpub,ypub = int(peer_info.xpublicKey),int(peer_info.ypublicKey)
            return xpub,ypub
        except Exception as e:
            print(e)
            self.getpeerinfo(uname)
            return self.pub_keys(uname)

    def startcli(self):
        t1 = threading.Thread(target=self.acc_connection)
        t1.start()

    def purge(self):
        self.sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_to_server.connect(('0.0.0.0', 8081))
        uj = json.dumps({'purge':self.username})
        self.sock_to_server.send(bytes(uj,'utf-8'))


    def receive_key(self,c):
        ke_dict = self.receive(c)

        try:
            p = Peers(uname=ke_dict['from_user'],xpublicKey=ke_dict['xpub'],ypublicKey=ke_dict['ypub'])
            p.save()
        except:
            pass

    def send_key(self,conn):
        user = User.select()[0]
        conn.send(bytes(json.dumps({'from_user':user.uname,'xpub':user.xpublicKey,'ypub':user.ypublicKey}),'utf-8'))

    def message_read(self,uname):
        user_obj = Peers.select().where(Peers.uname==uname)[0]
        list_read_msgs = NewMessages.select().where(NewMessages.uname==user_obj)

        for record in list_read_msgs:
            msg_obj = ReceivedMessages(uname=user_obj,message=record.message,timestamp=record.timestamp)
            msg_obj.save()
            record.delete_instance()


if __name__=="__main__":
    c = Chat()