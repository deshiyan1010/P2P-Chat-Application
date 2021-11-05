import socket
import threading
import json
import time



class Server:

    def __init__(self):
        self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serv.bind(('0.0.0.0', 8081))
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
                self.register(conn,rdict["register"],conn.getsockname()[0],rdict["port"])

            if "getpeer" in rdict.keys():
                self.getpeeripport(conn,rdict["getpeer"])

            if "purge" in rdict.keys():
                self.purgeuser(rdict['purge'])

    def register(self,conn,uname,ip,port):
        try:
            self.addr_dict[uname] = (ip,port,time.time())
            conn.send(bytes(json.dumps({'status':'1'}),'utf-8'))
        except:
            conn.send(bytes(json.dumps({'status':'0'}),'utf-8'))

    def getpeeripport(self,conn,peer):
        peer = self.addr_dict.get(peer,None)
        if peer != None:
            conn.send(bytes(json.dumps({'ip':peer[0],'port':peer[1],'timestamp':peer[2]}),'utf-8'))
        else:
            conn.send(bytes(json.dumps({'ip':None,'port':None,'timestamp':None}),'utf-8'))

    def purgeuser(self,uname):
        del self.addr_dict[uname]

serv = Server()
serv.start()