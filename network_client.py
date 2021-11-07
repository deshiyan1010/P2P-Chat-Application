import socket
import json
import threading
import time
import atexit


def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper

class Chat:


    def __init__(self):
        self.username = input('Username: ')

        self.sending_port = self.get_free_tcp_port()
        self.receiving_port = self.get_free_tcp_port()

        self.sending_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiving_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sending_sock.bind(('',self.sending_port)) 
        self.receiving_sock.bind(('',self.receiving_port))


        self.receiving_sock.listen(5)


        self.add_dict = {}
        self.messages = {}


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


        uj = json.dumps({'register':self.username,'port':self.receiving_port})
        self.sock_to_server.send(bytes(uj,'utf-8'))


        from_server = self.receive(self.sock_to_server)


        if from_server['status']==0:
            print("Connecting to server failed.")
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
        if None not in from_server.values():
            self.sending_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sending_sock.connect((from_server['ip'], from_server['port']))
            from_server['sock'] = self.sending_sock
            self.add_dict[uname] = from_server
        else:
            print("No such user found")
        
    @threaded
    def acc_connection(self):

        while True:
            conn, addr = self.receiving_sock.accept()
            rthread = threading.Thread(target=self.get_msg,kwargs={'c':conn})
            rthread.start()


    @threaded
    def get_msg(self,c):

        while True:
            msg_dict = c.recv(4096)
            if not msg_dict:
                continue

            msg_dict = json.loads(msg_dict.decode('utf-8'))
            self.messages[msg_dict['from_uname']] = msg_dict['message']
            print("Msg Received: ",msg_dict)

            if self.add_dict.get(msg_dict['from_uname'],None) is None:
                self.getpeerinfo(msg_dict['from_uname'])



    def send_msg(self,uname,msg):
        uinfo = self.add_dict[uname]
        uinfo['sock'].send(bytes(json.dumps({'from_uname':self.username,'message':msg}),'utf-8'))


    def startcli(self):
        t1 = threading.Thread(target=self.acc_connection)
        t1.start()

    def purge(self):
        self.sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_to_server.connect(('0.0.0.0', 8081))
        uj = json.dumps({'purge':self.username})
        self.sock_to_server.send(bytes(uj,'utf-8'))



if __name__=="__main__":
    c = Chat()
    c.connect()
    c.startcli()
    atexit.register(c.purge)
