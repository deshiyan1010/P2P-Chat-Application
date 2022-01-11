# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'test.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from re import U
from PyQt5 import QtCore, QtGui, QtWidgets
from network_client import Chat, User,Peers,NewMessages,ReceivedMessages,SentMessages, threaded
import threading
from PyQt5.QtCore import QThread,QObject,pyqtSignal,pyqtSlot

import time

class WorkerThread(QtCore.QThread):
    nm = QtCore.pyqtSignal()
    def run(self):
        while 1:
            self.nm.emit()
            time.sleep(0.2)

class Ui_Form(object):

    def __init__(self):
        super().__init__()

        
        self.cUser = None
        self.c = Chat()
        self.msg_dict = {}


        


    def displayOnChat(self):
        text = self.textEdit.toPlainText()

        if self.cUser!=None:
            print("sending")
            self.c.send_msg(self.cUser,text)
            self.msg_dict[self.cUser].append("Me: "+text)
            self.pushToGUI()

    def search(self):
        uname = self.textEdit_2.toPlainText()
        if self.c.getpeerinfo(uname)==True:
            self.addToListWidget(uname)
            self.msg_dict[uname] = []


    def pushToGUI(self):
        if self.cUser!=None:
            msgs = '\n'.join(self.msg_dict[self.cUser])
            self.textBrowser.setText(msgs)


    def listwidgetclicked(self,item):
        self.cUser = item.text()
        self.pushToGUI()
    
    def addToListWidget(self,uName):
        if uName not in [str(self.listWidget.item(i).text()) for i in range(self.listWidget.count())]:
            self.listWidget.addItem(QtWidgets.QListWidgetItem(uName))

    def addNewMessagesToDict(self):
        if self.c.pollForNewMessage()==False:
            return
        nMList = NewMessages.select()
        
        unameSet = set()
        for record in nMList:
            if record.uname.uname not in self.msg_dict:
                self.msg_dict[record.uname.uname] = []
            self.msg_dict[record.uname.uname].append(record.uname.uname+": "+record.message)
            unameSet.add(record.uname.uname)
        self.pushToGUI()

        for u in unameSet:
            self.addToListWidget(u)
            self.c.message_read(u)
        
    

    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(793, 715)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setGeometry(QtCore.QRect(314, 651, 411, 21))
        self.pushButton.setObjectName("pushButton")
        self.textBrowser = QtWidgets.QTextBrowser(Form)
        self.textBrowser.setGeometry(QtCore.QRect(310, 139, 421, 431))
        self.textBrowser.setObjectName("textBrowser")
        self.textEdit = QtWidgets.QTextEdit(Form)
        self.textEdit.setGeometry(QtCore.QRect(310, 579, 421, 61))
        self.textEdit.setObjectName("textEdit")
        self.listWidget = QtWidgets.QListWidget(Form)
        self.listWidget.setGeometry(QtCore.QRect(30, 140, 271, 531))
        self.listWidget.setObjectName("listWidget")
        self.textEdit_2 = QtWidgets.QTextEdit(Form)
        self.textEdit_2.setGeometry(QtCore.QRect(30, 90, 211, 31))
        self.textEdit_2.setObjectName("textEdit_2")
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setGeometry(QtCore.QRect(244, 90, 61, 31))
        self.pushButton_2.setObjectName("pushButton_2")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.worker = WorkerThread()
        self.worker.start()
        self.worker.nm.connect(self.addNewMessagesToDict)
        print("out")

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", self.c.username))
        self.pushButton.setText(_translate("Form", "SEND"))
        self.pushButton_2.setText(_translate("Form", "Search"))

        self.pushButton.clicked.connect(self.displayOnChat)
        self.pushButton_2.clicked.connect(self.search)   
        self.listWidget.itemClicked.connect(self.listwidgetclicked)





if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    print("sdvwd")
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())


#self.c.pollForNewMessage()
