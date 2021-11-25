import random

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random


class EllipticCurveCryptography:
    
    def __init__(self):
        self.Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 
        self.N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.Acurve = 0; Bcurve = 7 
        self.Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.GPoint = (self.Gx,self.Gy)

        # self.privKey = 75263518707598184987916378021939673586055614731957507592904438851787542395619

    def modinv(self,a,n):
        lm, hm = 1,0
        low, high = a%n,n

        while low > 1:
            ratio = int(high/low)

            nm, new = hm-lm*ratio, high-low*ratio
            lm, low, hm, high = nm, new, lm, low

        return lm % n

    def ECadd(self,a,b):
        LamAdd = ((b[1]-a[1]) * self.modinv(b[0]-a[0],self.Pcurve)) % self.Pcurve
        
        x = (LamAdd*LamAdd-a[0]-b[0]) % self.Pcurve
        y = (LamAdd*(a[0]-x)-a[1]) % self.Pcurve
        return (x,y)

    def ECdouble(self,a):

        Lam = ((3*a[0]*a[0]+self.Acurve) * self.modinv((2*a[1]),self.Pcurve)) % self.Pcurve
        x = (Lam*Lam-2*a[0]) % self.Pcurve
        y = (Lam*(a[0]-x)-a[1]) % self.Pcurve

        return (x,y)

    def EccMultiply(self,GenPoint,ScalarHex): 
        if ScalarHex == 0 or ScalarHex >= self.N: 
            raise Exception("Invalid Scalar/Private Key")
        ScalarBin = str(bin(ScalarHex))[2:]

        Q=GenPoint
        for i in range (1, len(ScalarBin)): 
            Q=self.ECdouble(Q); 
            if ScalarBin[i] == "1":
                Q=self.ECadd(Q,GenPoint)
        return (Q)


    def generate_pvt_key(self):
        a = 0
        for i in range(256):
            a = 2*a + random.randint(0,1)
        
        return a
    


    def generate_ecc_pair(self):

        private_key = self.generate_pvt_key()
        PublicKey = self.EccMultiply(self.GPoint,private_key)
        # print ("the private key:") 
        # print (self.privKey)
        # print ("the uncompressed public key (not address):")
        # print (PublicKey)
        # print("the uncompressed public key (HEX):")
        # print("04" + "%064x" % PublicKey[0] + "%064x" % PublicKey[1])

        # print("the official Public Key - compressed:") 
        # if PublicKey[1] % 2 == 1: # If the Y value for the Public Key is odd.
        #     public_key = "03"+str(hex(PublicKey[0])[2:]).zfill(64)
        # else: # Or else, if the Y value is even.
        #     public_key = "02"+str(hex(PublicKey[0])[2:]).zfill(64)

        return PublicKey[0],PublicKey[1],private_key

    def sign(self,private_key,hash):
        if isinstance(hash,str):
            hash = int(hash,16)
        RandNum = self.generate_pvt_key()
        xRandSignPoint, yRandSignPoint = self.EccMultiply(self.GPoint,RandNum)
        r = xRandSignPoint % self.N
        s = ((hash + r*private_key)*(self.modinv(RandNum,self.N))) % self.N
        return r,s

    def verify(self,public_x,public_y,hash,r,s):
        if isinstance(hash,str):
            hash = int(hash,16)
        w = self.modinv(s,self.N)
        xu1, yu1 = self.EccMultiply(self.GPoint,(hash * w)%self.N)
        xu2, yu2 = self.EccMultiply((public_x,public_y),(r*w)%self.N)
        x,y = self.ECadd((xu1,yu1),(xu2,yu2))
        if r==x:
            return True
        return False









import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode,b16decode,b16encode


class AESCipher(object):
    def __init__(self):
        self.block_size = AES.block_size


    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text
    

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]


    def encrypt(self, plain_text, key):
        key = repr(key).encode()
        key = hashlib.sha256(key).digest()
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b16encode(iv + encrypted_text).decode("utf-8")



    def decrypt(self, encrypted_text,key):
        key = repr(key).encode()
        key = hashlib.sha256(key).digest()
        encrypted_text = b16decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)






if __name__=="__main__":

    ecc = EllipticCurveCryptography()
    pux,puy,key = ecc.generate_ecc_pair()

    
    cipher = AESCipher()


    encrypted = cipher.encrypt('Secret',key)


    signed = ecc.sign(key,encrypted)

    print(ecc.verify(pux,puy,encrypted,*signed))

    decrypted = cipher.decrypt(encrypted,key)
    print(decrypted)
