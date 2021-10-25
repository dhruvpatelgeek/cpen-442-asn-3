# local import from "protocol.py"
from msg import *
import hashlib
import datetime, time
import json
from Crypto.Cipher import AES # pip install pycryptodome

class Protocol:

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, secretKey):
        self.max_bytes = 16                             # Max number of bytes for nonce length and tag length
        self._key = b"QeThWmYq3t6w9z$C&F)J@NcRfUjXn2r4" # AES key should be 128, 192, or 256 bits long
        self.hashFunc = hashlib.sha256()
        self.secretKey=secretKey
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, secretKey):

        print(str(self.secretKey))
        keyHash = hashlib.sha256(str.encode(self.secretKey)).hexdigest()
        dts = datetime.datetime.utcnow().strftime("%b %d %Y %H")
      
        timeStamp=str(dts)
        print("time is ",dts)
        authmessage = AuthMessage(keyHash,timeStamp)
      

        hash = hashlib.sha256(str.encode(json.dumps(authmessage.__dict__))).hexdigest()
        payload= Payload(hash,"AUTH")
        jsonStr = json.dumps(payload.__dict__)
        print("jsonStr is ", jsonStr)
        return jsonStr


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False
        received = json.loads(message)
        type = received["type"]
        if(type=="AUTH"):
            return True
        return False
        

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        received = json.loads(message)
        msg_val = received["msg"]
        crc_val = received["crc"] 
        print( "Received msg hash "+ str(msg_val))
        print("Received crc val "+str(crc_val))

        
        print("secret key: " + str(self.secretKey))
      
    
        keyHash = hashlib.sha256(str.encode(self.secretKey)).hexdigest()
        dts = datetime.datetime.utcnow().strftime("%b %d %Y %H")
        timeStamp=str(dts)
        print("time is ",dts)
        authmessage = AuthMessage(keyHash,timeStamp)
        hash = hashlib.sha256(str.encode(json.dumps(authmessage.__dict__))).hexdigest()

       
        print("comparing crc " + str(crc_val) + " and " + str(zlib.crc32(str.encode(msg_val))) )
        print("comparing hash " + str(msg_val) + " and " + str(hash))

        if crc_val==zlib.crc32(str.encode(msg_val)):
            if msg_val==hash:
                print(" 1 part of auth")
                return True
            else :
                print(" WRONG HASH ")
        else :
            print(" WRONG CRC ")
            
        print("NOT part of auth")
        return False
    
    
    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        
        # Encrypt the plaintext using AES in EAX mode
        cipher = AES.new(self._key, AES.MODE_EAX)
        nonce = cipher.nonce
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)   

        # Encode the length of the nonce, appended with #'s (16 bytes)
        nonce_str = str(len(nonce))
        nonce_str += ("#" * (self.max_bytes - len(nonce_str)))
        nonce_str = nonce_str.encode()

        # Encode the length of the tag, appended with #'s (16 bytes)
        tag_str = str(len(tag))
        tag_str += ("#" * (self.max_bytes - len(tag_str)))
        tag_str = tag_str.encode()

        # Send the nonce length, the tag length, the nonce, the tag, and the ciphertext
        data = nonce_str + tag_str + nonce + tag + cipher_text
        
        return data  


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, data):

        # Decode the nonce length and the tag length
        nonce_len = int(data[0:self.max_bytes].decode().strip("#"))
        tag_len = int(data[self.max_bytes:(2 * self.max_bytes)].decode().strip("#"))
        
        # Get the nonce, the tag, and the ciphertext
        nonce = data[(2 * self.max_bytes):(2 * self.max_bytes + nonce_len)]
        tag = data[(2 * self.max_bytes + nonce_len):(2 * self.max_bytes + nonce_len + tag_len)]
        cipher_text = data[(2 * self.max_bytes + nonce_len + tag_len):]

        # Decrypt the ciphertext using AES in EAX mode
        cipher = AES.new(self._key, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt(cipher_text)
        
        # Perform integrity check
        try:
            cipher.verify(tag)
        except ValueError:
            plain_text = b"Key incorrect or message corrupted"

        return plain_text
