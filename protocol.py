# local import from "protocol.py"
from msg import *
import hashlib
import datetime, time
import json

class Protocol:

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, secretKey):
        self._key = None
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
        payload= Payload(hash)
        jsonStr = json.dumps(payload.__dict__)
        print("jsonStr is ", jsonStr)
        return jsonStr


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        
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


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
