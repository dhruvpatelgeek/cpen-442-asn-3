import zlib
import hashlib

class Payload:
    def __init__(self,msg):
          self.msg = msg
          self.crc = zlib.crc32(str.encode(msg))

class AuthMessage:
    def __init__(self, keyHash, timeStamp):
        self.keyHash = keyHash
        self.timeStamp = timeStamp
      
        

class SessionKeyMessage:
    def __init__(self, sessionKey, timeStamp):
        self.sessionKey = sessionKey
        self.timeStamp = timeStamp
      
        

class nackMessage:
    def __init__(self, status, timeStamp):
        self.status = status
        self.timeStamp = timeStamp # unix.now()<mins,secs dropped>
       

