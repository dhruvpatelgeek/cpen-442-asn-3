import zlib
import hashlib
import enum

class Payload:
    def __init__(self,msg,type):
          self.type=type
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
       

class MsgType(enum.Enum):
    AUTH = 1
    CIPHER = 2
