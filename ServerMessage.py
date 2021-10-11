class AuthMessage:
    def __init__(self, keyHash, timeStamp):
        self.keyHash = keyHash
        self.timeStamp = timeStamp

class SessionKeyMessage:
    def __init__(self, sessionKey, timeStamp):
        self.sessionKey = sessionKey
        self.timeStamp = timeStamp

