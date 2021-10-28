class ServerMessage:
    def __init__(self, ra, dh_pub_key):
        self.name = "SERVER"
        self.ra = ra
        self.dh_pub_key = dh_pub_key

class ClientChallenge:
    def __init__(self, ra):
        self.name = "CLIENT"
        self.ra = ra
        self.authMessageType = "CLIENT_CHALLENGE"

class ServerChallenge:
    def __init__(self, rb,EncryptedServerMessage):
        self.rb = rb
        self.ServerMessage = EncryptedServerMessage
        self.authMessageType = "SERVER_RESPONSE"

class ClientResponse:
    def __init__(self, rb, dh_pub_key):
        self.name = "CLIENT"
        self.rb = rb
        self.dh_pub_key = dh_pub_key
        self.authMessageType = "CLIENT_RESPONSE"

# wrapper message function for all the messages
class Message:
    def __init__(self, messageText, messageType):
        self.messageText = messageText
        self.messageType = messageType # either AUTH or MSG
