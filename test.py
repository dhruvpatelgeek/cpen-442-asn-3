from protocol import Protocol
from protocolBuffer import *
from protocolBuffer.protogen_out.message_pb2 import *
import pyDHE as dh
import pickle
#client test

import protocolBuffer.protogen_out.msgProtoBuf_pb2 as msg_gpf

# client sends

clientChallange=msg_gpf.ClientChallenge()
clientChallange.name="CLIENT"
clientChallange.ra="7f29b16b-d7ab-45f3-8f5b-a71443804808"
clientChallange.authMessageType="clientChallange"

print(clientChallange)

#server sends
serverResponse_load=msg_gpf.ServerResponse_load()
serverResponse_load.name="SERVER"
serverResponse_load.ra="7f29b16b-d7ab-45f3-8f5b-a71443804808"
serverResponse_load.diffie_hellman_public_key=str(dh.new().getPublicKey())
load=serverResponse_load.SerializeToString()
prtcl = Protocol("self.secretEntry.get()")
encrypted_load=Protocol.EncryptAndProtectMessage(prtcl,load)
serverResponse_shell=msg_gpf.ServerResponse_shell()
serverResponse_shell.rb="a139dcb7-6b2a-4dd3-bfab-99da9a03f8f6"
serverResponse_shell.load=encrypted_load
serverResponse_shell.authMessageType="serverResponse"
print(serverResponse_shell)

print("\nSEND RA\t",serverResponse_load.ra)
#getting RA back
recv_load=Protocol.DecryptAndVerifyMessage(prtcl,serverResponse_shell.load)

recv_load_serverResponse_load=msg_gpf.ServerResponse_load()

recv_load_serverResponse_load.ParseFromString(recv_load)
print("\nRECV RA\t",recv_load_serverResponse_load.ra)

















