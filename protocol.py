# local import from "protocol.py"
import codecs


import hashlib
import datetime, time
import json
from Crypto.Cipher import AES  # pip install pycryptodome
import protocolBuffer.protogen_out.msgProtoBuf_pb2 as gpbf
import uuid
import pyDHE as dh


class Protocol:

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, secretKey):
        self.max_bytes = 16  # Max number of bytes for nonce length and tag length
        self._key = b"QeThWmYq3t6w9z$C&F)J@NcRfUjXn2r4"  # AES key should be 128, 192, or 256 bits long
        self.hashFunc = hashlib.sha256()
        self.secretKey = secretKey
        self.rb = 'NULL'
        self.ra = 'NULL'
        self.dh = dh.new()
        self.sessionKey = 'NULL'
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

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, mode):
        self.ra = str(uuid.uuid1())
        messagePayload = gpbf.Payload()
        messagePayload.type = "AUTH"
        messagePayload.load = b'null'
        messagePayload.authMessageType = "clientChallenge"
        # client mode then send a message
        if mode.get() == 0:
            print("\n [1] IN CLIENT MODE\n")
            # GENERATE THE CLIENT PAYLOAD
            clientChallange = gpbf.ClientChallenge()
            clientChallange.name = "CLIENT"
            clientChallange.ra = self.ra
            print("\n SEND ra \t", clientChallange.ra)
            messagePayload.load = clientChallange.SerializeToString()
        elif mode.get() == 1:
            print("\n [1] IN SERVER MODE\n")
            print("\n[ERROR] SERVER TRIED TO INIT CONN")
        else:
            print("\n [1] IN {NULL} MODE\n")
            print("\n[ERROR] SERVER TRIED TO INIT CONN")

        marshalled_message = messagePayload.SerializeToString()
        return marshalled_message

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        messagePayload = gpbf.Payload()
        messagePayload.ParseFromString(message)
        if messagePayload.type == "AUTH":
            return True
        else:
            return False

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    #
    # if the function returns true then send the message back to the client
    # if the funciton retuns false then don't send the message
    def ProcessReceivedProtocolMessage(self, message, mode):

        print("\n [0]recived \n", type(message), message)
        messagePayload = gpbf.Payload()
        messagePayload.ParseFromString(message)

        if mode.get() == 0:
            print("\n[1] recived AS CLIENT \n", messagePayload)
            rcvServerResShell = gpbf.ServerResponse_shell()
            rcvServerResShell.ParseFromString(messagePayload.load)
            print("\n[1.5] recived AS CLIENT \n", rcvServerResShell)

            # Decrypt and check Ra=Self.Ra && name=SERVER ----------
            rcvServerResLoad = gpbf.ServerResponse_load()
            rcvServerResLoad_Encrypted = rcvServerResShell.load
            print("\n[1.75] recived AS CLIENT \n", rcvServerResLoad_Encrypted)
            rcvServerResLoad_Decrypted = self.DecryptAndVerifyMessage(rcvServerResLoad_Encrypted)
            print("\n[1.875] recived AS CLIENT \n", rcvServerResLoad_Decrypted)
            rcvServerResLoad.ParseFromString(rcvServerResLoad_Decrypted)
            print("\n [2] client recived decrypeted ", rcvServerResLoad)
            # guard clause -----------------------------------------
            if rcvServerResLoad.name != "SERVER":
                print("[AUTH FAILED] REPLAY ATTACK", rcvServerResLoad)
                return False
            if rcvServerResLoad.ra != self.ra:
                print("[AUTH FAILED] Ra!=sent Ra", rcvServerResLoad)
                return False
            # -------------------------------------------------------

            # calculate session key ---------------------------------
            g_b_mod_p=int(rcvServerResLoad.diffie_hellman_public_key)
            self.dh.update(g_b_mod_p)
            session_key =self.dh.getFinalKey()
            print("\n[3.15] CLIENT SESSION KEY IS\t ",session_key)
            # -------------------------------------------------------

            # Rb,g^b mod p -----------------------------------------
            clientResponse=gpbf.ClientResponse()
            clientResponse.name="CLIENT"
            clientResponse.rb=rcvServerResShell.rb
            clientResponse.diffie_hellman_public_key = str(self.dh.getPublicKey())
            # -------------------------------------------------------

            marshalled_client_res=clientResponse.SerializeToString()
            print("\n[3.4] CLIENT SENDING\t",marshalled_client_res)
            marshalled_client_res_encrypted=self.EncryptAndProtectMessage(marshalled_client_res)
            print("\n[3.5] CLIENT SENDING\t")
            client_res_payload = gpbf.Payload()
            client_res_payload.load = marshalled_client_res_encrypted
            client_res_payload.type = "AUTH"
            client_res_payload.authMessageType = "clientResponse"

            send_marshalled_client_res = client_res_payload.SerializeToString()
            print("\n[3.9] CLIENT SENDING\t ", send_marshalled_client_res)

            # SET SESSION KEY----------------------------------------
            hashed_session_key = hashlib.sha256()
            hashed_session_key.update(str(session_key).encode())
            skey=hashed_session_key.digest()
            self.SetSessionKey(skey)
            print("[X] CLIENT BYTE CASTED STRING", self._key, "\n")
            #--------------------------------------------------------
            print("---------------------AUTH DONE---------------------")

            return True,send_marshalled_client_res
        elif mode.get() == 1:

            if messagePayload.authMessageType=="clientChallenge":
                print("\n[1] recived AS SERVER \n", messagePayload)
                rcvClientChallange = gpbf.ClientChallenge()
                rcvClientChallange.ParseFromString(messagePayload.load)

                # guard clause -----------------------------------------
                if rcvClientChallange.name != "CLIENT":
                    print("[AUTH FAILED] REPLAY ATTACK", rcvClientChallange)
                    return False
                # -------------------------------------------------------

                # Ra,g^b mod p ------------------------------------
                serverResponse_load = gpbf.ServerResponse_load()
                serverResponse_load.name = "SERVER"
                serverResponse_load.ra = rcvClientChallange.ra
                serverResponse_load.diffie_hellman_public_key = str(self.dh.getPublicKey())
                load = serverResponse_load.SerializeToString()
                # -------------------------------------------------------

                # E(Ra,g^b mod p,K) ------------------------------------
                encrypted_load = self.EncryptAndProtectMessage(load)
                # -------------------------------------------------------

                # Ra,E(Ra,g^b mod p,K) ------------------------------------
                serverResponse_shell = gpbf.ServerResponse_shell()
                self.rb = str(uuid.uuid1())
                serverResponse_shell.rb = self.rb
                serverResponse_shell.load = encrypted_load
                # -------------------------------------------------------

                marshalled_server_res = serverResponse_shell.SerializeToString()

                res_Payload = gpbf.Payload()
                res_Payload.load = marshalled_server_res
                res_Payload.type = "AUTH"
                res_Payload.authMessageType = "serverResponse"
                marshalled_res = res_Payload.SerializeToString()
                print("\n [1] SENDING AS SERVER \n", marshalled_res)
                return True,marshalled_res

            elif messagePayload.authMessageType == "clientResponse":
                print("[4] SERVER recived client response", messagePayload)

                # Decrypt and check Ra=Self.Ra && name=SERVER ----------
                rcvClientResLoad = gpbf.ClientResponse()
                print("[4.1] SERVER decrypted client")
                rcvClientResLoad_Encrypted = messagePayload.load
                print("[4.2] SERVER decrypted client")
                rcvClientResLoad_Decrypted =self.DecryptAndVerifyMessage(rcvClientResLoad_Encrypted)
                print("[4.3] SERVER decrypted client")
                rcvClientResLoad.ParseFromString(rcvClientResLoad_Decrypted)
                print("[4.5] SERVER decrypted client response",rcvClientResLoad_Decrypted)
                # guard clause -----------------------------------------
                if rcvClientResLoad.name != "CLIENT":
                    print("[AUTH FAILED] REPLAY ATTACK", rcvClientResLoad)
                    return False
                if rcvClientResLoad.rb != self.rb:
                    print("[AUTH FAILED] Rb!=sent Rb", rcvClientResLoad)
                    return False
                # -------------------------------------------------------

                # calculate session key ---------------------------------
                g_a_mod_p = int(rcvClientResLoad.diffie_hellman_public_key)
                self.dh.update(g_a_mod_p)
                session_key = self.dh.getFinalKey()
                print("\n[4] SERVER SESSION KEY IS\t ", session_key)
                # -------------------------------------------------------

                # SET SESSION KEY----------------------------------------
                hashed_session_key = hashlib.sha256()
                hashed_session_key.update(str(session_key).encode())
                skey = hashed_session_key.digest()
                self.SetSessionKey(skey)
                print("[X] SERVER BYTE CASTED STRING", self._key, "\n")
                # --------------------------------------------------------

                print("---------------------AUTH DONE---------------------")
                return False
        else:
            print("\n[1] recived AS NONE \n", messagePayload)

        return False

    def GetEncryptedMessage(self, text):
        generalMessage = gpbf.GeneralMessage()
        generalMessage.load = text
        marshalled_generalMessage=generalMessage.SerializeToString()
        generalMessage_encrypted = self.EncryptAndProtectMessage(marshalled_generalMessage)
        payload = gpbf.Payload()
        payload.load = generalMessage_encrypted
        payload.type = "MSG"
        payload.authMessageType = "generalMessage"
        marshalled_payload=payload.SerializeToString()
        return marshalled_payload

    def GetDecryptedMessage(self, payload_text):
        payload = gpbf.Payload()
        payload.ParseFromString(payload_text)
        generalMessage = gpbf.GeneralMessage()
        encrypted_load=payload.load
        decrypted_load=self.DecryptAndVerifyMessage(encrypted_load)
        generalMessage.ParseFromString(decrypted_load)
        text=generalMessage.load
        return text

