import hashlib
import pyDHE as dh

tesdh=dh.new()
key=tesdh.getPublicKey()
skey=str(key);
skey=skey.encode()
print(skey)
m = hashlib.sha256()
m.update(skey)
val=m.digest()
print("hashed key",val)
