from hashlib import sha256
from base64 import b64decode, b64encode

def prefs_to_aes(prefs_key):
    # Split in two the key in the preferences and add the strange text here
    key = prefs_key[0:len(prefs_key)/2]
    key += "a!k@ES2,g86AX&D8vn2]"
    key += prefs_key[len(prefs_key)/2:]

    # Hash the text to a sha256 fingerprint -> resulting key always 256 bit
    key_hash = sha256()
    key_hash.update(key)

    return key_hash.digest()

def b64decode_no_padding(string):
    pad = len(string) % 4
    string += "=" * pad
    return b64decode(string)


# def decrypt(value, key):
#     print("ENCRYPTED %s " % value)
#     value = b64decode_no_padding(value)
#     iv = value[len(value)-16:]
#     cypher_text = value[:len(value)-16]
#     # iv = value[:16]
#     # cypher_text = value[16:]
#     print("IV: %s , len: %d - Cyphertext: %s, len: %d" % (iv, len(iv), cypher_text, len(cypher_text)))
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted = cipher.decrypt(cypher_text)
#     print("DECRYPTED: %s \n" % decrypted)
#     return decrypted