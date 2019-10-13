import hashlib
import base64
import urllib.parse
import os
#from cryptography.hazmat.primitives.ciphers import algorithms,modes
#from cryptography.hazmat.primitives.ciphers.algorithms import AES
#from cryptography.hazmat.primitives.ciphers.modes import CBC,ECB
from Crypto.Cipher import AES,Blowfish,DES,DES3,CAST





def decrypt_aescbc(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(enc)



def decrypt_aesecb(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(enc)

def decrypt_blowfishcbc(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return cipher.decrypt(enc)
def decrypt_blowfishecb(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.decrypt(enc)

def decrypt_descbc(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(enc)
def decrypt_desecb(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(enc)

def decrypt_des3cbc(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    iv  = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(enc)
def decrypt_des3ecb(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.decrypt(enc)

def decrypt_castcbc(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    cipher = CAST.new(key, CAST.MODE_CBC, iv)
    return cipher.decrypt(enc)
def decrypt_castecb(enc, pwd,salt,keylen):
    key = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    cipher = CAST.new(key, CAST.MODE_ECB)
    return cipher.decrypt(enc)

def gamma (enc, pwd, salt, keylen):
    gamma = hashlib.pbkdf2_hmac("SHA1", pwd.encode('utf-8'), salt.encode('utf-8'), 1024, keylen)
    decrypt = b""
    for i in range(len(enc)):
        decrypt += (enc[i] ^ gamma[i % keylen]).to_bytes(1, byteorder="big")
    return decrypt


def output_bad_string(file_output, byte_str):
    try:
        file_output.write(byte_str.decode("utf-8") + '\n')
    except BaseException:
        file_output.write("utf-8 fail" + '\n')
    try:
        file_output.write(byte_str.decode("cp1251") + '\n')
    except BaseException:
        file_output.write("cp1251 fail" + '\n')
    try:
        file_output.write(byte_str.decode("utf-16") + '\n')
    except BaseException:
        file_output.write("utf-16 fail" + '\n')
    try:
        file_output.write(byte_str.decode("utf-32") + '\n\n')
    except BaseException:
        file_output.write("utf-32 fail" + '\n\n')




def execute(decryptor,token_byte, keylen):
    f = open(str(decryptor).split(' ')[1]+str(keylen), "w")
    # patterns of success decrypt
    flag1h = "".join("{:02x}".format(ord(c)) for c in "flag")
    flag2h = "".join("{:02x}".format(ord(c)) for c in "Flag")
    flag3h = "".join("{:02x}".format(ord(c)) for c in "FLAG")
    paddings = []
    for i in range(10):
        paddings.append(("0"+str(i))*i)
    paddings.append(("0" + "a") * 10)
    paddings.append(("0" + "b") * 11)
    paddings.append(("0" + "c") * 12)
    paddings.append(("0" + "d") * 13)
    paddings.append(("0" + "e") * 14)
    paddings.append(("0" + "f") * 15)

    # construct salt
    salts = [(b'\x00' * 16).decode("utf-8"),"salt","SALT","s","S","empty","Empty","EMPTY","AES","aes", "", "0", b"\x00".decode("utf-8"), "Token", "token", "TOKEN", "default", "DEFAULT", "sha1", "SHA1", "sha-1",
                     "SHA-1", "pbkdf2", "PBKDF2", "1024", "PBKDF2withHmacSHA1", "1234567890", "0123456789", "31337","16","nothing","Nothing","NOTHING","any",
             "ANY","Any","anything","Anything","ANYTHING"]
    for i in range(80,97):
        salts.append(str(i))
    salts.extend(paddings)

   # pin str
    for i in range(10000):
        pwd = str(i).zfill(4)

        os.system('clear')
        print("sampling pin - " + str(i))

        for salt in salts:
            token_decrypt = decryptor(token_byte, pwd, salt, keylen)
            token_decrypt_hex = token_decrypt.hex()
            # find flags
            if(token_decrypt_hex.find(flag1h)!=(-1)):
                f.write("\nflag" + pwd + ' ' + salt + ' ' + token_decrypt_hex + '\n')
                #output_bad_string(f,token_decrypt)
            if(token_decrypt_hex.find(flag2h)!=(-1)):
                f.write("\nFlag " + pwd + ' ' + salt + ' ' + token_decrypt_hex + '\n')
                #output_bad_string(f, token_decrypt)
            if(token_decrypt_hex.find(flag3h)!=(-1)):
                f.write("\nFLAG " + pwd + ' ' + salt + ' ' + token_decrypt_hex + '\n')
                #output_bad_string(f, token_decrypt)
            # find padding from 3
            for i in range(3,16):
                if(token_decrypt_hex[-i * 2:]==paddings[i]):
                    f.write("\n"+paddings[i]+" " + pwd + ' ' + salt + ' ' + token_decrypt_hex + '\n')
                    #output_bad_string(f, token_decrypt)
    f.close()


def main():
    token = "cWKz2Ajf8LPntPBqGdwIZT-3TxXKw40wCahYJRPGKzWzz2mHacBCTnoy43LOc1bZ0OoaVK734Azc_LsQd--Hl_VI_tCjF4-67-7-frheoK5m5ViaShI9n--nfAex2Jin"
    token_byte = base64.urlsafe_b64decode(token)

    execute(decrypt_aescbc, token_byte, 16)
    execute(decrypt_aescbc, token_byte, 24)
    execute(decrypt_aescbc, token_byte, 32)
    #execute(decrypt_aesecb, token_byte, 16)
    #execute(decrypt_aesecb, token_byte, 24)
    #execute(decrypt_aesecb, token_byte, 32)
    #execute(decrypt_blowfishcbc, token_byte, 56)
    #execute(decrypt_blowfishecb, token_byte, 56)
    '''
    for i in range(1, 97):
        execute(gamma, token_byte, i)
    '''
    #execute(decrypt_descbc, token_byte, 8)
    #execute(decrypt_desecb, token_byte, 8)
    #execute(decrypt_des3cbc, token_byte, 24)
    #execute(decrypt_des3ecb, token_byte, 24)
    #execute(decrypt_castcbc, token_byte, 16)
    #execute(decrypt_castecb, token_byte, 16)



if __name__=="__main__":
    main()
