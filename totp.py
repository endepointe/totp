'''
CS370
TOTP
Alvin Johns

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/fernet/
# segno.readthedocs.io/en/stable/comparison-qrcode-libs.html
# otpauth://type/label?parameters
# otpauth://totp/Example:alice@google.com?secret=<sk_key>&issuer=Example
'''

import sys
import segno
import string
import time
import math
import hmac
import hashlib
import base64
import struct
import os
# using due to warning label at:
# https://docs.python.org/3/library/random.html
import secrets 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# create hmac-sha1 signature
def hotp(secret,time_step):
  #print("secret: ", secret)
  key = base64.b32decode(secret, False)
  #print("key: ", key)
  msg = struct.pack(">Q", time_step)
  #print("msg: ", msg)
  h = hmac.new(key,msg,hashlib.sha1).digest()
  #print("h: ", h)
  o = h[19] & 15
  #print("o: ", o)
  #print("h[o:o+4]: ", h[o:o+4])
  #print("struct.unpack('>I',h[o:o+4])[0]",(struct.unpack(">I", h[o:o+4])[0]))
  #print("struct.unpack('>I',h[o:o+4])[0]",(struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000)
  h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
  #print("h: ", h)
  return h

# low probability bug where hotp() returns a string < 6.
# fix: prepend with 0 and if still less than 6, append a 0.
#   Other option is to disregard the shorter key until a new
#   code is generated during the next 30second cycle.
def totp(secret):
  x = str(hotp(secret, time_step=int(time.time())//30))
  if len(x) < 6:
    x = '0' + x
    if len(x) < 6:
      x = x + '0'
  return x

def generate_secret(size):
  base64 = string.ascii_uppercase + '234567'
  sk = ''.join([secrets.choice(base64) for n in range(size)])
  return str(sk)

def save_secret(s):
  f = open("secret.txt", "wb")
  f.write(s)
  f.close()

def read_secret():
  f = open("secret.txt","rb")
  secret = f.read()
  f.close()
  return secret

def encrypt_secret(s,p):
  salt = os.urandom(16) 
  #save salt
  salt_file = open("salt.txt","wb")
  salt_file.write(salt)
  salt_file.close()
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  ) 
  key = base64.urlsafe_b64encode(kdf.derive(p))
  f = Fernet(key)
  return f.encrypt(s)

def decrypt_secret(p):
  salt_file = open('salt.txt', 'rb')
  salt = salt_file.read()
  salt_file.close()
  enc_content = read_secret()
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  )
  key = base64.urlsafe_b64encode(kdf.derive(p))
  f = Fernet(key)
  dec_content = f.decrypt(enc_content)
  return dec_content

try:
  if sys.argv[1] == '--generate-qr':
    secret = generate_secret(16)
    #encrypt secret
    password = bytes(sys.argv[3], 'UTF-8')
    enc_token = encrypt_secret(bytes(secret,'UTF-8'),password)
    save_secret(enc_token)
    msg_uri = "otpauth://totp/Example:all@things.com?secret="
    msg_uri += secret
    msg_uri += "&issuer=Example"
    qrcode = segno.make(msg_uri)
    qrcode.save("otp.svg",scale=10)
    qrcode.save("otp.png",scale=10)
    print("QR code generated at otp.svg and otp.png")
    exit(0)
  elif sys.argv[1] == '--get-otp':
    password = bytes(sys.argv[3], 'UTF-8') 
    while True:
      print("Code valid for 30 seconds:",totp(decrypt_secret(password)))
      time.sleep(30)
except (IndexError):
  print("Valid parameters: [--generate-qr, --get-otp]") 
except (KeyboardInterrupt):
  print("\nQuiting...")
  exit(0)

