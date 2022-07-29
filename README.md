

# Password encrypted TOTP

Imports used:
	import sys
	import segno
	import secrets
	import string
	import time
	import math
	import hmac
	import hashlib
	import base64
	import struct
	import os
	from cryptography.fernet import Fernet
	from cryptography.hazmat.primitives import hashes
	from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

## Steps

1 - Run the following command to generate an encrypted qr code:   
    
    [py | python] totp.py --generate-qr -p <password>


2 - Run the following command to decrypt secret and get a OTP:   
    
    [py | python] totp.py --get-otp -p <password>


Implementation tldr:

First, a QR code is generated with a password in step 1. The 
password is required to encrypt the secret given to GA. There 
is no option to get a QR code generated that is unencrypted.

The secret is stored in 'secret.txt' as encrypted text.

When step 2 is run to receive a OTP, the correct password must
be given, otherwise the account will not be authenticated.

