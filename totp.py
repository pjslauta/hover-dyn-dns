import base64
import hmac
import hashlib
import struct
import time

def totp(secret, time_step=30, digits=6):
    # Decode base32 secret
    secret = secret.upper()
    secret = secret.replace(' ','')
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    key = base64.b32decode(secret, casefold=True)
    # Get current time step
    current_time = int(time.time() // time_step)
    # Pack time into byte array (big-endian)
    time_bytes = struct.pack(">Q", current_time)
    # Generate HMAC-SHA1
    hmac_result = hmac.new(key, time_bytes, hashlib.sha1).digest()
    # Extract dynamic binary code
    offset = hmac_result[-1] & 0x0F
    binary = struct.unpack(">I", hmac_result[offset:offset + 4])[0] & 0x7FFFFFFF
    # Compute TOTP value
    otp = binary % (10 ** digits)
    return f"{otp:0{digits}d}"