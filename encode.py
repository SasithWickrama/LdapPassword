import hashlib
import base64
import os

def hash_generate(password_text):
    salt = os.urandom(8)
    hashed_password = hashlib.sha1(password_text.encode('utf-8') + salt).digest()
    final_hash = base64.b64encode(hashed_password + salt).decode('utf-8')
    return "{SSHA}" + final_hash

# Example usage
password_text = "Cen#2339542"
ldap_hash = hash_generate(password_text)
print(ldap_hash)