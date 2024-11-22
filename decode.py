import base64
import hashlib

def ssha_check(text, hashed_password):
    ohash = base64.b64decode(hashed_password[6:])
    osalt = ohash[20:]
    ohash = ohash[:20]
    
    nhash = hashlib.sha1(text.encode('utf-8') + osalt).digest()
    
    return ohash == nhash

# Example usage
user_provided_password = "Sagara#563"
ldap_hash_from_ldap = "{SSHA}GWsC6DIGem3Gud5Is2GdyCaZFgbB9ISRgua5sg=="

result = ssha_check(user_provided_password, ldap_hash_from_ldap)
print(result)
