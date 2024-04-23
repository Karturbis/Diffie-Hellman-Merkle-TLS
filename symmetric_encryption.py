import string
ALPHABET = string.ascii_uppercase



def encrypt(message, key):
    chiffre = ""
    message = message.upper()
    for i in message:
        if not i in ALPHABET:
            continue
        message_number = ALPHABET.index(i)
        message_and_key = (message_number+key) % len(ALPHABET)
        chiffre = chiffre + (ALPHABET[message_and_key])
    return chiffre
    

def decrypt(chiffre, key):
    message = ""
    chiffre = chiffre.upper()
    for i in chiffre:
        chiffre_number = ALPHABET.index(i)
        chiffre_and_key = (chiffre_number-key) % len(ALPHABET)
        message = message + (ALPHABET[chiffre_and_key])
    return message
