from Crypto.Cipher import DES, AES, DES3
import Crypto.Util.Padding


def DESenc(k, v, msg):
    
    print("\n\nDES:\n")

    #clave tiene que ser de largo 8 bytes
    if len(k) < 8:
        pad = Crypto.Random.get_random_bytes(8-len(k))
        clave = k + pad
    else:
        clave = k[:8]

    #mensaje tiene que tener longitud multiplo de 8 bytes
    if not len(msg)%8 == 0:
        mensaje = Crypto.Util.Padding.pad(msg, 8)
    else:
        mensaje = msg

    #vector tiene que ser de largo 8 bytes
    if len(v) < 8:
        pad = Crypto.Random.get_random_bytes(8-len(v))
        vector = v + pad
    else:
        vector = v[:8]
    
    print(f"Clave:{clave}\nvector:{vector}")

    cipher = DES.new(clave, DES.MODE_CBC, vector)

    encriptado = cipher.encrypt(mensaje)

    cipher = DES.new(clave, DES.MODE_CBC, vector)

    desencriptado = cipher.decrypt(encriptado).decode()
    print(f"\nMensaje original: {msg.decode()}\nMensaje encriptado (HEX): {encriptado.hex()}\nMensaje desencriptado: {desencriptado}")


def DES3enc(k, v, msg):
    
    print("\n\n3DES:\n")

    #clave tiene que ser de largo 16 o 24 bytes
    if len(k) < 16:
        pad = Crypto.Random.get_random_bytes(16-len(k))
        clave = k + pad
    elif len(k) >24:
        clave = k[:24]
    else:
        clave = k[:16]


    #mensaje tiene que tener longitud multiplo de 8 bytes
    if not len(msg)%8 == 0:
        mensaje = Crypto.Util.Padding.pad(msg, 8)
    else:
        mensaje = msg

    #vector tiene que ser de largo 8 bytes
    if len(v) < 8:
        pad = Crypto.Random.get_random_bytes(8-len(v))
        vector = v + pad
    else:
        vector = v[:8]
    

    print(f"Clave:{clave}\nvector:{vector}")

    cipher = DES3.new(clave, DES3.MODE_CBC, vector)

    encriptado = cipher.encrypt(mensaje)

    cipher = DES3.new(clave, DES3.MODE_CBC, vector)

    desencriptado = cipher.decrypt(encriptado).decode()
    print(f"\nMensaje original: {msg.decode()}\nMensaje encriptado (HEX): {encriptado.hex()}\nMensaje desencriptado: {desencriptado}")

def AESenc(k, v, msg):
    print("\n\nAES:\n")

    #clave tiene que ser de largo 16, 24 o 32 bytes
    if len(k) < 16:
        pad = Crypto.Random.get_random_bytes(16-len(k))
        clave = k + pad
    elif len(k) >32:
        clave = k[:32]
    elif len(k) >24:
        clave = k[:24]
    else:
        clave = k[:16]


    #mensaje tiene que tener longitud multiplo de 16 bytes
    if not len(msg)%16 == 0:
        mensaje = Crypto.Util.Padding.pad(msg, 16)
    else:
        mensaje = msg

    #vector tiene que ser de largo 16 bytes
    if len(v) < 16:
        pad = Crypto.Random.get_random_bytes(16-len(v))
        vector = v + pad
    else:
        vector = v[:16]
    

    print(f"Clave:{clave}\nvector:{vector}")

    cipher = AES.new(clave, AES.MODE_CBC, vector)

    encriptado = cipher.encrypt(mensaje)

    cipher = AES.new(clave, AES.MODE_CBC, vector)

    desencriptado = cipher.decrypt(encriptado).decode()
    print(f"\nMensaje original: {msg.decode()}\nMensaje encriptado (HEX): {encriptado.hex()}\nMensaje desencriptado: {desencriptado}")


try:
    key = input("Ingrese key para los 3 algoritmos\n").encode()
    iv = input("Ingrese vector inicializador para los 3 algoritmos\n").encode()
    message = input("Ingrese mensaje para los 3 algoritmos\n").encode()
except:
    print("Ingrese valores validos")

DESenc(key, iv, message)

DES3enc(key, iv, message)

AESenc(key, iv, message)