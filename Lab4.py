from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Función para ajustar la clave de 3DES
def ajustar_clave_3des(clave_base, clave_3des_guardada=None):
    tamano_clave = 24  # 3DES requiere una clave de 24 bytes (3 claves de 8 bytes)
    
    if clave_3des_guardada:
        # Reutilizar clave completa guardada
        print(f"Reutilizando clave guardada para 3DES: {clave_3des_guardada.hex()}")
        return clave_3des_guardada, None

    # Truncar la clave base a 24 bytes si es más larga
    clave_base = clave_base[:tamano_clave]

    # Si la clave base es más corta, la completamos aleatoriamente
    if len(clave_base) < tamano_clave:
        parte_aleatoria = get_random_bytes(tamano_clave - len(clave_base))
    else:
        parte_aleatoria = b''

    clave_completa = clave_base + parte_aleatoria

    # Ajustamos la paridad de las tres claves de 8 bytes
    clave_completa = DES3.adjust_key_parity(clave_completa)  # Ajuste de paridad para 3DES

    print(f"Clave ajustada para 3DES: {clave_completa.hex()}")  # Ver cómo quedó la clave
    return clave_completa, parte_aleatoria

# Solicitar datos desde la terminal
def solicitar_datos():
    print("Ingrese la clave (8 bytes para DES, 32 bytes para AES-256, 24 bytes para 3DES):")
    clave = input().encode()  
    print("Ingrese el vector de inicialización (IV) (8 bytes para DES, 16 bytes para AES-256, 8 bytes para 3DES):")
    iv = input().encode()
    print("Ingrese el texto a cifrar:")
    texto = input().encode()
    return clave, iv, texto

# Ajuste de la clave para todos los algoritmos
def ajustar_clave(clave, algoritmo, clave_3des_guardada=None):
    if algoritmo == 'DES':
        tamano_clave = 8
    elif algoritmo == 'AES':
        tamano_clave = 32
    elif algoritmo == '3DES':
        return ajustar_clave_3des(clave, clave_3des_guardada)

    if len(clave) < tamano_clave:
        clave = clave + b'\0' * (tamano_clave - len(clave))
    elif len(clave) > tamano_clave:
        clave = clave[:tamano_clave]

    print(f"Clave ajustada para {algoritmo}: {clave.hex()}")
    return clave, None

# Ajuste del IV para los algoritmos
def ajustar_iv(iv, algoritmo):
    if algoritmo == 'AES':
        tamano_iv = 16
    elif algoritmo in ['DES', '3DES']:
        tamano_iv = 8
    else:
        tamano_iv = 8  

    if len(iv) < tamano_iv:
        iv = iv + b'\0' * (tamano_iv - len(iv))
    elif len(iv) > tamano_iv:
        iv = iv[:tamano_iv]

    print(f"IV ajustado para {algoritmo}: {iv.hex()}")
    return iv

# Función de cifrado
def cifrar(texto, clave, iv, algoritmo, clave_3des_guardada=None):
    iv = ajustar_iv(iv, algoritmo)
    clave, parte_aleatoria = ajustar_clave(clave, algoritmo, clave_3des_guardada)

    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
        texto_cifrado = cipher.encrypt(pad(texto, 8, style='pkcs7'))  # PKCS#7 para DES
    elif algoritmo == 'AES':
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        texto_cifrado = cipher.encrypt(pad(texto, 16, style='pkcs7'))  # PKCS#7 para AES
    elif algoritmo == '3DES':
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        texto_cifrado = cipher.encrypt(pad(texto, 8, style='pkcs7'))  # PKCS#7 para 3DES

    return texto_cifrado, clave, parte_aleatoria

# Función de descifrado
def descifrar(texto_cifrado, clave, iv, algoritmo, clave_3des_guardada=None):
    iv = ajustar_iv(iv, algoritmo)
    clave, _ = ajustar_clave(clave, algoritmo, clave_3des_guardada)

    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
        cipher_decrypt = cipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(cipher_decrypt, 8, style='pkcs7')  # PKCS#7 para DES
    elif algoritmo == 'AES':
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        cipher_decrypt = cipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(cipher_decrypt, 16, style='pkcs7')  # PKCS#7 para AES
    elif algoritmo == '3DES':
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        cipher_decrypt = cipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(cipher_decrypt, 8, style='pkcs7')  # PKCS#7 para 3DES

    return texto_descifrado

# Main program
clave, iv, texto = solicitar_datos()

clave_3des_guardada = None
for algoritmo in ['DES', 'AES', '3DES']:
    print(f"\nCifrado y Descifrado con {algoritmo}:")
    texto_cifrado, clave_ajustada, parte_aleatoria = cifrar(texto, clave, iv, algoritmo, clave_3des_guardada)

    # Guardamos la clave completa ajustada para 3DES para reutilizar en descifrado
    if algoritmo == '3DES':
        clave_3des_guardada = clave_ajustada

    try:
        texto_descifrado = descifrar(texto_cifrado, clave, iv, algoritmo, clave_3des_guardada)
        print(f"Texto Cifrado con {algoritmo} (hex): {texto_cifrado.hex()}")
        print(f"Texto Descifrado con {algoritmo}: {texto_descifrado.decode()}")
    except ValueError:
        print(f"Hubo un problema con el descifrado de {algoritmo}. Usa mismo IV y clave que para cifrado.")
