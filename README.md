# Lab4--Criptografia

# Proyecto de Cifrado Simétrico con DES, AES-256 y 3DES

Este proyecto implementa un programa en Python que permite cifrar y descifrar textos utilizando los algoritmos de cifrado simétrico **DES**, **AES-256** y **3DES** en modo **CBC**. El programa utiliza la librería **PyCryptodome** para realizar las operaciones criptográficas, y se asegura de que los datos tengan la longitud correcta mediante el uso de padding **PKCS#7**.

## Librerías Requeridas

Este proyecto depende de la librería **PyCryptodome**. Para instalarla, ejecuta el siguiente comando:

```bash
pip install pycryptodome
````
## Ejemplo de uso
Lo siguiente es ejecutar el archivo Lab4.py e ingresar los datos como el ejemplo a continuación:
```bash
Ingrese la clave (8 bytes para DES, 32 bytes para AES-256, 24 bytes para 3DES):
mi_clave_1234

Ingrese el vector de inicialización (IV) (8 bytes para DES, 16 bytes para AES-256, 8 bytes para 3DES):
mi_iv_1234

Ingrese el texto a cifrar:
Texto a cifrar de ejemplo


Cifrado y Descifrado con DES:
Texto Cifrado con DES (hex): ec712d3049cc770c0a126fa70c3c9a684761dc8ea5433d5deb444bd6ec8df401
Texto Descifrado con DES: Texto a cifrar de ejemplo

Cifrado y Descifrado con AES:
Texto Cifrado con AES (hex): f34fbee3d3a902059dc61480c54652ed52c8541f5e441464225a2dbea7ac74d4
Texto Descifrado con AES: Texto a cifrar de ejemplo

Cifrado y Descifrado con 3DES:
Texto Cifrado con 3DES (hex): 556c571b31712b98ffbb8246280403d21fbb758ecd59cea62087b1a89b298ad0
Texto Descifrado con 3DES: Texto a cifrar de ejemplo
