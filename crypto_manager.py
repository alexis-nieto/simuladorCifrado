import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class CryptoManager:
    """
    Clase que maneja toda la lógica de cifrado y descifrado.
    """
    
    def cifrar_cesar(self, texto, desplazamiento):
        """
        Aplica el cifrado César.
        """
        resultado = ""
        for char in texto:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                # Fórmula: (caracter - base + desplazamiento) % 26 + base
                nuevo_char = chr((ord(char) - ascii_offset + desplazamiento) % 26 + ascii_offset)
                resultado += nuevo_char
            else:
                resultado += char
        return resultado

    def descifrar_cesar(self, texto, desplazamiento):
        """
        Descifra el cifrado César (invierte el desplazamiento).
        """
        return self.cifrar_cesar(texto, -desplazamiento)

    def rot13(self, texto):
        """
        Aplica ROT13 (César con desplazamiento 13). Es su propio inverso.
        """
        return self.cifrar_cesar(texto, 13)

    def transposicion_columnar(self, texto, clave):
        """
        Cifrado por Transposición Columnar simple.
        La clave es un número entero que representa el número de columnas.
        """
        n = len(texto)
        columnas = clave
        filas = (n + columnas - 1) // columnas # Techo de n/columnas
        
        # Rellenar con espacios si es necesario para completar la cuadrícula
        texto_pad = texto.ljust(filas * columnas)
        
        resultado = ""
        for c in range(columnas):
            for r in range(filas):
                idx = r * columnas + c
                if idx < len(texto_pad):
                    resultado += texto_pad[idx]
        return resultado

    def descifrar_transposicion(self, texto, clave):
        """
        Descifrado por Transposición Columnar.
        """
        columnas = clave
        n = len(texto)
        filas = (n + columnas - 1) // columnas
        
        # Calcular cuántas celdas vacías hay en la última fila
        celdas_vacias = (filas * columnas) - n
        
        resultado = [''] * n
        col = 0
        row = 0
        
        for i in range(n):
            resultado[row * columnas + col] = texto[i]
            row += 1
            if (row == filas) or (row == filas - 1 and col >= columnas - celdas_vacias):
                row = 0
                col += 1
                
        return "".join(resultado).rstrip()

    def generar_clave_simetrica(self, password):
        """
        Genera una clave Fernet válida a partir de una contraseña.
        Usa SHA256 para asegurar 32 bytes y luego base64.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        key_32_bytes = digest.finalize()
        return base64.urlsafe_b64encode(key_32_bytes)

    def cifrar_simetrico(self, texto, password):
        """
        Cifra usando AES (Fernet).
        """
        key = self.generar_clave_simetrica(password)
        f = Fernet(key)
        token = f.encrypt(texto.encode())
        return token # Devuelve bytes

    def descifrar_simetrico(self, token_bytes, password):
        """
        Descifra usando AES (Fernet).
        """
        key = self.generar_clave_simetrica(password)
        f = Fernet(key)
        return f.decrypt(token_bytes).decode()

    def generar_par_claves_rsa(self):
        """
        Genera un par de claves RSA de 2048 bits.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serializar_clave_privada(self, private_key):
        """
        Convierte la clave privada a formato PEM.
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serializar_clave_publica(self, public_key):
        """
        Convierte la clave pública a formato PEM.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def cifrar_asimetrico(self, texto, public_key_pem):
        """
        Cifra usando RSA y la clave pública.
        """
        public_key = serialization.load_pem_public_key(public_key_pem)
        ciphertext = public_key.encrypt(
            texto.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def descifrar_asimetrico(self, ciphertext, private_key_pem):
        """
        Descifra usando RSA y la clave privada.
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
