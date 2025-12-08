import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ============================================================================
# GESTOR DE CRIPTOGRAFÍA (EL CEREBRO MATEMÁTICO)
# ============================================================================
# Esta clase es la que sabe hacer todos los trucos de magia (cifrar y descifrar).
# No sabe nada de botones ni ventanas, solo sabe transformar texto.

class CryptoManager:
    """
    Clase que maneja toda la lógica de cifrado y descifrado.
    """
    
    # === 1. Cifrado César (El más antiguo) ===
    # Imagina una rueda con el abecedario. Si la giras 'desplazamiento' veces,
    # la 'A' se convierte en otra letra. Eso es el cifrado César.
    
    def cifrar_cesar(self, texto, desplazamiento):
        """
        Aplica el cifrado César.
        """
        resultado = ""
        for char in texto:
            # Solo transformamos letras (A-Z, a-z). Los números y símbolos se quedan igual.
            if char.isalpha():
                # 'ascii_offset' es el número donde empieza el abecedario en el ordenador.
                # 'A' es 65, 'a' es 97.
                ascii_offset = 65 if char.isupper() else 97
                
                # Aquí está la magia matemática:
                # 1. (ord(char) - ascii_offset): Convertimos la letra en un número del 0 al 25.
                # 2. + desplazamiento: Le sumamos los pasos que queremos movernos.
                # 3. % 26: Si nos pasamos de la 'Z', volvemos a empezar por la 'A' (como un reloj).
                # 4. + ascii_offset: Convertimos el número de vuelta a una letra de ordenador.
                nuevo_char = chr((ord(char) - ascii_offset + desplazamiento) % 26 + ascii_offset)
                resultado += nuevo_char
            else:
                resultado += char
        return resultado

    def descifrar_cesar(self, texto, desplazamiento):
        """
        Descifra el cifrado César.
        El truco es simple: si para cifrar sumamos, para descifrar restamos.
        """
        return self.cifrar_cesar(texto, -desplazamiento)

    # === 2. ROT13 (El César especial) ===
    # Es un caso especial del César donde movemos exactamente 13 posiciones.
    # Como el abecedario inglés tiene 26 letras, si lo haces dos veces vuelves al principio.
    # (13 + 13 = 26). Por eso cifrar y descifrar es la misma función.
    
    def rot13(self, texto):
        """
        Aplica ROT13 (César con desplazamiento 13). Es su propio inverso.
        """
        return self.cifrar_cesar(texto, 13)

    # === 3. Transposición Columnar (El rompecabezas) ===
    # Imagina escribir tu mensaje en una cuadrícula, fila por fila,
    # y luego leerlo columna por columna. Eso mezcla las letras de posición.
    
    def transposicion_columnar(self, texto, clave):
        """
        Cifrado por Transposición Columnar simple.
        La clave es un número entero que nos dice cuántas columnas usar.
        """
        n = len(texto)
        columnas = clave
        # Calculamos cuántas filas necesitamos.
        # Es como repartir cartas: si tengo 'n' cartas y 'columnas' montones, ¿cuántas rondas hago?
        filas = (n + columnas - 1) // columnas 
        
        # Si sobran huecos al final, rellenamos con espacios para que la cuadrícula sea perfecta.
        texto_pad = texto.ljust(filas * columnas)
        
        resultado = ""
        # Leemos la cuadrícula columna por columna.
        for c in range(columnas):
            for r in range(filas):
                # Esta fórmula nos dice qué letra toca leer.
                idx = r * columnas + c
                if idx < len(texto_pad):
                    resultado += texto_pad[idx]
        return resultado

    def descifrar_transposicion(self, texto, clave):
        """
        Descifrado por Transposición Columnar.
        Esto es más difícil: tenemos que reconstruir la cuadrícula original.
        """
        columnas = clave
        n = len(texto)
        filas = (n + columnas - 1) // columnas
        
        # Calculamos cuántos huecos vacíos había en la última fila original.
        celdas_vacias = (filas * columnas) - n
        
        resultado = [''] * n
        col = 0
        row = 0
        
        # Vamos rellenando la cuadrícula original "imaginaria" siguiendo el orden de lectura.
        for i in range(n):
            resultado[row * columnas + col] = texto[i]
            row += 1
            # Esta condición complicada maneja el salto a la siguiente columna
            # teniendo en cuenta los huecos vacíos del final.
            if (row == filas) or (row == filas - 1 and col >= columnas - celdas_vacias):
                row = 0
                col += 1
                
        return "".join(resultado).rstrip()

    # === 4. Cifrado Simétrico (AES) - El Candado ===
    # Usamos una única clave (contraseña) para cerrar y abrir el mensaje.
    # Es como un cofre con un candado: quien tiene la llave, puede abrirlo.
    
    def generar_clave_simetrica(self, password):
        """
        Convierte una contraseña normal (ej: "gatito123") en una llave criptográfica segura.
        Usa SHA256 para mezclar la contraseña y obtener siempre 32 bytes exactos.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        key_32_bytes = digest.finalize()
        # La codificamos en base64 para que sea fácil de guardar como texto.
        return base64.urlsafe_b64encode(key_32_bytes)

    def cifrar_simetrico(self, texto, password):
        """
        Cifra usando AES (a través de Fernet, que es una librería segura).
        """
        key = self.generar_clave_simetrica(password)
        f = Fernet(key)
        # .encrypt() convierte el texto en un galimatías de bytes.
        token = f.encrypt(texto.encode())
        return token 

    def descifrar_simetrico(self, token_bytes, password):
        """
        Descifra usando la misma contraseña.
        """
        key = self.generar_clave_simetrica(password)
        f = Fernet(key)
        return f.decrypt(token_bytes).decode()

    # === 5. Cifrado Asimétrico (RSA) - El Buzón ===
    # Tenemos dos claves: una PÚBLICA (el buzón) y una PRIVADA (la llave del buzón).
    # Cualquiera puede meter mensajes en el buzón (usando la clave pública),
    # pero solo el dueño puede sacarlos y leerlos (usando la clave privada).
    
    def generar_par_claves_rsa(self):
        """
        Fabrica un par de claves RSA nuevas y seguras (2048 bits).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, # Un número primo estándar para RSA.
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serializar_clave_privada(self, private_key):
        """
        Convierte la clave privada (que es un objeto matemático complejo)
        en un bloque de texto que podemos guardar en un archivo (.pem).
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # ¡Cuidado! Aquí no la estamos protegiendo con contraseña extra.
        )

    def serializar_clave_publica(self, public_key):
        """
        Lo mismo, pero para la clave pública.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def cifrar_asimetrico(self, texto, public_key_pem):
        """
        Cifra usando un esquema Híbrido (RSA + AES).
        ¿Por qué híbrido? Porque RSA es muy lento para mensajes largos.
        
        La estrategia es:
        1. Inventamos una clave simétrica (AES) aleatoria y rápida para este mensaje.
        2. Ciframos el mensaje largo con esa clave rápida.
        3. Ciframos la clave rápida usando RSA (que es lento pero seguro).
        4. Guardamos todo junto: [Clave Cifrada] + [Mensaje Cifrado].
        """
        # 1. Generar clave simétrica aleatoria
        sim_key = Fernet.generate_key()
        
        # 2. Cifrar texto con clave simétrica
        f = Fernet(sim_key)
        texto_cifrado_sim = f.encrypt(texto.encode())
        
        # 3. Cifrar clave simétrica con RSA
        public_key = serialization.load_pem_public_key(public_key_pem)
        clave_sim_cifrada = public_key.encrypt(
            sim_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Combinar todo en un solo paquete de bytes
        return clave_sim_cifrada + texto_cifrado_sim

    def descifrar_asimetrico(self, ciphertext, private_key_pem):
        """
        Descifra usando esquema Híbrido.
        Hace lo inverso:
        1. Separa la clave cifrada del mensaje cifrado.
        2. Usa RSA (clave privada) para recuperar la clave simétrica.
        3. Usa la clave simétrica recuperada para leer el mensaje.
        """
        # Sabemos que la clave RSA cifrada siempre ocupa 256 bytes (para claves de 2048 bits).
        block_size = 256
        
        if len(ciphertext) < block_size:
            raise ValueError("El archivo es demasiado corto para ser un cifrado híbrido válido.")
            
        clave_sim_cifrada = ciphertext[:block_size]
        texto_cifrado_sim = ciphertext[block_size:]
        
        # 1. Descifrar clave simétrica con RSA
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        sim_key = private_key.decrypt(
            clave_sim_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Descifrar texto con clave simétrica
        f = Fernet(sim_key)
        return f.decrypt(texto_cifrado_sim).decode()
