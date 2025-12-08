import sys
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, 
    QComboBox, QPushButton, QMessageBox, QInputDialog, 
    QFileDialog, QGroupBox, QFormLayout, QFrame, QLineEdit
)
from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtCore import Qt

from crypto_manager import CryptoManager
from file_manager import guardar_archivo
from utils import validar_texto, limpiar_nombre_archivo

# ============================================================================
# CLASE PRINCIPAL DE LA INTERFAZ (GUI)
# ============================================================================
# Esta clase es como el "cuerpo" de nuestro programa. Define cómo se ve y cómo
# reacciona cuando pulsamos botones.
class EncryptionApp(QWidget):
    def __init__(self):
        # 'super().__init__()' es como llamar al constructor de la clase padre (QWidget).
        # Es necesario para que nuestra ventana funcione correctamente como una ventana de Qt.
        super().__init__()
        
        # Aquí creamos una instancia de nuestro "cerebro" de criptografía.
        # 'self.crypto' tendrá todas las funciones para cifrar y descifrar.
        self.crypto = CryptoManager()
        
        # Llamamos a nuestra función para dibujar todos los botones y textos.
        self.init_ui()

    def init_ui(self):
        """
        Esta función se encarga de poner todos los elementos en la ventana.
        Es como decorar una habitación vacía.
        """
        # Configuramos el título y el tamaño inicial de la ventana.
        self.setWindowTitle("Simulador de Cifrado")
        self.resize(900, 700)
        
        # === Diseño Principal (Layout) ===
        # Usamos un 'QVBoxLayout' (Vertical Box Layout).
        # Imagina una estantería donde ponemos cosas una encima de otra.
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # === Cabecera (Título) ===
        # Creamos una etiqueta (Label) con el título grande.
        title_label = QLabel("Simulador de Cifrado")
        
        # Le ponemos una fuente (letra) grande y en negrita.
        title_font = QFont("Sans Serif", 20, QFont.Weight.Bold)
        title_label.setFont(title_font)
        
        # Centramos el texto.
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Añadimos la etiqueta a nuestra "estantería" principal.
        main_layout.addWidget(title_label)
        
        # Añadimos un poco de espacio vacío debajo del título.
        main_layout.addSpacing(20)

        # === Área de Texto ===
        # Etiqueta para indicar qué es el cuadro de texto.
        input_label = QLabel("Texto de Entrada / Salida:")
        input_label.setFont(QFont("Sans Serif", 12))
        main_layout.addWidget(input_label)

        # Cuadro de texto grande (QTextEdit) donde el usuario escribe.
        self.txt_area = QTextEdit()
        # Usamos una fuente monoespaciada (como las máquinas de escribir) para que
        # las letras se alineen bien (útil para ver patrones en cifrados).
        self.txt_area.setFont(QFont("Monospace", 11))
        main_layout.addWidget(self.txt_area)
        
        # Más espacio vacío.
        main_layout.addSpacing(20)

        # === Panel de Control ===
        # Creamos un grupo (QGroupBox) para agrupar los botones.
        # Es como una cajita dentro de la ventana con un borde y título.
        controls_group = QGroupBox("Panel de Control")
        
        # Dentro de esta cajita, queremos poner las cosas una al lado de la otra.
        # Así que usamos un 'QHBoxLayout' (Horizontal Box Layout).
        controls_layout = QHBoxLayout()
        controls_group.setLayout(controls_layout)
        
        # Añadimos el grupo a la estantería principal.
        main_layout.addWidget(controls_group)

        # Selección de Algoritmo
        algo_label = QLabel("Algoritmo:")
        controls_layout.addWidget(algo_label)

        # Lista desplegable (ComboBox) para elegir el método de cifrado.
        self.combo_algo = QComboBox()
        self.combo_algo.addItems([
            "Cifrado César",
            "ROT13",
            "Transposición Columnar",
            "Simétrico (AES)",
            "Asimétrico (RSA)"
        ])
        self.combo_algo.setMinimumWidth(200)
        controls_layout.addWidget(self.combo_algo)
        
        # Espacio horizontal entre la lista y los botones.
        controls_layout.addSpacing(20)

        # Botones de Acción
        # Botón ENCRIPTAR
        btn_encrypt = QPushButton("ENCRIPTAR")
        # Conectamos el clic del botón a la función 'self.encriptar'.
        # Cuando alguien pulse el botón, se ejecutará esa función.
        btn_encrypt.clicked.connect(self.encriptar)
        controls_layout.addWidget(btn_encrypt)

        # Botón DESENCRIPTAR
        btn_decrypt = QPushButton("DESENCRIPTAR")
        btn_decrypt.clicked.connect(self.desencriptar)
        controls_layout.addWidget(btn_decrypt)

        # Botón LIMPIAR
        btn_clear = QPushButton("LIMPIAR")
        btn_clear.clicked.connect(self.limpiar)
        controls_layout.addWidget(btn_clear)

        # === Barra de Estado ===
        # Una etiqueta pequeña abajo del todo para mostrar mensajes ("Listo", "Encriptando...", etc.)
        self.status_label = QLabel("Listo para operar.")
        # Le damos un estilo "hundido" para que parezca una barra de estado clásica.
        self.status_label.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        # Añadimos un poco de margen interno para que el texto no toque los bordes.
        self.status_label.setContentsMargins(5, 5, 5, 5)
        main_layout.addWidget(self.status_label)

    def set_status(self, msg):
        """Ayuda a cambiar el mensaje de la barra de estado fácilmente."""
        self.status_label.setText(msg)

    def limpiar(self):
        """Borra todo el texto y reinicia el estado."""
        self.txt_area.clear()
        self.set_status("Área de texto limpiada.")

    def obtener_texto(self):
        """Obtiene el texto que el usuario escribió, quitando espacios extra al principio y final."""
        return self.txt_area.toPlainText().strip()

    def encriptar(self):
        """
        Esta es la función principal de ENCRIPTAR.
        Decide qué hacer basándose en qué algoritmo eligió el usuario.
        """
        texto = self.obtener_texto()
        
        # Primero, validamos que haya texto escrito.
        if not validar_texto(texto):
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese texto para encriptar.")
            return

        algo = self.combo_algo.currentText()
        resultado = None
        es_binario = False # Algunos cifrados (AES, RSA) producen datos binarios, no texto normal.
        
        self.set_status(f"Encriptando con {algo}...")

        try:
            # === Lógica para cada algoritmo ===
            
            if algo == "Cifrado César":
                # Pedimos al usuario el número de desplazamiento.
                shift, ok = QInputDialog.getInt(self, "Desplazamiento", "Ingrese el desplazamiento (número entero):")
                if ok:
                    resultado = self.crypto.cifrar_cesar(texto, shift)
            
            elif algo == "ROT13":
                # ROT13 no necesita parámetros extra.
                resultado = self.crypto.rot13(texto)

            elif algo == "Transposición Columnar":
                # Pedimos el número de columnas (clave).
                clave, ok = QInputDialog.getInt(self, "Clave", "Ingrese el número de columnas:")
                if ok and clave > 0:
                    resultado = self.crypto.transposicion_columnar(texto, clave)
                elif ok:
                    QMessageBox.critical(self, "Error", "La clave debe ser mayor a 0.")

            elif algo == "Simétrico (AES)":
                # Pedimos una contraseña.
                pwd, ok = QInputDialog.getText(self, "Contraseña", "Ingrese una contraseña segura:", QLineEdit.EchoMode.Password)
                if ok and pwd:
                    resultado = self.crypto.cifrar_simetrico(texto, pwd)
                    es_binario = True # AES produce bytes, no texto legible.
                    # Guardamos la contraseña en un archivo aparte por seguridad (backup).
                    guardar_archivo(pwd, prefijo="contrasena", extension=".backup.txt")

            elif algo == "Asimétrico (RSA)":
                # Generamos un par de claves nuevas (Pública y Privada).
                priv, pub = self.crypto.generar_par_claves_rsa()
                
                # Convertimos las claves a formato texto (PEM) para guardarlas.
                pub_pem = self.crypto.serializar_clave_publica(pub)
                priv_pem = self.crypto.serializar_clave_privada(priv)

                # Guardamos las claves en archivos.
                guardar_archivo(pub_pem, prefijo="public_key", extension=".pem", es_binario=True)
                guardar_archivo(priv_pem, prefijo="private_key", extension=".pem", es_binario=True)

                # Ciframos el texto usando la clave pública.
                resultado = self.crypto.cifrar_asimetrico(texto, pub_pem)
                es_binario = True
                QMessageBox.information(self, "Claves Generadas", "Se han generado y guardado las claves pública y privada.")

            # === Guardar y Mostrar Resultado ===
            if resultado:
                ext = ".bin" if es_binario else ".txt"
                # Guardamos el resultado en un archivo.
                archivo = guardar_archivo(resultado, prefijo=f"mensaje-encriptado_{limpiar_nombre_archivo(algo)}", extension=ext, es_binario=es_binario)
                
                if archivo:
                    self.txt_area.clear()
                    if not es_binario:
                        # Si es texto, lo mostramos en la pantalla.
                        self.txt_area.setPlainText(resultado)
                    else:
                        # Si es binario (garabatos), solo decimos dónde se guardó.
                        self.txt_area.setPlainText(f"[CONTENIDO BINARIO GUARDADO EN {archivo}]")
                    
                    msg_exito = f"Encriptación exitosa. Guardado en: {archivo}"
                    self.set_status(msg_exito)
                    QMessageBox.information(self, "Éxito", msg_exito)

        except Exception as e:
            # Si algo sale mal, mostramos el error.
            self.set_status("Error en encriptación.")
            QMessageBox.critical(self, "Error de Encriptación", f"Ocurrió un error:\n{e}")

    def desencriptar(self):
        """
        Esta es la función principal de DESENCRIPTAR.
        """
        algo = self.combo_algo.currentText()
        self.set_status(f"Desencriptando con {algo}...")

        try:
            # === Lógica de Desencriptación ===
            
            if algo == "Asimétrico (RSA)":
                # 1. Pedimos el archivo encriptado (.bin).
                QMessageBox.information(self, "Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Archivos Binarios (*.bin)")
                if not file_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(file_path, "rb") as f:
                    contenido = f.read()

                # 2. Pedimos la clave PRIVADA (.pem) para poder abrir el mensaje.
                QMessageBox.information(self, "Seleccionar Clave", "Seleccione la CLAVE PRIVADA (.pem)")
                key_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Clave", "", "Archivos PEM (*.pem)")
                if not key_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(key_path, "rb") as f:
                    key_pem = f.read()

                resultado = self.crypto.descifrar_asimetrico(contenido, key_pem)

            elif algo == "Simétrico (AES)":
                # 1. Pedimos el archivo encriptado.
                QMessageBox.information(self, "Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Archivos Binarios (*.bin)")
                if not file_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(file_path, "rb") as f:
                    contenido = f.read()

                # 2. Pedimos la contraseña.
                pwd, ok = QInputDialog.getText(self, "Contraseña", "Ingrese la contraseña:", QLineEdit.EchoMode.Password)
                if not ok or not pwd:
                    self.set_status("Operación cancelada.")
                    return

                resultado = self.crypto.descifrar_simetrico(contenido, pwd)

            else:
                # === Algoritmos de Texto (César, ROT13, Transposición) ===
                contenido = self.obtener_texto()
                
                # Si no hay texto en pantalla, ofrecemos cargar un archivo.
                if not contenido:
                    QMessageBox.information(self, "Seleccionar Archivo", "El área de texto está vacía. Seleccione un archivo.")
                    file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Archivos de Texto (*.txt);;Todos los archivos (*)")
                    if not file_path:
                        self.set_status("Operación cancelada.")
                        return
                    with open(file_path, "r", encoding="utf-8") as f:
                        contenido = f.read()
                    self.txt_area.setPlainText(contenido)

                if algo == "Cifrado César":
                    # Necesitamos saber cuánto se desplazó originalmente para deshacerlo.
                    shift, ok = QInputDialog.getInt(self, "Desplazamiento", "Ingrese el desplazamiento original:")
                    if ok:
                        resultado = self.crypto.descifrar_cesar(contenido, shift)
                    else:
                        self.set_status("Operación cancelada.")
                        return

                elif algo == "ROT13":
                    resultado = self.crypto.rot13(contenido)

                elif algo == "Transposición Columnar":
                    clave, ok = QInputDialog.getInt(self, "Clave", "Ingrese el número de columnas original:")
                    if ok:
                        resultado = self.crypto.descifrar_transposicion(contenido, clave)
                    else:
                        self.set_status("Operación cancelada.")
                        return
                else:
                    return

            # Mostramos el resultado desencriptado.
            self.txt_area.setPlainText(resultado)
            self.set_status("Desencriptación completada con éxito.")
            QMessageBox.information(self, "Listo!!!", "Desencriptación completada con éxito.")

        except Exception as e:
            self.set_status("Error en desencriptación.")
            QMessageBox.critical(self, "Error de Desencriptación", f"Ocurrió un error (verifique clave/contraseña):\n{e}")
