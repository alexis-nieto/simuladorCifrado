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
from file_manager import guardar_archivo, cargar_archivo
from utils import validar_texto, limpiar_nombre_archivo

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Simulador de Cifrado Modular")
        self.resize(900, 700)
        
        # Main Layout
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # === Header ===
        title_label = QLabel("Simulador de Cifrado Modular")
        title_font = QFont("Sans Serif", 20, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        main_layout.addSpacing(20)

        # === Text Area ===
        input_label = QLabel("Texto de Entrada / Salida:")
        input_label.setFont(QFont("Sans Serif", 12))
        main_layout.addWidget(input_label)

        self.txt_area = QTextEdit()
        self.txt_area.setFont(QFont("Monospace", 11))
        main_layout.addWidget(self.txt_area)
        main_layout.addSpacing(20)

        # === Controls ===
        controls_group = QGroupBox("Panel de Control")
        controls_layout = QHBoxLayout()
        controls_group.setLayout(controls_layout)
        main_layout.addWidget(controls_group)

        # Algorithm Selection
        algo_label = QLabel("Algoritmo:")
        controls_layout.addWidget(algo_label)

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
        controls_layout.addSpacing(20)

        # Action Buttons
        btn_encrypt = QPushButton("ENCRIPTAR")
        btn_encrypt.clicked.connect(self.encriptar)
        controls_layout.addWidget(btn_encrypt)

        btn_decrypt = QPushButton("DESENCRIPTAR")
        btn_decrypt.clicked.connect(self.desencriptar)
        controls_layout.addWidget(btn_decrypt)

        btn_clear = QPushButton("LIMPIAR")
        btn_clear.clicked.connect(self.limpiar)
        controls_layout.addWidget(btn_clear)

        # === Status Bar ===
        self.status_label = QLabel("Listo para operar.")
        self.status_label.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.status_label.setContentsMargins(5, 5, 5, 5)
        main_layout.addWidget(self.status_label)

    def set_status(self, msg):
        self.status_label.setText(msg)

    def limpiar(self):
        self.txt_area.clear()
        self.set_status("Área de texto limpiada.")

    def obtener_texto(self):
        return self.txt_area.toPlainText().strip()

    def encriptar(self):
        texto = self.obtener_texto()
        if not validar_texto(texto):
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese texto para encriptar.")
            return

        algo = self.combo_algo.currentText()
        resultado = None
        es_binario = False
        self.set_status(f"Encriptando con {algo}...")

        try:
            if algo == "Cifrado César":
                shift, ok = QInputDialog.getInt(self, "Desplazamiento", "Ingrese el desplazamiento (número entero):")
                if ok:
                    resultado = self.crypto.cifrar_cesar(texto, shift)
            
            elif algo == "ROT13":
                resultado = self.crypto.rot13(texto)

            elif algo == "Transposición Columnar":
                clave, ok = QInputDialog.getInt(self, "Clave", "Ingrese el número de columnas:")
                if ok and clave > 0:
                    resultado = self.crypto.transposicion_columnar(texto, clave)
                elif ok:
                    QMessageBox.critical(self, "Error", "La clave debe ser mayor a 0.")

            elif algo == "Simétrico (AES)":
                pwd, ok = QInputDialog.getText(self, "Contraseña", "Ingrese una contraseña segura:", QLineEdit.EchoMode.Password)
                if ok and pwd:
                    resultado = self.crypto.cifrar_simetrico(texto, pwd)
                    es_binario = True
                    guardar_archivo(pwd, prefijo="contrasena", extension=".backup.txt")

            elif algo == "Asimétrico (RSA)":
                priv, pub = self.crypto.generar_par_claves_rsa()
                pub_pem = self.crypto.serializar_clave_publica(pub)
                priv_pem = self.crypto.serializar_clave_privada(priv)

                guardar_archivo(pub_pem, prefijo="public_key", extension=".pem", es_binario=True)
                guardar_archivo(priv_pem, prefijo="private_key", extension=".pem", es_binario=True)

                resultado = self.crypto.cifrar_asimetrico(texto, pub_pem)
                es_binario = True
                QMessageBox.information(self, "Claves Generadas", "Se han generado y guardado las claves pública y privada.")

            if resultado:
                ext = ".bin" if es_binario else ".txt"
                archivo = guardar_archivo(resultado, prefijo=f"mensaje-encriptado_{limpiar_nombre_archivo(algo)}", extension=ext, es_binario=es_binario)
                if archivo:
                    self.txt_area.clear()
                    if not es_binario:
                        self.txt_area.setPlainText(resultado)
                    else:
                        self.txt_area.setPlainText(f"[CONTENIDO BINARIO GUARDADO EN {archivo}]")
                    
                    msg_exito = f"Encriptación exitosa. Guardado en: {archivo}"
                    self.set_status(msg_exito)
                    QMessageBox.information(self, "Éxito", msg_exito)

        except Exception as e:
            self.set_status("Error en encriptación.")
            QMessageBox.critical(self, "Error de Encriptación", f"Ocurrió un error:\n{e}")

    def desencriptar(self):
        algo = self.combo_algo.currentText()
        self.set_status(f"Desencriptando con {algo}...")

        try:
            if algo == "Asimétrico (RSA)":
                QMessageBox.information(self, "Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Archivos Binarios (*.bin)")
                if not file_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(file_path, "rb") as f:
                    contenido = f.read()

                QMessageBox.information(self, "Seleccionar Clave", "Seleccione la CLAVE PRIVADA (.pem)")
                key_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Clave", "", "Archivos PEM (*.pem)")
                if not key_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(key_path, "rb") as f:
                    key_pem = f.read()

                resultado = self.crypto.descifrar_asimetrico(contenido, key_pem)

            elif algo == "Simétrico (AES)":
                QMessageBox.information(self, "Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Archivos Binarios (*.bin)")
                if not file_path:
                    self.set_status("Operación cancelada.")
                    return
                with open(file_path, "rb") as f:
                    contenido = f.read()

                pwd, ok = QInputDialog.getText(self, "Contraseña", "Ingrese la contraseña:", QLineEdit.EchoMode.Password)
                if not ok or not pwd:
                    self.set_status("Operación cancelada.")
                    return

                resultado = self.crypto.descifrar_simetrico(contenido, pwd)

            else:
                contenido = self.obtener_texto()
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

            self.txt_area.setPlainText(resultado)
            self.set_status("Desencriptación completada con éxito.")
            QMessageBox.information(self, "Listo!!!", "Desencriptación completada con éxito.")

        except Exception as e:
            self.set_status("Error en desencriptación.")
            QMessageBox.critical(self, "Error de Desencriptación", f"Ocurrió un error (verifique clave/contraseña):\n{e}")
