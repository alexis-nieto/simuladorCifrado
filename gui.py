import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter import filedialog
import os

from crypto_manager import CryptoManager
from file_manager import guardar_archivo, cargar_archivo
from utils import validar_texto, limpiar_nombre_archivo

class EncryptionApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)
        self.pack(fill=BOTH, expand=YES)
        self.crypto = CryptoManager()
        
        # === Cabecera ===
        lbl_titulo = ttk.Label(self, text="Simulador de Cifrado Modular", font=("Segoe UI", 18, "bold"))
        lbl_titulo.pack(pady=(0, 20))
        
        # === Área de Texto ===
        lbl_input = ttk.Label(self, text="Texto de Entrada / Salida:", font=("Segoe UI", 12))
        lbl_input.pack(anchor=W, pady=(0, 5))
        
        self.txt_area = ScrolledText(self, height=10, font=("Consolas", 10))
        self.txt_area.pack(fill=BOTH, expand=YES, pady=(0, 20))
        
        # === Controles ===
        controls_frame = ttk.Frame(self)
        controls_frame.pack(fill=X, pady=(0, 20))
        
        # Selección de Algoritmo
        lbl_algo = ttk.Label(controls_frame, text="Algoritmo:", font=("Segoe UI", 10))
        lbl_algo.pack(side=LEFT, padx=(0, 10))
        
        self.combo_algo = ttk.Combobox(controls_frame, values=[
            "Cifrado César",
            "ROT13",
            "Transposición Columnar",
            "Simétrico (AES)",
            "Asimétrico (RSA)"
        ], state="readonly", width=25)
        self.combo_algo.current(0)
        self.combo_algo.pack(side=LEFT, padx=(0, 20))
        
        # Botones de Acción
        btn_encrypt = ttk.Button(controls_frame, text="Encriptar", style="primary.TButton", command=self.encriptar)
        btn_encrypt.pack(side=LEFT, padx=(0, 10))
        
        btn_decrypt = ttk.Button(controls_frame, text="Desencriptar", style="success.TButton", command=self.desencriptar)
        btn_decrypt.pack(side=LEFT, padx=(0, 10))
        
        btn_clear = ttk.Button(controls_frame, text="Limpiar", style="secondary.TButton", command=self.limpiar)
        btn_clear.pack(side=LEFT)

        # === Pie de página ===
        lbl_footer = ttk.Label(self, text="Desarrollado para Simulación Educativa", font=("Segoe UI", 8), bootstyle="secondary")
        lbl_footer.pack(side=BOTTOM, pady=(10, 0))

    def limpiar(self):
        self.txt_area.delete("1.0", END)

    def obtener_texto(self):
        return self.txt_area.get("1.0", END).strip()

    def encriptar(self):
        texto = self.obtener_texto()
        if not validar_texto(texto):
            messagebox.showwarning("Advertencia", "Por favor ingrese texto para encriptar.")
            return

        algo = self.combo_algo.get()
        resultado = None
        es_binario = False
        
        try:
            if algo == "Cifrado César":
                shift = simpledialog.askinteger("Desplazamiento", "Ingrese el desplazamiento (número entero):", parent=self)
                if shift is not None:
                    resultado = self.crypto.cifrar_cesar(texto, shift)
                    
            elif algo == "ROT13":
                resultado = self.crypto.rot13(texto)
                
            elif algo == "Transposición Columnar":
                clave = simpledialog.askinteger("Clave", "Ingrese el número de columnas:", parent=self)
                if clave is not None and clave > 0:
                    resultado = self.crypto.transposicion_columnar(texto, clave)
                elif clave is not None:
                    messagebox.showerror("Error", "La clave debe ser mayor a 0.")
                    
            elif algo == "Simétrico (AES)":
                pwd = simpledialog.askstring("Contraseña", "Ingrese una contraseña segura:", show='*', parent=self)
                if pwd:
                    resultado = self.crypto.cifrar_simetrico(texto, pwd)
                    es_binario = True
                    # Guardar contraseña (backup)
                    guardar_archivo(pwd, prefijo="contrasena", extension=".backup.txt")
                    
            elif algo == "Asimétrico (RSA)":
                priv, pub = self.crypto.generar_par_claves_rsa()
                pub_pem = self.crypto.serializar_clave_publica(pub)
                priv_pem = self.crypto.serializar_clave_privada(priv)
                
                # Guardar claves
                guardar_archivo(pub_pem, prefijo="public_key", extension=".pem", es_binario=True)
                guardar_archivo(priv_pem, prefijo="private_key", extension=".pem", es_binario=True)
                
                resultado = self.crypto.cifrar_asimetrico(texto, pub_pem)
                es_binario = True
                messagebox.showinfo("Claves Generadas", "Se han generado y guardado las claves pública y privada.")

            if resultado:
                ext = ".bin" if es_binario else ".txt"
                archivo = guardar_archivo(resultado, prefijo=f"mensaje-encriptado_{limpiar_nombre_archivo(algo)}", extension=ext, es_binario=es_binario)
                if archivo:
                    self.txt_area.delete("1.0", END)
                    if not es_binario:
                        self.txt_area.insert(END, resultado)
                    else:
                        self.txt_area.insert(END, f"[CONTENIDO BINARIO GUARDADO EN {archivo}]")
                    messagebox.showinfo("Éxito", f"Encriptación exitosa.\nGuardado en: {archivo}")

        except Exception as e:
            messagebox.showerror("Error de Encriptación", f"Ocurrió un error:\n{e}")

    def desencriptar(self):
        algo = self.combo_algo.get()
        
        try:
            if algo == "Asimétrico (RSA)":
                messagebox.showinfo("Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                contenido, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos Binarios", "*.bin")])
                if contenido is None: return
                
                messagebox.showinfo("Seleccionar Clave", "Seleccione la CLAVE PRIVADA (.pem)")
                key_pem, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos PEM", "*.pem")])
                if key_pem is None: return
                
                resultado = self.crypto.descifrar_asimetrico(contenido, key_pem)
                
            elif algo == "Simétrico (AES)":
                messagebox.showinfo("Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                contenido, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos Binarios", "*.bin")])
                if contenido is None: return
                
                pwd = simpledialog.askstring("Contraseña", "Ingrese la contraseña:", show='*', parent=self)
                if not pwd: return
                
                resultado = self.crypto.descifrar_simetrico(contenido, pwd)
                
            else:
                # Algoritmos de texto
                contenido = self.obtener_texto()
                if not contenido:
                    messagebox.showinfo("Seleccionar Archivo", "El área de texto está vacía. Seleccione un archivo.")
                    contenido, _ = cargar_archivo()
                    if contenido is None: return
                    self.txt_area.insert(END, contenido) # Mostrar lo cargado
                
                if algo == "Cifrado César":
                    shift = simpledialog.askinteger("Desplazamiento", "Ingrese el desplazamiento original:", parent=self)
                    if shift is not None:
                        resultado = self.crypto.descifrar_cesar(contenido, shift)
                    else: return
                        
                elif algo == "ROT13":
                    resultado = self.crypto.rot13(contenido)
                    
                elif algo == "Transposición Columnar":
                    clave = simpledialog.askinteger("Clave", "Ingrese el número de columnas original:", parent=self)
                    if clave is not None:
                        resultado = self.crypto.descifrar_transposicion(contenido, clave)
                    else: return
                else:
                    return

            self.txt_area.delete("1.0", END)
            self.txt_area.insert(END, resultado)
            messagebox.showinfo("Listo!!!", "Desencriptación completada con éxito.")
            
        except Exception as e:
            messagebox.showerror("Error de Desencriptación", f"Ocurrió un error (verifique clave/contraseña):\n{e}")
