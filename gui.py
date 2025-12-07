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
from tkinter import font as tkfont

def get_ui_font(size=10, weight="normal"):
    """Return a font tuple with the best available sans-serif font."""
    families = ["Roboto", "Helvetica", "Arial", "Liberation Sans", "DejaVu Sans", "Verdana", "sans-serif"]
    # We can't easily check availability without a root window here, but Tkinter handles lists in some versions or we just pick one.
    # A safer bet is to let Tkinter find the best match or just use the first one that works if we could check.
    # Since we can't check easily before root init, we'll use a common Linux friendly one as primary if on Linux.
    import platform
    if platform.system() == "Linux":
        families = ["Liberation Sans", "DejaVu Sans", "Ubuntu", "Roboto", "Helvetica", "Arial"] + families
    
    return (families[0], size, weight)

def get_mono_font(size=10):
    """Return a font tuple with the best available monospace font."""
    families = ["Consolas", "Monaco", "Liberation Mono", "DejaVu Sans Mono", "Ubuntu Mono", "Courier New", "monospace"]
    import platform
    if platform.system() == "Linux":
        families = ["Liberation Mono", "DejaVu Sans Mono", "Ubuntu Mono"] + families
    return (families[0], size)

class EncryptionApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=30)
        self.pack(fill=BOTH, expand=YES)
        self.crypto = CryptoManager()
        
        # === Cabecera ===
        # Fuente más grande y moderna
        lbl_titulo = ttk.Label(self, text="Simulador de Cifrado Modular", font=get_ui_font(24, "bold"), bootstyle="primary")
        lbl_titulo.pack(pady=(0, 30))
        
        # === Área de Texto ===
        lbl_input = ttk.Label(self, text="Texto de Entrada / Salida:", font=get_ui_font(12))
        lbl_input.pack(anchor=W, pady=(0, 10))
        
        # Fuente monoespaciada para el texto cifrado, un poco más grande
        self.txt_area = ScrolledText(self, height=12, font=get_mono_font(11))
        self.txt_area.pack(fill=BOTH, expand=YES, pady=(0, 30))
        
        # === Controles ===
        # Agrupamos los controles en un LabelFrame para mejor organización visual
        controls_frame = ttk.Labelframe(self, text="Panel de Control", padding=20, bootstyle="info")
        controls_frame.pack(fill=X, pady=(0, 20))
        
        # Frame interno para centrar elementos si se desea, o usar grid
        grid_frame = ttk.Frame(controls_frame)
        grid_frame.pack(fill=X, expand=YES)

        # Selección de Algoritmo
        lbl_algo = ttk.Label(grid_frame, text="Algoritmo:", font=get_ui_font(11))
        lbl_algo.pack(side=LEFT, padx=(0, 15))
        
        self.combo_algo = ttk.Combobox(grid_frame, values=[
            "Cifrado César",
            "ROT13",
            "Transposición Columnar",
            "Simétrico (AES)",
            "Asimétrico (RSA)"
        ], state="readonly", width=30, font=get_ui_font(10))
        self.combo_algo.current(0)
        self.combo_algo.pack(side=LEFT, padx=(0, 30))
        
        # Botones de Acción - Más grandes y con iconos (simulados con texto por ahora)
        btn_encrypt = ttk.Button(grid_frame, text="ENCRIPTAR", style="primary.TButton", command=self.encriptar, width=15)
        btn_encrypt.pack(side=LEFT, padx=(0, 15))
        
        btn_decrypt = ttk.Button(grid_frame, text="DESENCRIPTAR", style="success.TButton", command=self.desencriptar, width=15)
        btn_decrypt.pack(side=LEFT, padx=(0, 15))
        
        btn_clear = ttk.Button(grid_frame, text="LIMPIAR", style="secondary.TButton", command=self.limpiar, width=10)
        btn_clear.pack(side=LEFT)

        # === Barra de Estado ===
        self.status_var = tk.StringVar()
        self.status_var.set("Listo para operar.")
        lbl_status = ttk.Label(self, textvariable=self.status_var, font=get_ui_font(9), bootstyle="secondary", relief=SUNKEN, anchor=W)
        lbl_status.pack(side=BOTTOM, fill=X, pady=(20, 0))

    def set_status(self, msg):
        self.status_var.set(msg)

    def limpiar(self):
        self.txt_area.delete("1.0", END)
        self.set_status("Área de texto limpiada.")

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
        self.set_status(f"Encriptando con {algo}...")
        
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
                    
                    msg_exito = f"Encriptación exitosa. Guardado en: {archivo}"
                    self.set_status(msg_exito)
                    messagebox.showinfo("Éxito", msg_exito)

        except Exception as e:
            self.set_status("Error en encriptación.")
            messagebox.showerror("Error de Encriptación", f"Ocurrió un error:\n{e}")

    def desencriptar(self):
        algo = self.combo_algo.get()
        self.set_status(f"Desencriptando con {algo}...")
        
        try:
            if algo == "Asimétrico (RSA)":
                messagebox.showinfo("Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                contenido, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos Binarios", "*.bin")])
                if contenido is None: 
                    self.set_status("Operación cancelada.")
                    return
                
                messagebox.showinfo("Seleccionar Clave", "Seleccione la CLAVE PRIVADA (.pem)")
                key_pem, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos PEM", "*.pem")])
                if key_pem is None: 
                    self.set_status("Operación cancelada.")
                    return
                
                resultado = self.crypto.descifrar_asimetrico(contenido, key_pem)
                
            elif algo == "Simétrico (AES)":
                messagebox.showinfo("Seleccionar Archivo", "Seleccione el archivo encriptado (.bin)")
                contenido, _ = cargar_archivo(es_binario=True, extensiones=[("Archivos Binarios", "*.bin")])
                if contenido is None: 
                    self.set_status("Operación cancelada.")
                    return
                
                pwd = simpledialog.askstring("Contraseña", "Ingrese la contraseña:", show='*', parent=self)
                if not pwd: 
                    self.set_status("Operación cancelada.")
                    return
                
                resultado = self.crypto.descifrar_simetrico(contenido, pwd)
                
            else:
                # Algoritmos de texto
                contenido = self.obtener_texto()
                if not contenido:
                    messagebox.showinfo("Seleccionar Archivo", "El área de texto está vacía. Seleccione un archivo.")
                    contenido, _ = cargar_archivo()
                    if contenido is None: 
                        self.set_status("Operación cancelada.")
                        return
                    self.txt_area.insert(END, contenido) # Mostrar lo cargado
                
                if algo == "Cifrado César":
                    shift = simpledialog.askinteger("Desplazamiento", "Ingrese el desplazamiento original:", parent=self)
                    if shift is not None:
                        resultado = self.crypto.descifrar_cesar(contenido, shift)
                    else: 
                        self.set_status("Operación cancelada.")
                        return
                        
                elif algo == "ROT13":
                    resultado = self.crypto.rot13(contenido)
                    
                elif algo == "Transposición Columnar":
                    clave = simpledialog.askinteger("Clave", "Ingrese el número de columnas original:", parent=self)
                    if clave is not None:
                        resultado = self.crypto.descifrar_transposicion(contenido, clave)
                    else: 
                        self.set_status("Operación cancelada.")
                        return
                else:
                    return

            self.txt_area.delete("1.0", END)
            self.txt_area.insert(END, resultado)
            self.set_status("Desencriptación completada con éxito.")
            messagebox.showinfo("Listo!!!", "Desencriptación completada con éxito.")
            
        except Exception as e:
            self.set_status("Error en desencriptación.")
            messagebox.showerror("Error de Desencriptación", f"Ocurrió un error (verifique clave/contraseña):\n{e}")
