import os
from datetime import datetime
# from tkinter import filedialog, messagebox # Moved inside functions

def guardar_archivo(contenido, prefijo="mensaje", extension=".txt", es_binario=False):
    """
    Guarda el contenido en un archivo con un nombre generado automáticamente basado en la fecha y hora.
    
    Args:
        contenido (str/bytes): El contenido a guardar.
        prefijo (str): El prefijo del nombre del archivo.
        extension (str): La extensión del archivo.
        es_binario (bool): Si el contenido es binario (bytes) o texto.
        
    Returns:
        str: La ruta del archivo guardado o None si falló.
    """
    try:
        from tkinter import messagebox
        # Generar marca de tiempo
        ahora = datetime.now()
        timestamp = ahora.strftime("%Y-%m-%d_%H-%M-%S")
        nombre_archivo = f"{prefijo}_{timestamp}{extension}"
        
        # Modo de escritura
        modo = "wb" if es_binario else "w"
        encoding = None if es_binario else "utf-8"
        
        with open(nombre_archivo, modo, encoding=encoding) as f:
            f.write(contenido)
            
        return nombre_archivo
    except Exception as e:
        from tkinter import messagebox
        messagebox.showerror("Error al guardar", f"No se pudo guardar el archivo:\n{e}")
        return None

def cargar_archivo(es_binario=False, extensiones=[("Archivos de texto", "*.txt")]):
    """
    Abre un diálogo para seleccionar un archivo y carga su contenido.
    
    Args:
        es_binario (bool): Si se debe leer como binario.
        extensiones (list): Lista de tuplas con descripciones y extensiones permitidas.
        
    Returns:
        tuple: (contenido, ruta_archivo) o (None, None) si se cancela o falla.
    """
    try:
        from tkinter import filedialog
        ruta_archivo = filedialog.askopenfilename(filetypes=extensiones)
        if not ruta_archivo:
            return None, None
            
        modo = "rb" if es_binario else "r"
        encoding = None if es_binario else "utf-8"
        
        with open(ruta_archivo, modo, encoding=encoding) as f:
            contenido = f.read()
            
        return contenido, ruta_archivo
    except Exception as e:
        from tkinter import messagebox
        messagebox.showerror("Error al leer", f"No se pudo leer el archivo:\n{e}")
        return None, None
