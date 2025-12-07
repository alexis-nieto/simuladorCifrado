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
        str: La ruta del archivo guardado.
    Raises:
        Exception: Si ocurre un error al guardar.
    """
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

def cargar_archivo(es_binario=False, extensiones=[("Archivos de texto", "*.txt")]):
    """
    DEPRECATED: Use QFileDialog in the GUI layer instead.
    """
    raise NotImplementedError("cargar_archivo in file_manager is deprecated. Use GUI file dialogs.")
