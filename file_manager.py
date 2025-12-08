import os
from datetime import datetime

# ============================================================================
# GESTOR DE ARCHIVOS (EL BIBLIOTECARIO)
# ============================================================================
# Este archivo se encarga de guardar cosas en el disco duro.
# Es como un bibliotecario que sabe dónde poner cada libro para que no se pierda.

def guardar_archivo(contenido, prefijo="mensaje", extension=".txt", es_binario=False):
    """
    Guarda el contenido en un archivo nuevo.
    Para no sobrescribir archivos antiguos, le pone la fecha y hora al nombre.
    Ejemplo: mensaje_2023-10-27_15-30-00.txt
    
    Args:
        contenido: Lo que queremos guardar (texto o bytes).
        prefijo: La primera parte del nombre del archivo (ej: "clave", "mensaje").
        extension: El tipo de archivo (ej: ".txt", ".pem", ".bin").
        es_binario: Verdadero (True) si son datos raros (bytes), Falso (False) si es texto normal.
        
    Returns:
        El nombre del archivo que se creó.
    """
    # 1. Crear un nombre único
    # Preguntamos la hora actual al reloj del sistema.
    ahora = datetime.now()
    # La convertimos en texto bonito: Año-Mes-Día_Hora-Minuto-Segundo
    timestamp = ahora.strftime("%Y-%m-%d_%H-%M-%S")
    # Juntamos todo para formar el nombre.
    nombre_archivo = f"{prefijo}_{timestamp}{extension}"
    
    # 2. Decidir cómo abrir el archivo
    # Si es binario ('wb'), escribimos bytes puros.
    # Si es texto ('w'), escribimos letras y usamos UTF-8 (para que funcionen las tildes y ñ).
    modo = "wb" if es_binario else "w"
    encoding = None if es_binario else "utf-8"
    
    # 3. Guardar
    # 'with open(...)' es la forma segura de abrir archivos.
    # Se asegura de cerrar el archivo automáticamente cuando terminamos, incluso si hay errores.
    with open(nombre_archivo, modo, encoding=encoding) as f:
        f.write(contenido)
        
    return nombre_archivo


