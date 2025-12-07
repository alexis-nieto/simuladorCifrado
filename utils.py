import re

def validar_texto(texto):
    """
    Valida si el texto no está vacío.
    
    Args:
        texto (str): El texto a validar.
        
    Returns:
        bool: True si el texto es válido, False si está vacío.
    """
    if not texto or not texto.strip():
        return False
    return True

def limpiar_nombre_archivo(nombre):
    """
    Limpia el nombre del archivo para evitar caracteres inválidos.
    
    Args:
        nombre (str): El nombre del archivo sugerido.
        
    Returns:
        str: El nombre del archivo limpio.
    """
    # Eliminar caracteres no alfanuméricos excepto guiones y puntos
    return re.sub(r'[^\w\-\.]', '_', nombre)
