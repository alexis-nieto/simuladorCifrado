import re

# ============================================================================
# UTILIDADES (LA CAJA DE HERRAMIENTAS)
# ============================================================================
# Aquí guardamos funciones pequeñas que nos ayudan en varias partes del programa.
# Son como el destornillador o el martillo: herramientas simples pero útiles.

def validar_texto(texto):
    """
    Comprueba si el texto es válido para trabajar con él.
    Básicamente, nos aseguramos de que no esté vacío.
    
    Args:
        texto: La cadena de letras que queremos revisar.
        
    Returns:
        True (Verdadero) si el texto sirve.
        False (Falso) si está vacío o solo tiene espacios en blanco.
    """
    # 'not texto': ¿Es nulo o vacío?
    # 'not texto.strip()': Si le quitamos los espacios del principio y final, ¿queda algo?
    if not texto or not texto.strip():
        return False
    return True

def limpiar_nombre_archivo(nombre):
    """
    Arregla un nombre de archivo para que sea seguro guardarlo.
    A veces los nombres tienen símbolos raros que a Windows o Linux no le gustan (como / \ : * ?).
    Esta función cambia esos símbolos raros por guiones bajos (_).
    
    Args:
        nombre: El nombre que queremos usar.
        
    Returns:
        El nombre limpio y seguro.
    """
    # Usamos una "Expresión Regular" (regex). Es una forma avanzada de buscar patrones.
    # r'[^\w\-\.]' significa: "Busca cualquier cosa que NO sea una letra, número, guion o punto".
    # Y 're.sub' lo sustituye por un guion bajo '_'.
    return re.sub(r'[^\w\-\.]', '_', nombre)
