from crypto_manager import CryptoManager
from file_manager import guardar_archivo, cargar_archivo
import os

def test_crypto():
    cm = CryptoManager()
    
    print("Testing Caesar...")
    assert cm.cifrar_cesar("ABC", 1) == "BCD"
    assert cm.descifrar_cesar("BCD", 1) == "ABC"
    
    print("Testing ROT13...")
    assert cm.rot13("ABC") == "NOP"
    assert cm.rot13("NOP") == "ABC"
    
    print("Testing Transposition...")
    # "HELLO WORLD" (11 chars), 4 cols
    # H L O
    # E O R
    # L   L
    # L W D
    # -> HLOEORL LDWD (spaces matter)
    # Let's use a simpler one without spaces to be sure of the logic implementation details
    msg = "HELLOWORLD"
    # 4 cols
    # H O R
    # E W L
    # L O D
    # L
    # -> HOR EWL LOD L
    # encrypted = cm.transposicion_columnar(msg, 4)
    # decrypted = cm.descifrar_transposicion(encrypted, 4)
    # assert decrypted == msg
    # Actually, let's just test reversibility
    enc = cm.transposicion_columnar("HELLOWORLD", 4)
    dec = cm.descifrar_transposicion(enc, 4)
    assert dec == "HELLOWORLD"
    
    print("Testing AES...")
    pwd = "secretpassword"
    token = cm.cifrar_simetrico("Secret Message", pwd)
    assert cm.descifrar_simetrico(token, pwd) == "Secret Message"
    
    print("Testing RSA...")
    priv, pub = cm.generar_par_claves_rsa()
    pub_pem = cm.serializar_clave_publica(pub)
    priv_pem = cm.serializar_clave_privada(priv)
    
    cipher = cm.cifrar_asimetrico("RSA Message", pub_pem)
    plain = cm.descifrar_asimetrico(cipher, priv_pem)
    assert plain == "RSA Message"
    
    print("All logic tests passed!")

if __name__ == "__main__":
    test_crypto()
