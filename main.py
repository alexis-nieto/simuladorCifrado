import sys
from PyQt6.QtWidgets import QApplication
from gui import EncryptionApp

# ============================================================================
# PUNTO DE ENTRADA PRINCIPAL (MAIN)
# ============================================================================
# Este archivo es como la llave de encendido de nuestro coche (el programa).
# Su único trabajo es arrancar todo y asegurarse de que la ventana se muestre.

if __name__ == "__main__":
    # 1. Crear la Aplicación
    # 'QApplication' es el cerebro de la interfaz gráfica. Necesitamos crear
    # una (y solo una) para que nuestro programa pueda dibujar ventanas y
    # responder a los clics del ratón.
    # Le pasamos 'sys.argv' por si alguien quiere arrancar el programa desde
    # la consola con opciones especiales (aunque nosotros no usamos ninguna por ahora).
    app = QApplication(sys.argv)

    # 2. Ponerle nombre
    # Esto es como ponerle una etiqueta a nuestro programa para que el sistema
    # operativo sepa cómo llamarlo.
    app.setApplicationName("Simulador de Cifrado")
    
    # 3. Crear la Ventana Principal
    # Aquí es donde "fabricamos" nuestra ventana. 'EncryptionApp' es una clase
    # que definimos en el archivo 'gui.py'. Imagina que es un plano de construcción.
    # Al hacer 'EncryptionApp()', estamos construyendo la casa siguiendo ese plano.
    window = EncryptionApp()

    # 4. Mostrar la Ventana
    # Por defecto, las ventanas son tímidas y están ocultas.
    # Con '.show()', le decimos: "¡Sal al escenario y déjate ver!".
    window.show()
    
    # 5. Ejecutar el Bucle Principal (Main Loop)
    # Esto es muy importante. 'app.exec()' inicia un bucle infinito que se queda
    # esperando a que hagas algo (clic, escribir, cerrar).
    # El programa se quedará "congelado" en esta línea hasta que cierres la ventana.
    # 'sys.exit(...)' asegura que cuando cierres la ventana, el programa se apague
    # limpiamente y le diga al sistema operativo "todo salió bien".
    sys.exit(app.exec())
