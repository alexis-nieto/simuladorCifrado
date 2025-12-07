import ttkbootstrap as ttk
from gui import EncryptionApp

if __name__ == "__main__":
    # Configuración del tema principal
    # Se usa "flatly" para un look moderno y plano
    app = ttk.Window(title="Simulador de Cifrado", themename="flatly", size=(900, 700))
    
    # Iniciar la interfaz gráfica
    EncryptionApp(app)
    
    # Centrar la ventana
    app.place_window_center()
    
    app.mainloop()
