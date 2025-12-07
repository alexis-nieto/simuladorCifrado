import ttkbootstrap as ttk
from gui import EncryptionApp

if __name__ == "__main__":
    # Configuración del tema principal
    # Se usa "litera" como solicitado para un look limpio y moderno (blanco/azul)
    app = ttk.Window(title="Simulador de Cifrado", themename="litera", size=(800, 600))
    
    # Iniciar la interfaz gráfica
    EncryptionApp(app)
    
    # Centrar la ventana
    app.place_window_center()
    
    app.mainloop()
