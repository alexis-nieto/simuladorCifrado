import tkinter as tk
from tkinter import ttk
from gui import EncryptionApp

if __name__ == "__main__":
    # Configuración de la ventana principal (Vanilla Tkinter)
    app = tk.Tk()
    app.title("Simulador de Cifrado")
    app.geometry("900x700")
    
    # Iniciar la interfaz gráfica
    EncryptionApp(app)
    
    # Centrar la ventana (manual en vanilla tk)
    app.eval('tk::PlaceWindow . center')
    
    app.mainloop()
