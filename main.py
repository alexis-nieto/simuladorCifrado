import sys
from PyQt6.QtWidgets import QApplication
from gui import EncryptionApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Simulador de Cifrado")
    
    window = EncryptionApp()
    window.show()
    
    sys.exit(app.exec())
