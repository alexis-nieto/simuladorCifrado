#!/bin/bash

# Exit on error
set -e

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Cleaning previous builds..."
rm -rf build dist *.spec

echo "Compiling to single file ELF..."
# --onefile: Create a single executable
# --windowed: No console window
# --add-data: Include the font file (Linux separator is :)
# --name: Name of the executable
pyinstaller --onefile --windowed \
    --add-data "SourceCodePro-Regular.ttf:." \
    --name "SimuladorCifrado" \
    --hidden-import="PIL._tkinter_finder" \
    main.py

echo "Build complete!"
echo "Executable is located at: dist/SimuladorCifrado"
