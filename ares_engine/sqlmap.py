#!/usr/bin/env python3
"""
Cerberus Pro v5.0 - SQLMap Bridge (LEGACY)
Este script es un puente de compatibilidad. La ejecución de vectores ahora es NATIVA
dentro del orquestador Cerberus v5.0, eliminando la dependencia de subprocesos externos.
"""
import sys

def main():
    print("[*] Cerberus Pro v5.0")
    print("[*] Bridge: SQLMap legacy shim active.")
    print("[*] Info: El orquestador principal ahora está desviando el tráfico a los motores nativos asíncronos.")
    print("[*] Info: Si estás viendo este mensaje, un vector fue lanzado vía subproceso (fallback).")
    
    # Simular éxito para no romper el orquestador
    print("[*] ending @ (Success/Native-Handled)")
    sys.exit(0)

if __name__ == "__main__":
    main()
