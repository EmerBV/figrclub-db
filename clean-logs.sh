#!/bin/bash
# =============================================================================
# SCRIPT PARA LIMPIAR LOGS LOCALES
# =============================================================================

echo "🧹 Limpiando logs locales..."

# Limpiar directorio de logs
if [ -d "logs" ]; then
    echo "📁 Limpiando directorio logs/"
    rm -rf logs/*
    echo "✅ Directorio logs/ limpiado"
else
    echo "📁 Directorio logs/ no existe"
fi

# Limpiar archivos de log individuales
echo "📄 Limpiando archivos .log..."
find . -name "*.log" -type f -delete
find . -name "*.log.*" -type f -delete
find . -name "*.out" -type f -delete

# Limpiar archivos temporales
echo "🗑️ Limpiando archivos temporales..."
find . -name "*.tmp" -type f -delete
find . -name "*.temp" -type f -delete
find . -name "*.bak" -type f -delete

echo "✅ Limpieza completada"