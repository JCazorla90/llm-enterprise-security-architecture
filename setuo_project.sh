#!/bin/bash

# ============================================================================
# Script de Configuración del Proyecto
# LLM Enterprise Security Architecture
# ============================================================================

set -e  # Exit on error

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   LLM Enterprise Security Architecture - Setup Script          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar Python
echo -e "${YELLOW}→ Verificando Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 no está instalado${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✓ Python $PYTHON_VERSION instalado${NC}"

# Crear estructura de directorios
echo -e "${YELLOW}→ Creando estructura de directorios...${NC}"

mkdir -p src/ai_gateway_proxy
mkdir -p src/mlops_scripts
mkdir -p tests
mkdir -p policies
mkdir -p models/examples
mkdir -p data/examples
mkdir -p logs
mkdir -p monitoring
mkdir -p docs
mkdir -p .github/workflows

echo -e "${GREEN}✓ Estructura de directorios creada${NC}"

# Crear archivos __init__.py
echo -e "${YELLOW}→ Creando archivos __init__.py...${NC}"

touch src/__init__.py
touch src/ai_gateway_proxy/__init__.py
touch src/mlops_scripts/__init__.py
touch tests/__init__.py

echo -e "${GREEN}✓ Archivos __init__.py creados${NC}"

# Crear entorno virtual
echo -e "${YELLOW}→ ¿Deseas crear un entorno virtual? (y/n)${NC}"
read -r create_venv

if [[ $create_venv =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}→ Creando entorno virtual...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✓ Entorno virtual creado${NC}"
    
    # Activar entorno virtual
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi
    
    echo -e "${GREEN}✓ Entorno virtual activado${NC}"
fi

# Instalar dependencias
echo -e "${YELLOW}→ ¿Deseas instalar las dependencias? (y/n)${NC}"
read -r install_deps

if [[ $install_deps =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}→ Instalando dependencias...${NC}"
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Instalar modelo de SpaCy
    echo -e "${YELLOW}→ Descargando modelo de SpaCy para PII detection...${NC}"
    python -m spacy download en_core_web_sm
    
    echo -e "${GREEN}✓ Dependencias instaladas${NC}"
fi

# Configurar archivo .env
echo -e "${YELLOW}→ Configurando archivo .env...${NC}"

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Archivo .env creado desde .env.example${NC}"
    echo -e "${YELLOW}⚠️  Recuerda configurar tus API keys en el archivo .env${NC}"
else
    echo -e "${YELLOW}⚠️  El archivo .env ya existe. No se sobrescribirá.${NC}"
fi

# Configurar Git hooks (opcional)
echo -e "${YELLOW}→ ¿Deseas configurar pre-commit hooks? (y/n)${NC}"
read -r setup_hooks

if [[ $setup_hooks =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}→ Instalando pre-commit...${NC}"
    pip install pre-commit
    
    # Crear archivo .pre-commit-config.yaml
    cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-json
      
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3
        
  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
        
  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=100']
EOF
    
    pre-commit install
    echo -e "${GREEN}✓ Pre-commit hooks configurados${NC}"
fi

# Ejecutar tests
echo -e "${YELLOW}→ ¿Deseas ejecutar los tests? (y/n)${NC}"
read -r run_tests

if [[ $run_tests =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}→ Ejecutando tests...${NC}"
    pytest tests/ -v || echo -e "${YELLOW}⚠️  Algunos tests fallaron (normal si no hay configuración completa)${NC}"
fi

# Docker
echo -e "${YELLOW}→ ¿Deseas construir la imagen Docker? (y/n)${NC}"
read -r build_docker

if [[ $build_docker =~ ^[Yy]$ ]]; then
    if command -v docker &> /dev/null; then
        echo -e "${YELLOW}→ Construyendo imagen Docker...${NC}"
        docker build -t llm-security-gateway:latest .
        echo -e "${GREEN}✓ Imagen Docker construida${NC}"
    else
        echo -e "${RED}✗ Docker no está instalado${NC}"
    fi
fi

# Resumen final
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  ✓ Setup Completado                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}Proyecto configurado exitosamente!${NC}"
echo ""
echo -e "${YELLOW}Próximos pasos:${NC}"
echo "  1. Edita el archivo .env con tus API keys"
echo "  2. Ejecuta 'make test' para verificar que todo funciona"
echo "  3. Ejecuta 'make run-gateway' para iniciar el AI Gateway"
echo "  4. Visita http://localhost:8080/docs para la documentación"
echo ""
echo -e "${YELLOW}Comandos útiles:${NC}"
echo "  make help           - Ver todos los comandos disponibles"
echo "  make docker-up      - Iniciar todos los servicios con Docker"
echo "  make test           - Ejecutar tests"
echo "  make format         - Formatear código"
echo ""
echo -e "${GREEN}¡Listo para empezar! 🚀${NC}"
