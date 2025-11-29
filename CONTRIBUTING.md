# 🤝 Guía de Contribución

¡Gracias por tu interés en contribuir a **LLM Enterprise Security Architecture**! Esta guía te ayudará a empezar.

## 📋 Tabla de Contenidos

- [Código de Conducta](#código-de-conducta)
- [Cómo Contribuir](#cómo-contribuir)
- [Configuración del Entorno de Desarrollo](#configuración-del-entorno-de-desarrollo)
- [Proceso de Desarrollo](#proceso-de-desarrollo)
- [Estándares de Código](#estándares-de-código)
- [Tests](#tests)
- [Documentación](#documentación)
- [Pull Requests](#pull-requests)

---

## 📜 Código de Conducta

Este proyecto se adhiere a un código de conducta. Al participar, se espera que mantengas un ambiente respetuoso y profesional.

### Comportamientos Esperados:
- ✅ Ser respetuoso y considerado con otros
- ✅ Aceptar críticas constructivas de manera profesional
- ✅ Enfocarse en lo que es mejor para la comunidad
- ✅ Mostrar empatía hacia otros miembros

### Comportamientos Inaceptables:
- ❌ Lenguaje o imágenes sexualizadas
- ❌ Ataques personales o políticos
- ❌ Acoso público o privado
- ❌ Publicar información privada de otros sin permiso

---

## 🚀 Cómo Contribuir

Hay muchas formas de contribuir:

### 1. Reportar Bugs 🐛

Si encuentras un bug, abre un **Issue** con:
- Descripción clara del problema
- Pasos para reproducirlo
- Comportamiento esperado vs. actual
- Versión de Python y sistema operativo
- Logs relevantes

**Template:**
```markdown
**Descripción del Bug**
Descripción clara y concisa del problema.

**Para Reproducir**
Pasos para reproducir:
1. Ejecutar '...'
2. Con input '...'
3. Ver error

**Comportamiento Esperado**
Lo que debería suceder.

**Screenshots/Logs**
Si aplica, añade capturas o logs.

**Entorno:**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.10.5]
- Versión del proyecto: [e.g., 1.0.0]
```

### 2. Sugerir Mejoras 💡

Para nuevas funcionalidades o mejoras, abre un **Issue** con:
- Descripción de la funcionalidad
- Por qué sería útil
- Ejemplos de uso propuestos
- Posibles alternativas consideradas

### 3. Contribuir Código 💻

1. **Fork** el repositorio
2. Crea una **rama** para tu feature
3. Implementa tus cambios
4. Añade **tests**
5. Actualiza la **documentación**
6. Envía un **Pull Request**

### 4. Mejorar Documentación 📚

- Corregir errores tipográficos
- Añadir ejemplos
- Mejorar explicaciones
- Traducir documentación

### 5. Ayudar en Issues 🆘

- Responder preguntas de otros usuarios
- Reproducir bugs reportados
- Sugerir soluciones

---

## 🛠️ Configuración del Entorno de Desarrollo

### Paso 1: Fork y Clone

```bash
# Fork en GitHub primero, luego:
git clone https://github.com/TU-USUARIO/llm-enterprise-security-architecture.git
cd llm-enterprise-security-architecture
```

### Paso 2: Configurar Upstream

```bash
git remote add upstream https://github.com/ORIGINAL/llm-enterprise-security-architecture.git
git fetch upstream
```

### Paso 3: Crear Entorno Virtual

```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

### Paso 4: Instalar Dependencias

```bash
# Dependencias de desarrollo
make install-dev

# O manualmente:
pip install -r requirements.txt
pip install pytest pytest-cov black isort flake8 mypy bandit
```

### Paso 5: Configurar Pre-commit Hooks (Opcional)

```bash
make setup-pre-commit
```

### Paso 6: Verificar Configuración

```bash
# Copiar archivo de configuración
cp .env.example .env

# Ejecutar tests para verificar
make test
```

---

## 🔄 Proceso de Desarrollo

### 1. Crear una Rama

```bash
# Actualizar main
git checkout main
git pull upstream main

# Crear rama feature
git checkout -b feature/nombre-descriptivo

# O para bugs:
git checkout -b fix/descripcion-del-bug
```

### 2. Hacer Cambios

- Escribe código claro y documentado
- Sigue los estándares de estilo
- Añade docstrings a funciones y clases
- Comenta código complejo

### 3. Añadir Tests

**Siempre añade tests para nuevas funcionalidades:**

```python
# tests/test_nueva_funcionalidad.py

def test_nueva_funcionalidad():
    """Descripción del test"""
    # Arrange
    input_data = "test"
    
    # Act
    result = nueva_funcionalidad(input_data)
    
    # Assert
    assert result == "expected_output"
```

### 4. Ejecutar Tests

```bash
# Todos los tests
make test

# Solo tus nuevos tests
pytest tests/test_nueva_funcionalidad.py -v

# Con coverage
make coverage-report
```

### 5. Formatear Código

```bash
# Formatear automáticamente
make format

# O verificar primero:
make format-check
```

### 6. Linting

```bash
# Ejecutar linters
make lint

# Corregir issues automáticamente cuando sea posible
black src/
isort src/
```

### 7. Security Scan

```bash
# Escanear vulnerabilidades
make security-scan
```

### 8. Commit

Usa mensajes de commit claros y descriptivos:

```bash
git add .
git commit -m "feat: añade detección de nuevo tipo de PII"

# O para bugs:
git commit -m "fix: corrige validación de emails con guiones"

# Para docs:
git commit -m "docs: actualiza guía de instalación"
```

**Convención de commits:**
- `feat:` Nueva funcionalidad
- `fix:` Corrección de bug
- `docs:` Cambios en documentación
- `style:` Formateo, sin cambios de código
- `refactor:` Refactorización sin cambiar funcionalidad
- `test:` Añadir o corregir tests
- `chore:` Cambios en build, CI, etc.

### 9. Push

```bash
git push origin feature/nombre-descriptivo
```

---

## 📏 Estándares de Código

### Python Style Guide

Seguimos [PEP 8](https://pep8.org/) con algunas modificaciones:

- **Longitud de línea:** 100 caracteres (no 79)
- **Imports:** Organizados con `isort`
- **Formateo:** Automático con `black`

### Docstrings

Usa docstrings de estilo Google:

```python
def funcion_ejemplo(param1: str, param2: int) -> bool:
    """
    Descripción breve de la función.
    
    Descripción más detallada si es necesaria.
    
    Args:
        param1: Descripción del primer parámetro
        param2: Descripción del segundo parámetro
        
    Returns:
        Descripción de lo que retorna
        
    Raises:
        ValueError: Cuando param2 es negativo
        
    Example:
        >>> funcion_ejemplo("test", 5)
        True
    """
    if param2 < 0:
        raise ValueError("param2 debe ser positivo")
    
    return len(param1) == param2
```

### Type Hints

Siempre usa type hints:

```python
from typing import List, Dict, Optional

def procesar_datos(
    datos: List[str],
    opciones: Optional[Dict[str, Any]] = None
) -> Dict[str, List[str]]:
    """Procesa una lista de datos."""
    ...
```

### Estructura de Archivos

```python
"""
Docstring del módulo explicando su propósito.
"""

# Imports estándar
import os
import sys
from typing import List, Dict

# Imports de terceros
import numpy as np
from fastapi import FastAPI

# Imports locales
from src.utils import helper_function

# Constantes
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Código
class MiClase:
    """Docstring de la clase."""
    ...
```

---

## 🧪 Tests

### Escribir Tests

**Estructura de un test:**

```python
import pytest
from src.mi_modulo import mi_funcion

class TestMiFuncion:
    """Tests para mi_funcion"""
    
    def test_caso_normal(self):
        """Descripción del test"""
        # Arrange
        input_data = "test"
        expected = "TEST"
        
        # Act
        result = mi_funcion(input_data)
        
        # Assert
        assert result == expected
    
    def test_caso_edge(self):
        """Test para caso límite"""
        assert mi_funcion("") == ""
    
    def test_excepcion(self):
        """Test que verifica excepciones"""
        with pytest.raises(ValueError):
            mi_funcion(None)
```

### Fixtures

```python
@pytest.fixture
def datos_de_prueba():
    """Fixture que proporciona datos para tests"""
    return {
        "email": "test@example.com",
        "phone": "612345678"
    }

def test_con_fixture(datos_de_prueba):
    """Test que usa el fixture"""
    assert "email" in datos_de_prueba
```

### Coverage

- **Objetivo:** Mantener >80% de cobertura
- **Prioridad:** Cubrir paths críticos de seguridad al 100%

```bash
# Ver reporte de coverage
make coverage-report
```

---

## 📚 Documentación

### README

- Mantener actualizado con nuevas features
- Añadir ejemplos de uso
- Actualizar tabla de contenidos

### Docstrings

- Todas las funciones públicas deben tener docstrings
- Incluir ejemplos cuando sea útil
- Documentar excepciones

### Comentarios

```python
# BIEN: Comenta el "por qué", no el "qué"
# Usamos SHA-256 porque es requerido por FIPS 140-2
hash_value = hashlib.sha256(data).hexdigest()

# MAL: Obvio qué hace el código
# Calcula el hash SHA-256
hash_value = hashlib.sha256(data).hexdigest()
```

### CHANGELOG

Actualiza `CHANGELOG.md` con tus cambios:

```markdown
## [Unreleased]
### Added
- Nueva detección de PII tipo X

### Fixed
- Corrige validación de emails con caracteres especiales

### Changed
- Mejora performance del escáner DLP
```

---

## 🔀 Pull Requests

### Antes de Enviar

**Checklist:**
- [ ] Los tests pasan (`make test`)
- [ ] El código está formateado (`make format`)
- [ ] Pasa el linting (`make lint`)
- [ ] Pasa el security scan (`make security-scan`)
- [ ] La documentación está actualizada
- [ ] Se añadieron tests para nuevas funcionalidades
- [ ] El CHANGELOG está actualizado

### Crear el PR

1. **Título descriptivo:**
   ```
   feat: Añade detección de números de pasaporte
   ```

2. **Descripción completa:**
   ```markdown
   ## Descripción
   Implementa detección de números de pasaporte internacionales en el escáner DLP.
   
   ## Cambios
   - Añade patrón regex para pasaportes
   - Implementa validación de checksum
   - Añade tests exhaustivos
   
   ## Testing
   - [ ] Tests unitarios añadidos
   - [ ] Tests de integración actualizados
   - [ ] Verificado manualmente con datos reales
   
   ## Screenshots
   (Si aplica)
   
   ## Issues Relacionados
   Closes #123
   ```

3. **Vincula Issues:**
   - Use `Closes #123` para cerrar issues automáticamente
   - Use `Relates to #456` para referenciar

### Durante la Revisión

- Responde a los comentarios de manera constructiva
- Haz cambios solicitados en commits separados
- No hagas force push si hay conversaciones activas
- Marca conversaciones como resueltas cuando corresponda

### Después de la Aprobación

- El equipo hará merge (no hagas merge tú mismo)
- Puedes eliminar tu rama después del merge

---

## 🏷️ Versionado

Seguimos [Semantic Versioning](https://semver.org/):

- **MAJOR:** Cambios incompatibles con versiones anteriores
- **MINOR:** Nueva funcionalidad compatible
- **PATCH:** Correcciones de bugs compatibles

Ejemplo: `1.2.3`
- `1` = Major
- `2` = Minor
- `3` = Patch

---


## 🎉 Reconocimientos

¡Todos los contribuidores serán reconocidos en el README y en el CHANGELOG!

---

**¡Gracias por contribuir a hacer la IA más segura! 🚀🔒**
