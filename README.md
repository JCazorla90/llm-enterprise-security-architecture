# 🚀 llm-enterprise-security-architecture: Protegiendo el Cerebro Digital Empresarial

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Este repositorio complementa la serie de artículos **"Del Prompt al Compliance"** de **[José Cazorla](https://www.linkedin.com/in/jose-cazorla/recent-activity/articles/)** en LinkedIn, proporcionando ejemplos prácticos y configuraciones para implementar una arquitectura de seguridad robusta para Large Language Models (LLMs) en entornos empresariales.

En la era de la IA Generativa, la seguridad ya no es una opción, sino una necesidad imperativa. Aquí encontrarás cómo traducir los principios de DevSecOps, MLOps y gobernanza en soluciones técnicas concretas para proteger tus LLMs, datasets y pipelines.

🚧 **En construcción** · 🧩 Contenido incompleto · 🔜 Más actualizaciones pronto

---

## 💡 El Problema: Un Nuevo Perímetro de Ataque

La adopción de LLMs introduce vectores de ataque sin precedentes:

- **🎣 Prompt Injection**: Manipulación maliciosa de las instrucciones del modelo
- **🔓 Data Exfiltration**: Robo de información sensible a través de respuestas del LLM
- **🧩 Model Theft**: Extracción de los pesos del modelo mediante consultas adversarias
- **🔐 Training Data Poisoning**: Contaminación de datasets con datos maliciosos
- **⚡ Supply Chain Attacks**: Compromiso de modelos pre-entrenados o librerías

Las defensas de seguridad tradicionales son insuficientes. Necesitamos una estrategia adaptada que considere la naturaleza probabilística y los ciclos de vida específicos de la IA.

---

## 🎯 Nuestra Solución: Una Arquitectura de Defensa en Profundidad

Proponemos una arquitectura multicapa que integra controles en todo el ciclo de vida del modelo:

```
┌─────────────────────────────────────────────────────────────────┐
│                    🌐 USUARIOS / APLICACIONES                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     🛡️ AI GATEWAY / PROXY                       │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐           │
│  │ Prompt      │  │ DLP         │  │ Rate         │           │
│  │ Injection   │  │ Filtering   │  │ Limiting     │           │
│  │ Detection   │  │             │  │              │           │
│  └─────────────┘  └─────────────┘  └──────────────┘           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    🤖 LLM (GPT-4, Claude, etc.)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    📊 VECTOR DATABASE (RAG)                      │
│                    + RBAC Policies                               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌──────────────┐  ┌─────────────────┐
│ 🔍 Cranium    │  │ 🚨 Darktrace │  │ 📈 Prometheus   │
│ (Governance)  │  │ (Detection)  │  │ (Monitoring)    │
└───────────────┘  └──────────────┘  └─────────────────┘
```

---

## 🛠️ Componentes Clave y Ejemplos Prácticos

### 1. 🛡️ El AI Gateway/Proxy: Nuestro "LLM Firewall"

El AI Gateway es el punto de control crítico que inspecciona y filtra las interacciones con tus LLMs.

**Archivos principales:**
- [`src/ai_gateway_proxy/main.py`](src/ai_gateway_proxy/main.py) - Proxy FastAPI con flujo de seguridad completo
- [`src/ai_gateway_proxy/prompt_injection_filters.py`](src/ai_gateway_proxy/prompt_injection_filters.py) - Detector multicapa de Prompt Injection
- [`src/ai_gateway_proxy/dlp_filters.py`](src/ai_gateway_proxy/dlp_filters.py) - Escáner DLP para PII

**Funcionalidades:**
- ✅ Detección de Prompt Injection con múltiples heurísticas
- ✅ Escaneo DLP para PII (correos, teléfonos, SSN, tarjetas de crédito, etc.)
- ✅ Rate limiting por usuario
- ✅ Logging y auditoría completa
- ✅ Métricas de seguridad en tiempo real

**Ejemplo de uso:**

```bash
# Iniciar el AI Gateway
cd src/ai_gateway_proxy
uvicorn main:app --reload --port 8080

# Probar con curl
curl -X POST "http://localhost:8080/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "¿Cuál es la capital de Francia?",
    "user_id": "user123",
    "model": "gpt-4"
  }'
```

**Flujo de seguridad:**

```
Solicitud → Prompt Injection Check → DLP Input Scan → LLM Call 
         → DLP Output Scan → Response → Audit Log
```

---

### 2. 🔒 Seguridad en MLOps: Blindando la Cadena de Suministro de la IA

La seguridad debe integrarse en cada paso del ciclo de vida del modelo. Esto es **DevSecLLMOps** en acción.

**Pipeline de CI/CD:**
- [`.github/workflows/devsecllmops-pipeline.yml`](.github/workflows/devsecllmops-pipeline.yml) - Pipeline completo con escaneos de seguridad

**Scripts de MLOps:**
- [`src/mlops_scripts/scan_model_artifact.py`](src/mlops_scripts/scan_model_artifact.py) - Escáner de artefactos de modelos (.pkl, .safetensors, .h5)
- [`src/mlops_scripts/check_dataset_lineage.py`](src/mlops_scripts/check_dataset_lineage.py) - Verificador de trazabilidad de datasets

**Controles de seguridad implementados:**

1. **🔍 Escaneo de Dependencias**: Snyk/Trivy para vulnerabilidades
2. **🔐 Escaneo de Modelos**: Detección de código malicioso en pickles
3. **📊 Verificación de Lineage**: Validación de origen y compliance de datasets
4. **🐳 Escaneo de Contenedores**: Trivy para imágenes Docker
5. **📋 Registro en Cranium**: Inventario de activos AI y AI-BOM

**Ejemplo: Escanear un artefacto de modelo**

```bash
python src/mlops_scripts/scan_model_artifact.py models/my_model.pkl

# Output:
# ======================================================================
#   REPORTE DE ESCANEO DE SEGURIDAD - ARTEFACTO ML
# ======================================================================
# 
# Archivo: models/my_model.pkl
# Tipo: pickle
# SHA-256: abc123...
# 
# RESULTADO: ✗ NO SEGURO
# Nivel de Riesgo: CRITICAL
# 
# 🚨 AMENAZAS DETECTADAS (2):
#   1. ⚠️ CRÍTICO: Módulo peligroso encontrado: 'os'
#   2. ⚠️ ALTO: Operación sospechosa encontrada: exec
```

**Ejemplo: Verificar lineage de un dataset**

```bash
# Crear template de metadatos
python src/mlops_scripts/check_dataset_lineage.py --create-template

# Verificar compliance
python src/mlops_scripts/check_dataset_lineage.py data/training_data_metadata.json
```

---

### 3. 📋 Gobernanza y Monitoreo: La Visibilidad que Necesitas

Para proteger lo que no conoces, necesitas visibilidad.

**Políticas RBAC:**
- [`policies/rbac_vector_db.yaml`](policies/rbac_vector_db.yaml) - Control de acceso para Vector DB

**Características de la política RBAC:**
- ✅ Roles granulares (admin, ml-engineer, data-scientist, llm-app, etc.)
- ✅ Clasificación de datos por sensibilidad (public, internal, confidential, restricted)
- ✅ Control de acceso dinámico basado en contexto (horario, geolocalización, etc.)
- ✅ Rate limiting por rol
- ✅ Auditoría completa de accesos
- ✅ Manejo de PII con auto-detección
- ✅ Integración con AI Gateway para propagación de contexto

**Ejemplo de política:**

```yaml
- name: llm-application-prod
  permissions:
    - resource: "vectors/public/*"
      actions: [read]
    - resource: "vectors/user-specific/{user_id}/*"
      actions: [read, create, update]
  conditions:
    authentication_method: "certificate"
    pii_filtering: true
  rate_limits:
    requests_per_minute: 10000
  data_filtering:
    exclude_collections: ["hr-data", "financial-records"]
```

---

## 🚀 Cómo Empezar

### Paso 1: Clonar el Repositorio

```bash
git clone https://github.com/tu-usuario/llm-enterprise-security-architecture.git
cd llm-enterprise-security-architecture
```

### Paso 2: Configurar el Entorno

```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Instalar modelo de SpaCy para PII detection (opcional)
python -m spacy download en_core_web_sm
```

### Paso 3: Configuración

Crea un archivo `.env` con tus credenciales:

```bash
# LLM API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Governance & Security
CRANIUM_API_URL=https://cranium.company.com/api/v1
CRANIUM_API_KEY=...

# Vector DB
PINECONE_API_KEY=...
PINECONE_ENVIRONMENT=...

# Monitoring
PROMETHEUS_GATEWAY=...
```

### Paso 4: Ejecutar el AI Gateway

```bash
cd src/ai_gateway_proxy
uvicorn main:app --reload --host 0.0.0.0 --port 8080
```

Accede a la documentación interactiva en: `http://localhost:8080/docs`

### Paso 5: Integrar en tu Pipeline CI/CD

Copia el workflow de ejemplo a tu repositorio:

```bash
cp .github/workflows/devsecllmops-pipeline.yml .github/workflows/
```

Configura los secrets necesarios en GitHub:
- `SNYK_TOKEN`
- `CRANIUM_API_KEY`
- `CRANIUM_API_URL`

---

## 📦 Estructura del Proyecto

```
llm-enterprise-security-architecture/
├── .github/
│   └── workflows/
│       └── devsecllmops-pipeline.yml    # Pipeline DevSecLLMOps
├── docs/
│   └── architecture_diagram.png          # Diagrama de arquitectura
│   └── ai_gateway_flow.png               # Flujo del AI Gateway
├── src/
│   ├── ai_gateway_proxy/
│   │   ├── main.py                       # AI Gateway FastAPI
│   │   ├── prompt_injection_filters.py   # Detector de Prompt Injection
│   │   └── dlp_filters.py                # Escáner DLP
│   └── mlops_scripts/
│       ├── scan_model_artifact.py        # Escáner de modelos
│       └── check_dataset_lineage.py      # Verificador de lineage
├── policies/
│   └── rbac_vector_db.yaml               # Política RBAC
├── models/                                # (Tus modelos aquí)
├── data/                                  # (Tus datasets aquí)
├── tests/                                 # Tests unitarios
├── README.md                              # Este archivo
├── requirements.txt                       # Dependencias Python
└── LICENSE                                # Licencia MIT
```

---

## 🧪 Testing

Ejecutar los tests:

```bash
# Todos los tests
pytest

# Con cobertura
pytest --cov=src --cov-report=html

# Solo tests de seguridad
pytest tests/security/
```

---

## 🔐 Mejores Prácticas de Seguridad

### Para el AI Gateway:
1. **Siempre** ejecuta el gateway en modo HTTPS en producción
2. Implementa **autenticación robusta** (OAuth 2.0, mTLS)
3. Configura **rate limiting** agresivo para prevenir abusos
4. Habilita **logging exhaustivo** pero redacta PII automáticamente
5. Integra con un **SIEM** para correlación de eventos

### Para MLOps:
1. **Nunca** deserialices pickles no confiables
2. Usa **safetensors** en lugar de pickle cuando sea posible
3. **Firma criptográficamente** todos los artefactos de modelos
4. Implementa **escaneo obligatorio** en el pipeline CI/CD
5. Mantén un **inventario completo** de datasets y modelos

### Para Vector DBs:
1. Implementa **RBAC estricto** según el principio de mínimo privilegio
2. **Cifra** datos en reposo y en tránsito (TLS 1.3+)
3. Habilita **auditoría** de todos los accesos a datos sensibles
4. Usa **aislamiento por namespace** para diferentes aplicaciones
5. Implementa **filtrado dinámico** basado en el contexto del usuario

---

## 🤝 Integración con Herramientas Empresariales

### Cranium (AI Governance)
```python
# Registro de modelo en Cranium
cranium_client.register_model(
    name="chatbot-v2",
    version="2.1.0",
    risk_assessment={"score": "low"},
    datasets_used=["customer-faq-v1"],
    compliance_status={"gdpr": True, "soc2": True}
)
```

### Darktrace (Threat Detection)
```python
# Enviar eventos de seguridad a Darktrace
darktrace_client.send_event({
    "type": "prompt_injection_attempt",
    "severity": "high",
    "user_id": "user123",
    "timestamp": datetime.utcnow()
})
```

### Prometheus (Monitoring)
```python
from prometheus_client import Counter

prompt_injection_attempts = Counter(
    'prompt_injection_attempts_total',
    'Total prompt injection attempts detected'
)

# Incrementar métrica
prompt_injection_attempts.inc()
```

---

## 📚 Recursos Adicionales

### Artículos de la Serie "Del Prompt al Compliance":
- [Parte 1: Introducción](https://www.linkedin.com/pulse/del-prompt-al-compliance-arquitectura-de-seguridad-jose-cazorla-gij%C3%B3n-eraff)
- [Parte 2: Arquitectura de Seguridad]()
- [Parte 3: MLOps Seguro]()


### Documentación Recomendada:
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Microsoft Presidio (PII Detection)](https://microsoft.github.io/presidio/)
- [HiddenLayer Model Scanner](https://hiddenlayer.com/)

---

## 💬 Contribución y Feedback

¡Tu experiencia es valiosa! Si tienes ideas para mejorar estos ejemplos, sugerencias para nuevos controles o has encontrado un error, no dudes en:

- 🐛 Abrir un **Issue** para reportar bugs
- 💡 Enviar un **Pull Request** con mejoras
- 💬 Compartir tu experiencia implementando estos controles
- ⭐ Dar una estrella al repo si te ha sido útil

### Contribuir:

```bash
# 1. Fork el repositorio
# 2. Crea una rama para tu feature
git checkout -b feature/mi-nueva-funcionalidad

# 3. Commit tus cambios
git commit -am "Añade nueva funcionalidad X"

# 4. Push a la rama
git push origin feature/mi-nueva-funcionalidad

# 5. Abre un Pull Request
```

---

## 🛡️ Seguridad y Responsabilidad

Este proyecto tiene fines educativos y de referencia. 


---

## 📄 Licencia

Este proyecto está bajo la licencia [MIT License](LICENSE).

```
MIT License

Copyright (c) 2025 José Cazorla Gijón

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🙏 Agradecimientos

- A la comunidad de **OWASP** por sus guías sobre LLM Security
- A **Microsoft** por Presidio y herramientas de PII detection
- A **Anthropic** y **OpenAI** por sus investigaciones en AI Safety
- A todos los contribuidores que hacen posible este proyecto

---




<div align="center">

**⭐ Si este proyecto te ayuda a proteger tus LLMs, considera darle una estrella ⭐**

*Construyendo juntos una comunidad más segura para la IA*

</div>
