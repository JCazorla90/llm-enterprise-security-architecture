"""
AI Gateway/Proxy - Punto de control crítico para interacciones con LLMs
Este módulo actúa como firewall inteligente entre usuarios y modelos LLM.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional
import logging
from datetime import datetime

from prompt_injection_filters import PromptInjectionDetector
from dlp_filters import DLPScanner

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LLM Security Gateway", version="1.0.0")

# Inicialización de componentes de seguridad
injection_detector = PromptInjectionDetector()
dlp_scanner = DLPScanner()


class LLMRequest(BaseModel):
    """Modelo de solicitud al LLM"""
    prompt: str
    user_id: str
    session_id: Optional[str] = None
    model: str = "gpt-4"
    max_tokens: int = 1000
    temperature: float = 0.7


class LLMResponse(BaseModel):
    """Modelo de respuesta del LLM"""
    content: str
    model: str
    usage: Dict[str, int]
    blocked: bool = False
    block_reason: Optional[str] = None


class SecurityMetrics:
    """Métricas de seguridad del gateway"""
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.injection_attempts = 0
        self.dlp_violations = 0
    
    def record_request(self, blocked: bool, reason: str = None):
        self.total_requests += 1
        if blocked:
            self.blocked_requests += 1
            if "injection" in reason.lower():
                self.injection_attempts += 1
            elif "dlp" in reason.lower() or "pii" in reason.lower():
                self.dlp_violations += 1


metrics = SecurityMetrics()


@app.post("/v1/chat/completions")
async def proxy_llm_request(request: LLMRequest) -> JSONResponse:
    """
    Endpoint principal que intercepta y valida solicitudes al LLM
    
    Flujo de seguridad:
    1. Detección de Prompt Injection
    2. Escaneo DLP en el prompt
    3. Validación RBAC (simplificado)
    4. Envío al LLM (si pasa los controles)
    5. Escaneo DLP en la respuesta
    6. Logging y auditoría
    """
    
    logger.info(f"Nueva solicitud de usuario: {request.user_id}")
    
    # === FASE 1: Validación del Prompt de Entrada ===
    
    # 1.1 Detección de Prompt Injection
    injection_result = injection_detector.scan(request.prompt)
    if injection_result['is_malicious']:
        logger.warning(
            f"Prompt injection detectado - Usuario: {request.user_id}, "
            f"Confianza: {injection_result['confidence']}"
        )
        metrics.record_request(blocked=True, reason="injection")
        
        return JSONResponse(
            status_code=403,
            content={
                "error": "Solicitud bloqueada por razones de seguridad",
                "type": "prompt_injection_detected",
                "details": injection_result['patterns_found']
            }
        )
    
    # 1.2 Escaneo DLP del Prompt
    dlp_result = dlp_scanner.scan_input(request.prompt)
    if dlp_result['contains_pii']:
        logger.warning(
            f"PII detectado en prompt - Usuario: {request.user_id}, "
            f"Tipos: {dlp_result['pii_types']}"
        )
        metrics.record_request(blocked=True, reason="dlp_input")
        
        return JSONResponse(
            status_code=403,
            content={
                "error": "Prompt contiene información sensible",
                "type": "pii_detected",
                "pii_types": dlp_result['pii_types']
            }
        )
    
    # === FASE 2: Envío al LLM (simulado) ===
    # En producción, aquí se haría la llamada real al LLM
    # (OpenAI API, Azure OpenAI, Claude, etc.)
    
    try:
        llm_response_text = await call_llm_backend(request)
    except Exception as e:
        logger.error(f"Error llamando al LLM: {str(e)}")
        raise HTTPException(status_code=500, detail="Error en el servicio LLM")
    
    # === FASE 3: Validación de la Respuesta ===
    
    # 3.1 Escaneo DLP de la respuesta
    dlp_output_result = dlp_scanner.scan_output(llm_response_text)
    if dlp_output_result['contains_pii']:
        logger.warning(
            f"PII detectado en respuesta LLM - Usuario: {request.user_id}, "
            f"Tipos: {dlp_output_result['pii_types']}"
        )
        metrics.record_request(blocked=True, reason="dlp_output")
        
        # Sanitizar la respuesta eliminando PII
        llm_response_text = dlp_output_result['sanitized_text']
        logger.info("Respuesta sanitizada automáticamente")
    
    # === FASE 4: Logging y Auditoría ===
    audit_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": request.user_id,
        "session_id": request.session_id,
        "model": request.model,
        "prompt_length": len(request.prompt),
        "response_length": len(llm_response_text),
        "security_checks": {
            "injection_score": injection_result['confidence'],
            "input_pii_detected": dlp_result['contains_pii'],
            "output_pii_detected": dlp_output_result['contains_pii']
        }
    }
    logger.info(f"Auditoría: {audit_log}")
    
    metrics.record_request(blocked=False)
    
    return JSONResponse(content={
        "content": llm_response_text,
        "model": request.model,
        "usage": {"prompt_tokens": 100, "completion_tokens": 200},
        "blocked": False
    })


async def call_llm_backend(request: LLMRequest) -> str:
    """
    Llamada simulada al backend LLM
    En producción, integrar con OpenAI API, Azure, Anthropic, etc.
    """
    # Simulación de respuesta
    return f"Esta es una respuesta simulada del modelo {request.model} al prompt del usuario."


@app.get("/health")
async def health_check():
    """Endpoint de salud del gateway"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "metrics": {
            "total_requests": metrics.total_requests,
            "blocked_requests": metrics.blocked_requests,
            "block_rate": (
                metrics.blocked_requests / metrics.total_requests 
                if metrics.total_requests > 0 else 0
            )
        }
    }


@app.get("/metrics")
async def get_metrics():
    """Endpoint de métricas para monitoreo (Prometheus, Grafana, etc.)"""
    return {
        "total_requests": metrics.total_requests,
        "blocked_requests": metrics.blocked_requests,
        "injection_attempts": metrics.injection_attempts,
        "dlp_violations": metrics.dlp_violations,
        "block_rate": (
            metrics.blocked_requests / metrics.total_requests 
            if metrics.total_requests > 0 else 0
        )
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
