"""
DLP (Data Loss Prevention) Scanner para LLMs
Detecta y previene la exposición de información sensible (PII)
"""

import re
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class PIIType(Enum):
    """Tipos de información personal identificable"""
    EMAIL = "email"
    PHONE = "phone_number"
    SSN = "social_security_number"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    PASSPORT = "passport_number"
    DRIVER_LICENSE = "driver_license"
    IBAN = "iban"
    API_KEY = "api_key"
    AWS_KEY = "aws_access_key"
    PRIVATE_KEY = "private_key"
    ADDRESS = "physical_address"
    NAME = "person_name"


@dataclass
class PIIMatch:
    """Información sobre una coincidencia de PII"""
    pii_type: PIIType
    value: str
    start_pos: int
    end_pos: int
    confidence: float


class DLPScanner:
    """
    Escáner DLP para detectar información sensible en prompts y respuestas
    """
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.redaction_mode = "mask"  # 'mask', 'remove', 'tokenize'
    
    def _initialize_patterns(self) -> Dict[PIIType, Dict]:
        """
        Inicializa patrones regex para diferentes tipos de PII
        
        NOTA: Estos patrones son simplificados. En producción, usar
        librerías especializadas como Presidio de Microsoft o AWS Macie.
        """
        return {
            PIIType.EMAIL: {
                "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "confidence": 0.95,
                "description": "Dirección de correo electrónico"
            },
            PIIType.PHONE: {
                "pattern": r'\b(?:\+?34)?[6789]\d{8}\b|\b(?:\+?1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                "confidence": 0.85,
                "description": "Número de teléfono (ES/US)"
            },
            PIIType.SSN: {
                "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
                "confidence": 0.90,
                "description": "Social Security Number (US)"
            },
            PIIType.CREDIT_CARD: {
                "pattern": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                "confidence": 0.80,
                "description": "Número de tarjeta de crédito"
            },
            PIIType.IP_ADDRESS: {
                "pattern": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                "confidence": 0.70,
                "description": "Dirección IP"
            },
            PIIType.IBAN: {
                "pattern": r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',
                "confidence": 0.75,
                "description": "IBAN (cuenta bancaria internacional)"
            },
            PIIType.API_KEY: {
                "pattern": r'\b[A-Za-z0-9_-]{32,}\b',
                "confidence": 0.60,
                "description": "API Key genérica"
            },
            PIIType.AWS_KEY: {
                "pattern": r'\bAKIA[0-9A-Z]{16}\b',
                "confidence": 0.95,
                "description": "AWS Access Key"
            },
            PIIType.PRIVATE_KEY: {
                "pattern": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                "confidence": 0.99,
                "description": "Clave privada criptográfica"
            },
            PIIType.PASSPORT: {
                "pattern": r'\b[A-Z]{1,2}\d{6,9}\b',
                "confidence": 0.65,
                "description": "Número de pasaporte"
            }
        }
    
    def scan_input(self, text: str) -> Dict[str, Any]:
        """
        Escanea el prompt de entrada en busca de PII
        
        Returns:
            Dict con información sobre PII encontrado
        """
        matches = self._find_all_pii(text)
        
        return {
            "contains_pii": len(matches) > 0,
            "pii_count": len(matches),
            "pii_types": list(set([m.pii_type.value for m in matches])),
            "matches": [
                {
                    "type": m.pii_type.value,
                    "position": (m.start_pos, m.end_pos),
                    "confidence": m.confidence
                }
                for m in matches
            ],
            "risk_level": self._calculate_risk_level(matches)
        }
    
    def scan_output(self, text: str) -> Dict[str, Any]:
        """
        Escanea la respuesta del LLM en busca de PII
        También incluye texto sanitizado
        
        Returns:
            Dict con información de PII y texto sanitizado
        """
        matches = self._find_all_pii(text)
        sanitized_text = self._sanitize_text(text, matches)
        
        return {
            "contains_pii": len(matches) > 0,
            "pii_count": len(matches),
            "pii_types": list(set([m.pii_type.value for m in matches])),
            "sanitized_text": sanitized_text,
            "redaction_count": len(matches),
            "risk_level": self._calculate_risk_level(matches)
        }
    
    def _find_all_pii(self, text: str) -> List[PIIMatch]:
        """Encuentra todas las instancias de PII en el texto"""
        matches = []
        
        for pii_type, pattern_info in self.patterns.items():
            pattern = pattern_info["pattern"]
            confidence = pattern_info["confidence"]
            
            for match in re.finditer(pattern, text):
                # Validación adicional para reducir falsos positivos
                if self._validate_match(pii_type, match.group()):
                    matches.append(PIIMatch(
                        pii_type=pii_type,
                        value=match.group(),
                        start_pos=match.start(),
                        end_pos=match.end(),
                        confidence=confidence
                    ))
        
        # Ordenar por posición en el texto
        matches.sort(key=lambda x: x.start_pos)
        
        return matches
    
    def _validate_match(self, pii_type: PIIType, value: str) -> bool:
        """
        Validación adicional para reducir falsos positivos
        """
        
        # Validación de tarjeta de crédito (algoritmo de Luhn)
        if pii_type == PIIType.CREDIT_CARD:
            return self._luhn_check(value.replace('-', '').replace(' ', ''))
        
        # Validación de dirección IP (rangos válidos)
        if pii_type == PIIType.IP_ADDRESS:
            parts = value.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # Validación de email (más estricta)
        if pii_type == PIIType.EMAIL:
            # Evitar dominios de ejemplo
            example_domains = ['example.com', 'test.com', 'domain.com']
            return not any(domain in value.lower() for domain in example_domains)
        
        # Validación de API keys (evitar strings genéricos)
        if pii_type == PIIType.API_KEY:
            # Debe contener mezcla de letras y números
            has_letter = any(c.isalpha() for c in value)
            has_digit = any(c.isdigit() for c in value)
            return has_letter and has_digit and len(value) >= 32
        
        return True
    
    def _luhn_check(self, card_number: str) -> bool:
        """Algoritmo de Luhn para validar números de tarjeta de crédito"""
        try:
            digits = [int(d) for d in card_number]
            checksum = 0
            
            # Proceso del algoritmo de Luhn
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            
            return checksum % 10 == 0
        except (ValueError, TypeError):
            return False
    
    def _sanitize_text(self, text: str, matches: List[PIIMatch]) -> str:
        """
        Sanitiza el texto reemplazando PII con marcadores
        
        Estrategias de redacción:
        - mask: Reemplaza con [REDACTED_<TYPE>]
        - remove: Elimina completamente
        - tokenize: Reemplaza con un token único reversible (para logging)
        """
        
        if not matches:
            return text
        
        # Procesar de atrás hacia adelante para mantener índices válidos
        sanitized = text
        for match in reversed(matches):
            if self.redaction_mode == "mask":
                replacement = f"[REDACTED_{match.pii_type.value.upper()}]"
            elif self.redaction_mode == "remove":
                replacement = ""
            else:  # tokenize
                replacement = f"[TOKEN_{match.pii_type.value.upper()}_{hash(match.value) % 10000}]"
            
            sanitized = (
                sanitized[:match.start_pos] + 
                replacement + 
                sanitized[match.end_pos:]
            )
        
        return sanitized
    
    def _calculate_risk_level(self, matches: List[PIIMatch]) -> str:
        """
        Calcula el nivel de riesgo basado en el tipo y cantidad de PII
        
        Returns:
            'critical', 'high', 'medium', 'low', 'none'
        """
        
        if not matches:
            return "none"
        
        # PII de alto riesgo
        high_risk_types = {
            PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PASSPORT,
            PIIType.AWS_KEY, PIIType.PRIVATE_KEY
        }
        
        # PII de riesgo medio
        medium_risk_types = {
            PIIType.EMAIL, PIIType.PHONE, PIIType.IBAN,
            PIIType.DRIVER_LICENSE, PIIType.API_KEY
        }
        
        high_risk_count = sum(
            1 for m in matches if m.pii_type in high_risk_types
        )
        medium_risk_count = sum(
            1 for m in matches if m.pii_type in medium_risk_types
        )
        
        # Lógica de clasificación
        if high_risk_count >= 2:
            return "critical"
        elif high_risk_count >= 1:
            return "high"
        elif medium_risk_count >= 3:
            return "high"
        elif medium_risk_count >= 1:
            return "medium"
        else:
            return "low"
    
    def set_redaction_mode(self, mode: str):
        """Configura el modo de redacción"""
        if mode in ["mask", "remove", "tokenize"]:
            self.redaction_mode = mode
        else:
            raise ValueError(f"Modo inválido: {mode}")
    
    def add_custom_pattern(self, pii_type: str, pattern: str, 
                          confidence: float = 0.8, description: str = ""):
        """
        Permite añadir patrones personalizados para PII específicos
        de la organización
        """
        custom_type = PIIType[pii_type.upper()] if hasattr(PIIType, pii_type.upper()) else None
        
        if not custom_type:
            # Crear tipo personalizado dinámicamente
            # (en producción, extender el Enum apropiadamente)
            print(f"Advertencia: {pii_type} no es un tipo estándar")
        
        self.patterns[custom_type or pii_type] = {
            "pattern": pattern,
            "confidence": confidence,
            "description": description or f"Patrón personalizado: {pii_type}"
        }
    
    def generate_dlp_report(self, scan_result: Dict[str, Any]) -> str:
        """Genera un reporte legible del escaneo DLP"""
        if not scan_result["contains_pii"]:
            return "✓ No se detectó información sensible (PII)."
        
        report = f"⚠️  ALERTA DLP - Información Sensible Detectada\n"
        report += f"{'='*50}\n\n"
        report += f"Nivel de Riesgo: {scan_result['risk_level'].upper()}\n"
        report += f"Tipos de PII detectados: {len(scan_result['pii_types'])}\n"
        report += f"Total de instancias: {scan_result['pii_count']}\n\n"
        
        report += "Detalles:\n"
        for pii_type in scan_result['pii_types']:
            count = sum(1 for m in scan_result['matches'] if m['type'] == pii_type)
            report += f"  • {pii_type}: {count} instancia(s)\n"
        
        report += f"\n{'='*50}\n"
        report += "ACCIÓN REQUERIDA: Revisar y sanitizar el contenido antes de proceder.\n"
        
        return report
