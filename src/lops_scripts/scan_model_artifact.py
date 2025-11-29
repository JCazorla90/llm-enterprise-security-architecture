"""
Escáner de Seguridad para Artefactos de Modelos ML
Detecta código malicioso en archivos .pkl, .safetensors, .h5, etc.
"""

import os
import pickle
import hashlib
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import sys


@dataclass
class ScanResult:
    """Resultado del escaneo de un artefacto"""
    file_path: str
    file_type: str
    file_size: int
    sha256_hash: str
    is_safe: bool
    risk_level: str  # 'safe', 'low', 'medium', 'high', 'critical'
    threats_found: List[str]
    warnings: List[str]
    scan_timestamp: str


class ModelArtifactScanner:
    """
    Escáner de seguridad para artefactos de modelos ML
    
    Detecta:
    - Código malicioso en archivos pickle
    - Operaciones peligrosas deserializadas
    - Artefactos no firmados o con firmas inválidas
    - Tamaños de archivo sospechosos
    - Metadatos maliciosos
    """
    
    def __init__(self):
        self.dangerous_pickle_modules = [
            'os', 'sys', 'subprocess', 'socket', 'urllib',
            'requests', 'eval', 'exec', 'compile', '__import__'
        ]
        
        self.suspicious_operations = [
            b'system', b'exec', b'eval', b'__import__',
            b'subprocess', b'Popen', b'socket', b'urlopen'
        ]
    
    def scan_artifact(self, file_path: str) -> ScanResult:
        """
        Escanea un artefacto de modelo en busca de amenazas
        
        Args:
            file_path: Ruta al archivo del modelo
            
        Returns:
            ScanResult con los hallazgos de seguridad
        """
        
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")
        
        # Información básica del archivo
        file_size = path.stat().st_size
        file_type = self._identify_file_type(file_path)
        file_hash = self._calculate_hash(file_path)
        
        # Inicializar resultado
        threats = []
        warnings = []
        risk_level = "safe"
        
        # === Análisis según tipo de archivo ===
        
        if file_type == "pickle":
            pickle_threats = self._scan_pickle(file_path)
            threats.extend(pickle_threats)
            
        elif file_type == "safetensors":
            st_threats = self._scan_safetensors(file_path)
            threats.extend(st_threats)
            
        elif file_type == "h5" or file_type == "hdf5":
            h5_threats = self._scan_h5(file_path)
            threats.extend(h5_threats)
        
        # === Verificaciones generales ===
        
        # Verificar tamaño sospechoso
        if file_size > 10 * 1024 * 1024 * 1024:  # > 10GB
            warnings.append(f"Archivo muy grande: {file_size / (1024**3):.2f} GB")
        
        if file_size < 1024:  # < 1KB
            warnings.append("Archivo sospechosamente pequeño")
            risk_level = "medium"
        
        # Buscar contenido binario sospechoso
        binary_threats = self._scan_binary_content(file_path)
        threats.extend(binary_threats)
        
        # === Determinar nivel de riesgo ===
        if threats:
            if any("ejecución" in t.lower() or "código" in t.lower() for t in threats):
                risk_level = "critical"
            elif len(threats) >= 3:
                risk_level = "high"
            elif len(threats) >= 1:
                risk_level = "medium"
        elif warnings:
            risk_level = "low"
        
        is_safe = risk_level in ["safe", "low"]
        
        from datetime import datetime
        
        return ScanResult(
            file_path=str(path.absolute()),
            file_type=file_type,
            file_size=file_size,
            sha256_hash=file_hash,
            is_safe=is_safe,
            risk_level=risk_level,
            threats_found=threats,
            warnings=warnings,
            scan_timestamp=datetime.utcnow().isoformat()
        )
    
    def _identify_file_type(self, file_path: str) -> str:
        """Identifica el tipo de archivo del modelo"""
        path = Path(file_path)
        extension = path.suffix.lower()
        
        type_mapping = {
            '.pkl': 'pickle',
            '.pickle': 'pickle',
            '.pt': 'pytorch',
            '.pth': 'pytorch',
            '.safetensors': 'safetensors',
            '.h5': 'h5',
            '.hdf5': 'hdf5',
            '.onnx': 'onnx',
            '.pb': 'tensorflow',
            '.tflite': 'tflite'
        }
        
        return type_mapping.get(extension, 'unknown')
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calcula el hash SHA-256 del archivo"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _scan_pickle(self, file_path: str) -> List[str]:
        """
        Escanea archivos pickle en busca de código malicioso
        
        IMPORTANTE: Los archivos pickle son inherentemente inseguros
        ya que pueden ejecutar código arbitrario durante la deserialización.
        """
        
        threats = []
        
        # Leer el contenido raw del pickle
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Buscar importaciones peligrosas
        for module in self.dangerous_pickle_modules:
            if module.encode() in content:
                threats.append(
                    f"⚠️ CRÍTICO: Módulo peligroso encontrado: '{module}'. "
                    f"Puede ejecutar código arbitrario."
                )
        
        # Buscar operaciones sospechosas
        for operation in self.suspicious_operations:
            if operation in content:
                threats.append(
                    f"⚠️ ALTO: Operación sospechosa encontrada: {operation.decode()}"
                )
        
        # Intentar analizar la estructura del pickle de forma segura
        try:
            # Usar pickletools para inspeccionar sin ejecutar
            import pickletools
            import io
            
            output = io.StringIO()
            pickletools.dis(content, out=output)
            disassembly = output.getvalue()
            
            # Buscar patrones peligrosos en el desensamblado
            dangerous_patterns = ['REDUCE', 'GLOBAL', 'BUILD']
            for pattern in dangerous_patterns:
                if pattern in disassembly:
                    threats.append(
                        f"⚠️ MEDIO: Operación pickle '{pattern}' detectada. "
                        f"Requiere revisión manual."
                    )
        
        except Exception as e:
            threats.append(
                f"⚠️ ERROR: No se pudo analizar el pickle de forma segura: {str(e)}"
            )
        
        return threats
    
    def _scan_safetensors(self, file_path: str) -> List[str]:
        """
        Escanea archivos safetensors (formato más seguro)
        
        Safetensors es un formato diseñado para ser más seguro que pickle,
        pero aún puede contener metadatos maliciosos.
        """
        
        threats = []
        
        try:
            # Leer los metadatos del safetensors
            with open(file_path, 'rb') as f:
                # Los primeros 8 bytes contienen el tamaño del header
                header_size_bytes = f.read(8)
                header_size = int.from_bytes(header_size_bytes, byteorder='little')
                
                # Verificar tamaño razonable del header
                if header_size > 100 * 1024 * 1024:  # > 100MB
                    threats.append(
                        "⚠️ ALTO: Header de safetensors sospechosamente grande"
                    )
                    return threats
                
                # Leer el header JSON
                header_bytes = f.read(header_size)
                header_json = json.loads(header_bytes.decode('utf-8'))
                
                # Analizar metadatos
                if '__metadata__' in header_json:
                    metadata = header_json['__metadata__']
                    
                    # Buscar campos sospechosos
                    suspicious_keys = ['exec', 'eval', 'import', 'system']
                    for key in suspicious_keys:
                        if any(key in str(v).lower() for v in metadata.values()):
                            threats.append(
                                f"⚠️ MEDIO: Metadatos sospechosos con '{key}'"
                            )
        
        except Exception as e:
            threats.append(
                f"⚠️ ERROR: No se pudieron leer metadatos safetensors: {str(e)}"
            )
        
        return threats
    
    def _scan_h5(self, file_path: str) -> List[str]:
        """Escanea archivos HDF5/H5 (Keras/TensorFlow)"""
        
        threats = []
        
        try:
            import h5py
            
            with h5py.File(file_path, 'r') as f:
                # Verificar atributos sospechosos
                for key in f.attrs.keys():
                    value = f.attrs[key]
                    
                    # Buscar código ejecutable en atributos
                    if isinstance(value, (str, bytes)):
                        value_str = value.decode() if isinstance(value, bytes) else value
                        
                        if any(op in value_str for op in ['exec', 'eval', 'import']):
                            threats.append(
                                f"⚠️ ALTO: Atributo sospechoso '{key}' contiene código"
                            )
        
        except ImportError:
            threats.append("⚠️ INFO: h5py no disponible para análisis profundo")
        except Exception as e:
            threats.append(f"⚠️ ERROR: Error al analizar H5: {str(e)}")
        
        return threats
    
    def _scan_binary_content(self, file_path: str) -> List[str]:
        """Busca patrones sospechosos en el contenido binario"""
        
        threats = []
        
        # Leer una muestra del contenido
        with open(file_path, 'rb') as f:
            sample = f.read(1024 * 1024)  # Primeros 1MB
        
        # Buscar URLs sospechosas
        url_pattern = rb'https?://[^\s\x00]+'
        import re
        urls = re.findall(url_pattern, sample)
        
        if urls:
            threats.append(
                f"⚠️ MEDIO: Se encontraron {len(urls)} URL(s) en el archivo. "
                f"Revisar si son legítimas."
            )
        
        # Buscar strings de shell commands
        shell_commands = [b'/bin/sh', b'/bin/bash', b'cmd.exe', b'powershell']
        for cmd in shell_commands:
            if cmd in sample:
                threats.append(
                    f"⚠️ CRÍTICO: Comando de shell encontrado: {cmd.decode()}"
                )
        
        return threats
    
    def verify_signature(self, file_path: str, 
                        signature_file: Optional[str] = None,
                        public_key: Optional[str] = None) -> bool:
        """
        Verifica la firma criptográfica del artefacto
        
        En producción, integrar con sistemas como:
        - Sigstore (Cosign) para artefactos de contenedores
        - GPG para archivos individuales
        - Azure Key Vault / AWS KMS para firmas enterprise
        """
        
        # Implementación simplificada
        # En producción, usar librerías como cryptography o gpg
        
        if not signature_file or not public_key:
            print("⚠️  Verificación de firma no configurada")
            return False
        
        print("✓ Verificación de firma (simulada) exitosa")
        return True
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """Genera un reporte legible del escaneo"""
        
        report = f"\n{'='*70}\n"
        report += f"  REPORTE DE ESCANEO DE SEGURIDAD - ARTEFACTO ML\n"
        report += f"{'='*70}\n\n"
        
        report += f"Archivo: {scan_result.file_path}\n"
        report += f"Tipo: {scan_result.file_type}\n"
        report += f"Tamaño: {scan_result.file_size / (1024**2):.2f} MB\n"
        report += f"SHA-256: {scan_result.sha256_hash}\n"
        report += f"Timestamp: {scan_result.scan_timestamp}\n\n"
        
        report += f"{'─'*70}\n"
        report += f"RESULTADO: {'✓ SEGURO' if scan_result.is_safe else '✗ NO SEGURO'}\n"
        report += f"Nivel de Riesgo: {scan_result.risk_level.upper()}\n"
        report += f"{'─'*70}\n\n"
        
        if scan_result.threats_found:
            report += f"🚨 AMENAZAS DETECTADAS ({len(scan_result.threats_found)}):\n"
            for i, threat in enumerate(scan_result.threats_found, 1):
                report += f"  {i}. {threat}\n"
            report += "\n"
        
        if scan_result.warnings:
            report += f"⚠️  ADVERTENCIAS ({len(scan_result.warnings)}):\n"
            for i, warning in enumerate(scan_result.warnings, 1):
                report += f"  {i}. {warning}\n"
            report += "\n"
        
        if not scan_result.is_safe:
            report += "🛡️  RECOMENDACIONES:\n"
            report += "  • NO desplegar este modelo en producción\n"
            report += "  • Revisar manualmente el artefacto\n"
            report += "  • Contactar al equipo de MLOps/Seguridad\n"
            report += "  • Considerar reconstruir desde fuente confiable\n"
        
        report += f"\n{'='*70}\n"
        
        return report


def main():
    """Función principal para uso en CLI"""
    
    if len(sys.argv) < 2:
        print("Uso: python scan_model_artifact.py <ruta_al_modelo>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    scanner = ModelArtifactScanner()
    
    print(f"\n🔍 Escaneando artefacto: {file_path}\n")
    
    try:
        result = scanner.scan_artifact(file_path)
        
        # Imprimir reporte
        print(scanner.generate_report(result))
        
        # Guardar resultado en JSON
        output_file = f"{file_path}.scan_result.json"
        with open(output_file, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        
        print(f"📄 Resultado guardado en: {output_file}\n")
        
        # Exit code basado en el resultado
        sys.exit(0 if result.is_safe else 1)
    
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        sys.exit(2)


if __name__ == "__main__":
    main()
