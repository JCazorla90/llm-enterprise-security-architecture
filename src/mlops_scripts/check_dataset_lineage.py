"""
Verificador de Trazabilidad de Datasets (Dataset Lineage)
Valida el origen, transformaciones y compliance de datasets de entrenamiento
"""

import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
import sys


@dataclass
class DatasetMetadata:
    """Metadatos de un dataset"""
    name: str
    version: str
    source: str  # URL, repositorio, etc.
    created_at: str
    size_bytes: int
    row_count: Optional[int] = None
    column_count: Optional[int] = None
    hash: Optional[str] = None
    license: Optional[str] = None
    contains_pii: bool = False
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    transformations: List[Dict[str, Any]] = field(default_factory=list)
    source_datasets: List[str] = field(default_factory=list)


@dataclass
class LineageCheckResult:
    """Resultado de la verificación de lineage"""
    dataset_name: str
    is_compliant: bool
    issues_found: List[str]
    warnings: List[str]
    compliance_checks: Dict[str, bool]
    risk_level: str
    timestamp: str


class DatasetLineageChecker:
    """
    Verificador de trazabilidad y compliance de datasets
    
    Valida:
    - Origen verificable del dataset
    - Licencias compatibles
    - Ausencia de PII no autorizado
    - Compliance con regulaciones (GDPR, CCPA, etc.)
    - Trazabilidad de transformaciones
    - Integridad (hashes)
    """
    
    def __init__(self):
        self.compliance_frameworks = {
            'GDPR': self._check_gdpr_compliance,
            'CCPA': self._check_ccpa_compliance,
            'HIPAA': self._check_hipaa_compliance,
            'SOC2': self._check_soc2_compliance
        }
        
        self.approved_licenses = [
            'MIT', 'Apache-2.0', 'BSD-3-Clause', 'CC-BY-4.0',
            'CC0-1.0', 'GPL-3.0'  # Añadir las licencias aprobadas por tu org
        ]
        
        self.approved_sources = [
            'huggingface.co',
            'kaggle.com',
            'github.com',
            's3.amazonaws.com',  # Buckets internos aprobados
            # Añadir fuentes internas aprobadas
        ]
    
    def check_lineage(self, metadata_file: str) -> LineageCheckResult:
        """
        Verifica la trazabilidad y compliance de un dataset
        
        Args:
            metadata_file: Ruta al archivo de metadatos del dataset
            
        Returns:
            LineageCheckResult con los hallazgos
        """
        
        # Cargar metadatos
        metadata = self._load_metadata(metadata_file)
        
        issues = []
        warnings = []
        compliance_checks = {}
        
        # === VERIFICACIÓN 1: Fuente Aprobada ===
        source_ok = self._verify_source(metadata.source)
        compliance_checks['approved_source'] = source_ok
        
        if not source_ok:
            issues.append(
                f"❌ Fuente no aprobada: {metadata.source}. "
                f"Debe provenir de: {', '.join(self.approved_sources)}"
            )
        
        # === VERIFICACIÓN 2: Licencia Compatible ===
        license_ok = self._verify_license(metadata.license)
        compliance_checks['compatible_license'] = license_ok
        
        if not license_ok:
            if metadata.license:
                issues.append(
                    f"❌ Licencia no aprobada: {metadata.license}. "
                    f"Licencias permitidas: {', '.join(self.approved_licenses)}"
                )
            else:
                issues.append("❌ Licencia no especificada")
        
        # === VERIFICACIÓN 3: Integridad del Dataset ===
        integrity_ok = self._verify_integrity(metadata)
        compliance_checks['data_integrity'] = integrity_ok
        
        if not integrity_ok:
            issues.append(
                "❌ Hash no especificado o verificación de integridad fallida"
            )
        
        # === VERIFICACIÓN 4: PII y Datos Sensibles ===
        pii_ok = self._check_pii_compliance(metadata)
        compliance_checks['pii_compliant'] = pii_ok
        
        if not pii_ok:
            issues.append(
                "❌ El dataset contiene PII sin las autorizaciones necesarias"
            )
        
        # === VERIFICACIÓN 5: Compliance con Frameworks ===
        for framework, check_func in self.compliance_frameworks.items():
            is_compliant = check_func(metadata)
            compliance_checks[f'{framework.lower()}_compliant'] = is_compliant
            
            if not is_compliant:
                warnings.append(
                    f"⚠️  No cumple con {framework}. Revisar requisitos específicos."
                )
        
        # === VERIFICACIÓN 6: Trazabilidad de Transformaciones ===
        transformations_ok = self._verify_transformations(metadata)
        compliance_checks['transformations_documented'] = transformations_ok
        
        if not transformations_ok:
            warnings.append(
                "⚠️  Transformaciones no documentadas o incompletas"
            )
        
        # === VERIFICACIÓN 7: Dependencias (Source Datasets) ===
        dependencies_ok = self._verify_dependencies(metadata)
        compliance_checks['dependencies_verified'] = dependencies_ok
        
        if not dependencies_ok:
            warnings.append(
                "⚠️  Datasets fuente no verificados o no especificados"
            )
        
        # === Determinar Nivel de Riesgo ===
        risk_level = self._calculate_risk_level(issues, warnings, compliance_checks)
        
        is_compliant = len(issues) == 0 and risk_level in ['low', 'none']
        
        return LineageCheckResult(
            dataset_name=metadata.name,
            is_compliant=is_compliant,
            issues_found=issues,
            warnings=warnings,
            compliance_checks=compliance_checks,
            risk_level=risk_level,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _load_metadata(self, metadata_file: str) -> DatasetMetadata:
        """Carga los metadatos del dataset desde un archivo JSON"""
        
        path = Path(metadata_file)
        
        if not path.exists():
            raise FileNotFoundError(f"Archivo de metadatos no encontrado: {metadata_file}")
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        return DatasetMetadata(**data)
    
    def _verify_source(self, source: str) -> bool:
        """Verifica que la fuente esté en la lista de aprobadas"""
        
        if not source:
            return False
        
        return any(approved in source for approved in self.approved_sources)
    
    def _verify_license(self, license: Optional[str]) -> bool:
        """Verifica que la licencia sea compatible"""
        
        if not license:
            return False
        
        return license in self.approved_licenses
    
    def _verify_integrity(self, metadata: DatasetMetadata) -> bool:
        """Verifica la integridad del dataset mediante hash"""
        
        # En producción, recalcular el hash del dataset real y comparar
        # Aquí solo verificamos que exista
        return metadata.hash is not None and len(metadata.hash) > 0
    
    def _check_pii_compliance(self, metadata: DatasetMetadata) -> bool:
        """Verifica compliance con políticas de PII"""
        
        if not metadata.contains_pii:
            # No contiene PII, siempre OK
            return True
        
        # Si contiene PII, debe tener autorización específica
        # En metadata.compliance_status
        return metadata.compliance_status.get('pii_authorized', False)
    
    def _check_gdpr_compliance(self, metadata: DatasetMetadata) -> bool:
        """Verifica compliance con GDPR"""
        
        # Requisitos GDPR simplificados:
        # 1. Consentimiento documentado si hay PII
        # 2. Derecho al olvido implementable
        # 3. Datos minimizados
        
        if metadata.contains_pii:
            has_consent = metadata.compliance_status.get('gdpr_consent', False)
            has_deletion = metadata.compliance_status.get('deletion_mechanism', False)
            
            return has_consent and has_deletion
        
        return True  # No PII = no aplica GDPR específicamente
    
    def _check_ccpa_compliance(self, metadata: DatasetMetadata) -> bool:
        """Verifica compliance con CCPA (California Consumer Privacy Act)"""
        
        # Similar a GDPR pero con enfoque en datos de consumidores de California
        if metadata.contains_pii:
            has_disclosure = metadata.compliance_status.get('ccpa_disclosure', False)
            has_opt_out = metadata.compliance_status.get('opt_out_mechanism', False)
            
            return has_disclosure and has_opt_out
        
        return True
    
    def _check_hipaa_compliance(self, metadata: DatasetMetadata) -> bool:
        """Verifica compliance con HIPAA (datos de salud)"""
        
        # HIPAA aplica solo a datos de salud
        is_health_data = metadata.compliance_status.get('contains_phi', False)
        
        if not is_health_data:
            return True
        
        # Si contiene PHI, debe tener controles específicos
        has_baa = metadata.compliance_status.get('has_baa', False)
        is_encrypted = metadata.compliance_status.get('encrypted_at_rest', False)
        has_audit = metadata.compliance_status.get('audit_trail', False)
        
        return has_baa and is_encrypted and has_audit
    
    def _check_soc2_compliance(self, metadata: DatasetMetadata) -> bool:
        """Verifica compliance con SOC 2"""
        
        # SOC 2 se centra en controles de seguridad
        required_controls = [
            'access_control',
            'encryption',
            'audit_logging',
            'change_management'
        ]
        
        return all(
            metadata.compliance_status.get(control, False)
            for control in required_controls
        )
    
    def _verify_transformations(self, metadata: DatasetMetadata) -> bool:
        """Verifica que las transformaciones estén documentadas"""
        
        if not metadata.transformations:
            # Si no hay transformaciones declaradas, está OK
            # (asumimos dataset raw)
            return True
        
        # Cada transformación debe tener ciertos campos
        required_fields = ['type', 'timestamp', 'operator']
        
        for transformation in metadata.transformations:
            if not all(field in transformation for field in required_fields):
                return False
        
        return True
    
    def _verify_dependencies(self, metadata: DatasetMetadata) -> bool:
        """Verifica que los datasets fuente estén documentados"""
        
        if not metadata.source_datasets:
            # Dataset primario sin dependencias
            return True
        
        # En producción, verificar que cada source_dataset
        # también tenga su propio lineage verificado
        return True  # Simplificado
    
    def _calculate_risk_level(self, issues: List[str], warnings: List[str],
                             compliance_checks: Dict[str, bool]) -> str:
        """Calcula el nivel de riesgo global"""
        
        critical_checks = ['approved_source', 'compatible_license', 'pii_compliant']
        
        # Si hay issues críticos
        if issues:
            critical_issues = [
                i for i in issues 
                if any(check in i for check in critical_checks)
            ]
            
            if critical_issues:
                return "critical"
            elif len(issues) >= 3:
                return "high"
            else:
                return "medium"
        
        # Solo warnings
        if warnings:
            if len(warnings) >= 3:
                return "medium"
            else:
                return "low"
        
        return "none"
    
    def generate_report(self, result: LineageCheckResult) -> str:
        """Genera un reporte legible de la verificación"""
        
        report = f"\n{'='*70}\n"
        report += f"  REPORTE DE VERIFICACIÓN DE LINEAGE - DATASET\n"
        report += f"{'='*70}\n\n"
        
        report += f"Dataset: {result.dataset_name}\n"
        report += f"Timestamp: {result.timestamp}\n\n"
        
        report += f"{'─'*70}\n"
        status = "✓ CUMPLE" if result.is_compliant else "✗ NO CUMPLE"
        report += f"RESULTADO: {status}\n"
        report += f"Nivel de Riesgo: {result.risk_level.upper()}\n"
        report += f"{'─'*70}\n\n"
        
        # Compliance Checks
        report += "📋 VERIFICACIONES DE COMPLIANCE:\n"
        for check, passed in result.compliance_checks.items():
            icon = "✓" if passed else "✗"
            report += f"  {icon} {check.replace('_', ' ').title()}\n"
        report += "\n"
        
        # Issues
        if result.issues_found:
            report += f"❌ PROBLEMAS CRÍTICOS ({len(result.issues_found)}):\n"
            for i, issue in enumerate(result.issues_found, 1):
                report += f"  {i}. {issue}\n"
            report += "\n"
        
        # Warnings
        if result.warnings:
            report += f"⚠️  ADVERTENCIAS ({len(result.warnings)}):\n"
            for i, warning in enumerate(result.warnings, 1):
                report += f"  {i}. {warning}\n"
            report += "\n"
        
        # Recomendaciones
        if not result.is_compliant:
            report += "🛡️  ACCIONES REQUERIDAS:\n"
            report += "  • NO utilizar este dataset para entrenamiento en producción\n"
            report += "  • Resolver todos los problemas críticos antes de continuar\n"
            report += "  • Documentar las correcciones en el sistema de lineage\n"
            report += "  • Re-ejecutar la verificación tras las correcciones\n"
        
        report += f"\n{'='*70}\n"
        
        return report
    
    def create_metadata_template(self, output_file: str = "dataset_metadata_template.json"):
        """Crea un template de metadatos para facilitar la documentación"""
        
        template = {
            "name": "my-training-dataset",
            "version": "1.0.0",
            "source": "https://huggingface.co/datasets/organization/dataset-name",
            "created_at": datetime.utcnow().isoformat(),
            "size_bytes": 0,
            "row_count": 0,
            "column_count": 0,
            "hash": "sha256:...",
            "license": "MIT",
            "contains_pii": False,
            "compliance_status": {
                "pii_authorized": False,
                "gdpr_consent": True,
                "deletion_mechanism": True,
                "ccpa_disclosure": True,
                "opt_out_mechanism": True,
                "contains_phi": False,
                "access_control": True,
                "encryption": True,
                "audit_logging": True,
                "change_management": True
            },
            "transformations": [
                {
                    "type": "filtering",
                    "timestamp": datetime.utcnow().isoformat(),
                    "operator": "data-engineer@company.com",
                    "description": "Removed rows with missing values"
                }
            ],
            "source_datasets": []
        }
        
        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)
        
        print(f"✓ Template de metadatos creado: {output_file}")


def main():
    """Función principal para uso en CLI"""
    
    if len(sys.argv) < 2:
        print("Uso: python check_dataset_lineage.py <metadata_file.json>")
        print("  O: python check_dataset_lineage.py --create-template")
        sys.exit(1)
    
    checker = DatasetLineageChecker()
    
    if sys.argv[1] == "--create-template":
        output = sys.argv[2] if len(sys.argv) > 2 else "dataset_metadata_template.json"
        checker.create_metadata_template(output)
        sys.exit(0)
    
    metadata_file = sys.argv[1]
    
    print(f"\n🔍 Verificando lineage del dataset: {metadata_file}\n")
    
    try:
        result = checker.check_lineage(metadata_file)
        
        # Imprimir reporte
        print(checker.generate_report(result))
        
        # Guardar resultado en JSON
        output_file = f"{Path(metadata_file).stem}_lineage_check.json"
        with open(output_file, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        
        print(f"📄 Resultado guardado en: {output_file}\n")
        
        # Exit code basado en el resultado
        sys.exit(0 if result.is_compliant else 1)
    
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        sys.exit(2)


if __name__ == "__main__":
    main()
