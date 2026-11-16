"""Subpacote de motores de detecção de anomalias (Z-Score, Isolation Forest, CloudTrail Rules e Engine)."""

from secops_core.detectors.base import AnomalyResult, BaseDetector
from secops_core.detectors.cloudtrail_rules import (
    BaseCloudTrailRule,
    CloudTrailRulesEngine,
    RuleBruteForceConsole,
    RuleIAMPrivilegeEscalation,
    RuleNetworkPerimeterTampering,
    RuleOffHoursActivity,
    RuleRootActivity,
    RuleSensitiveS3PublicAccess,
    RuleSuspiciousIP,
    RuleTrailTampering,
    RuleUnauthorizedAPIBurst,
)
from secops_core.detectors.engine import ConsolidatedAnomaly, DetectionEngine
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.rules import RuleBasedDetector
from secops_core.detectors.zscore_detector import ZScoreDetector

__all__ = [
    "BaseDetector",
    "AnomalyResult",
    "ConsolidatedAnomaly",
    "DetectionEngine",
    "ZScoreDetector",
    "IsolationForestDetector",
    "RuleBasedDetector",
    "CloudTrailRulesEngine",
    "BaseCloudTrailRule",
    "RuleTrailTampering",
    "RuleIAMPrivilegeEscalation",
    "RuleRootActivity",
    "RuleBruteForceConsole",
    "RuleUnauthorizedAPIBurst",
    "RuleSensitiveS3PublicAccess",
    "RuleNetworkPerimeterTampering",
    "RuleSuspiciousIP",
    "RuleOffHoursActivity",
]
