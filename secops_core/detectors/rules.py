"""Detector determinístico baseado em assinaturas e catálogo de regras CloudTrail."""

from typing import List, Optional
import pandas as pd
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


class RuleBasedDetector(CloudTrailRulesEngine):
    """Detector baseado em regras e assinaturas de segurança alinhadas ao MITRE ATT&CK e CIS AWS.

    Herda e integra o catálogo completo de regras determinísticas do CloudTrailRulesEngine.
    """

    def __init__(
        self,
        rules: Optional[List[BaseCloudTrailRule]] = None,
        name: str = "RuleBasedDetector",
    ):
        if rules is None:
            rules = [
                RuleTrailTampering(),
                RuleIAMPrivilegeEscalation(),
                RuleRootActivity(),
                RuleBruteForceConsole(),
                RuleUnauthorizedAPIBurst(),
                RuleSensitiveS3PublicAccess(),
                RuleNetworkPerimeterTampering(),
                RuleSuspiciousIP(),
                RuleOffHoursActivity(),
            ]
        super().__init__(rules=rules, name=name)


__all__ = [
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
