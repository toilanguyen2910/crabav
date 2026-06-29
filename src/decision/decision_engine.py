"""
Decision Engine - Threat scoring and action recommendation
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import statistics

from ..enums import ThreatLevel, ActionType, AgentType
from ..models import ThreatFinding, AgentResult, ThreatReport
from ..utils import get_logger

logger = get_logger("decision_engine")


@dataclass
class ScoringWeights:
    """Weights for different scoring factors"""
    signature_match: float = 0.40
    heuristic_analysis: float = 0.25
    behavior_analysis: float = 0.20
    threat_intel: float = 0.15


class ThreatScorer:
    """
    Calculates threat scores from multiple agent findings
    
    Scoring Algorithm:
    1. Aggregate findings from all agents
    2. Apply weighted scoring based on agent type
    3. Consider confidence levels
    4. Apply severity multipliers
    5. Generate final score (0-100)
    """
    
    def __init__(self, weights: Optional[ScoringWeights] = None):
        self.weights = weights or ScoringWeights()
        logger.info("ThreatScorer initialized")
    
    def calculate_score(self, findings: List[ThreatFinding]) -> float:
        """
        Calculate overall threat score from multiple findings
        
        Args:
            findings: List of threat findings from different agents
        
        Returns:
            Score between 0-100
        """
        if not findings:
            return 0.0
        
        # Group findings by agent type
        findings_by_type: Dict[AgentType, List[ThreatFinding]] = {}
        for finding in findings:
            agent_type = finding.agent_type
            if agent_type not in findings_by_type:
                findings_by_type[agent_type] = []
            findings_by_type[agent_type].append(finding)
        
        # Calculate weighted scores
        scores = []
        
        for agent_type, agent_findings in findings_by_type.items():
            # Average confidence for this agent type
            avg_confidence = statistics.mean(
                f.confidence for f in agent_findings
            )
            
            # Apply agent type weight
            weight = self._get_agent_weight(agent_type)
            weighted_score = avg_confidence * weight
            
            scores.append(weighted_score)
        
        # Base score
        base_score = sum(scores) * 100
        
        # Apply severity multiplier
        severity_multiplier = self._get_severity_multiplier(findings)
        
        # Apply count multiplier (more agents detecting = higher confidence)
        count_multiplier = 1.0 + (len(findings_by_type) * 0.1)
        
        # Final score
        final_score = base_score * severity_multiplier * count_multiplier
        
        # Clamp to 0-100
        final_score = min(100.0, max(0.0, final_score))
        
        logger.debug(f"Threat score: {final_score:.2f} (base={base_score:.2f}, severity={severity_multiplier}, count={count_multiplier})")
        
        return round(final_score, 2)
    
    def _get_agent_weight(self, agent_type: AgentType) -> float:
        """Get weight based on agent type"""
        weights = {
            AgentType.SCANNER: 1.0,
            AgentType.MONITOR: 0.8,
            AgentType.ANALYSIS: 0.9,
            AgentType.DECISION: 0.0  # Decision agents don't generate findings
        }
        return weights.get(agent_type, 0.5)
    
    def _get_severity_multiplier(self, findings: List[ThreatFinding]) -> float:
        """Multiplier based on highest severity"""
        if not findings:
            return 1.0
        
        max_severity = max((f.threat_level.value if hasattr(f.threat_level, 'value') else f.threat_level) for f in findings)
        
        multipliers = {
            1: 1.0,   # LOW
            2: 1.2,   # MEDIUM
            3: 1.5,   # HIGH
            4: 2.0,   # CRITICAL
        }
        
        return multipliers.get(max_severity, 1.0)
    
    def determine_threat_level(self, score: float) -> ThreatLevel:
        """Convert score to threat level"""
        if score < 30:
            return ThreatLevel.LOW
        elif score < 50:
            return ThreatLevel.MEDIUM
        elif score < 70:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL


class ActionRecommender:
    """
    Recommends actions based on threat characteristics
    """
    
    def __init__(self):
        self.action_rules = self._initialize_rules()
        logger.info("ActionRecommender initialized")
    
    def _initialize_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize action recommendation rules"""
        return {
            'critical': {
                'primary': ActionType.QUARANTINE,
                'secondary': [ActionType.DELETE],
                'allow_whitelist': False,
                'requires_confirmation': True
            },
            'high': {
                'primary': ActionType.QUARANTINE,
                'secondary': [ActionType.DELETE, ActionType.WHITELIST],
                'allow_whitelist': True,
                'requires_confirmation': True
            },
            'medium': {
                'primary': ActionType.QUARANTINE,
                'secondary': [ActionType.WHITELIST],
                'allow_whitelist': True,
                'requires_confirmation': True
            },
            'low': {
                'primary': ActionType.IGNORE,
                'secondary': [ActionType.WHITELIST],
                'allow_whitelist': True,
                'requires_confirmation': False
            }
        }
    
    def recommend_actions(
        self,
        threat_level: ThreatLevel,
        threat_type: str,
        confidence: float
    ) -> List[ActionType]:
        """
        Recommend actions based on threat characteristics
        
        Args:
            threat_level: Severity level of threat
            threat_type: Type of threat detected
            confidence: Detection confidence (0-1)
        
        Returns:
            List of recommended actions in priority order
        """
        level_map = {
            ThreatLevel.CRITICAL: 'critical',
            ThreatLevel.HIGH: 'high',
            ThreatLevel.MEDIUM: 'medium',
            ThreatLevel.LOW: 'low'
        }
        
        level_key = level_map.get(threat_level, 'medium')
        rules = self.action_rules.get(level_key, self.action_rules['medium'])
        
        actions = [rules['primary']]
        actions.extend(rules['secondary'])
        
        # Filter based on confidence
        if confidence < 0.5 and ActionType.DELETE in actions:
            actions.remove(ActionType.DELETE)
        
        return actions
    
    def requires_confirmation(self, threat_level: ThreatLevel) -> bool:
        """Check if action requires user confirmation"""
        level_map = {
            ThreatLevel.CRITICAL: 'critical',
            ThreatLevel.HIGH: 'high',
            ThreatLevel.MEDIUM: 'medium',
            ThreatLevel.LOW: 'low'
        }
        
        level_key = level_map.get(threat_level, 'medium')
        rules = self.action_rules.get(level_key, self.action_rules['medium'])
        
        return rules.get('requires_confirmation', True)


class DecisionEngine:
    """
    Main decision engine that coordinates scoring and recommendations
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scorer = ThreatScorer()
        self.recommender = ActionRecommender()
        
        self.min_confidence = config.get('min_confidence_threshold', 0.5)
        self.min_agents = config.get('min_agents_for_high_risk', 2)
        
        logger.info("DecisionEngine initialized")
    
    def analyze_findings(
        self,
        agent_results: List[AgentResult]
    ) -> Optional[ThreatReport]:
        """
        Analyze agent results and generate threat report
        
        Args:
            agent_results: Results from multiple agents
        
        Returns:
            ThreatReport if threats found, None otherwise
        """
        # Collect all findings
        all_findings = []
        for result in agent_results:
            if result.success and result.findings:
                all_findings.extend(result.findings)
        
        if not all_findings:
            logger.info("No threats detected")
            return None
        
        logger.info(f"Analyzing {len(all_findings)} threat findings")
        
        # Calculate threat score
        score = self.scorer.calculate_score(all_findings)
        
        # Determine threat level
        threat_level = self.scorer.determine_threat_level(score)
        
        # Get primary threat
        primary_finding = max(all_findings, key=lambda f: f.confidence)
        
        # Recommend actions
        recommended_actions = self.recommender.recommend_actions(
            threat_level,
            primary_finding.threat_name,
            primary_finding.confidence
        )
        
        # Generate threat report
        import uuid
        threat_id = f"threat_{uuid.uuid4().hex[:8]}"
        
        report = ThreatReport(
            threat_id=threat_id,
            threat_name=primary_finding.threat_name,
            threat_level=threat_level,
            risk_score=score,
            file_path=primary_finding.evidence.get('file_path', 'Unknown'),
            file_size=primary_finding.metadata.get('file_size', 0),
            file_hash=primary_finding.metadata.get('file_hash'),
            findings=all_findings,
            recommended_actions=recommended_actions
        )
        
        logger.info(
            f"Generated threat report: {threat_id} "
            f"(score={score}, level={threat_level.name})"
        )
        
        return report
    
    def should_auto_quarantine(self, report: ThreatReport) -> bool:
        """
        Determine if threat should be auto-quarantined
        
        Note: Per project requirements, we ALWAYS ask user first.
        This method exists for future automation features.
        """
        # Current policy: Never auto-quarantine
        return False
    
    def get_decision_summary(self, report: ThreatReport) -> Dict[str, Any]:
        """Get summary of decision for logging/reporting"""
        tl = report.threat_level
        tl_enum = tl if isinstance(tl, ThreatLevel) else ThreatLevel(tl)
        
        actions = report.recommended_actions
        action_values = [a.value if hasattr(a, 'value') else a for a in actions]
        
        return {
            'threat_id': report.threat_id,
            'threat_name': report.threat_name,
            'risk_score': report.risk_score,
            'threat_level': tl_enum.name,
            'recommended_actions': action_values,
            'requires_confirmation': self.recommender.requires_confirmation(tl_enum),
            'agents_detected': len(set(f.agent_id for f in report.findings)),
            'total_findings': len(report.findings)
        }
