"""FedRAMP Moderate baseline catalog and AWS Config rule mapping.

This module is the single source of truth for:

* ``CONTROL_FAMILIES`` -- NIST 800-53 Rev 5 family identifiers and titles.
* ``CONTROL_CATALOG`` -- the curated subset of FedRAMP Moderate controls this
  tool can evaluate from AWS Config evidence, with human readable titles.
* ``RULE_CONTROL_MAP`` -- AWS Config managed rule names mapped to the controls
  they provide evidence for. This mapping is modelled on AWS's published
  "Operational Best Practices for FedRAMP" conformance pack.

The mapping is pragmatic, not authoritative: it surfaces the controls that can
realistically be checked from AWS Config compliance data so a security
engineer can triage gaps quickly.
"""

from __future__ import annotations

from typing import Dict, List, Set

# ---------------------------------------------------------------------------
# NIST 800-53 Rev 5 control families
# ---------------------------------------------------------------------------

#: Family id -> family title.
CONTROL_FAMILIES: Dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# ---------------------------------------------------------------------------
# Control catalog (subset of FedRAMP Moderate / NIST 800-53 Rev 5)
# ---------------------------------------------------------------------------

#: Control id -> human readable title.
CONTROL_CATALOG: Dict[str, str] = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-9": "Protection of Audit Information",
    "AU-11": "Audit Record Retention",
    "AU-12": "Audit Record Generation",
    "CA-7": "Continuous Monitoring",
    "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-8": "System Component Inventory",
    "CP-9": "System Backup",
    "CP-10": "System Recovery and Reconstitution",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "IR-6": "Incident Reporting",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-5": "Denial-of-Service Protection",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
    "SI-7": "Software, Firmware, and Information Integrity",
}

# ---------------------------------------------------------------------------
# AWS Config rule -> controls mapping
# ---------------------------------------------------------------------------

#: AWS Config managed rule name -> controls the rule provides evidence for.
RULE_CONTROL_MAP: Dict[str, List[str]] = {
    # --- Identity & access -------------------------------------------------
    "iam-password-policy": ["IA-5", "AC-2"],
    "iam-user-mfa-enabled": ["IA-2", "AC-2"],
    "mfa-enabled-for-iam-console-access": ["IA-2", "AC-2"],
    "root-account-mfa-enabled": ["IA-2", "AC-6"],
    "iam-root-access-key-check": ["AC-2", "AC-3", "AC-6", "IA-2"],
    "iam-user-no-policies-check": ["AC-2", "AC-3", "AC-6"],
    "iam-policy-no-statements-with-admin-access": ["AC-3", "AC-6"],
    "iam-policy-no-statements-with-full-access": ["AC-3", "AC-6"],
    "access-keys-rotated": ["IA-5", "AC-2"],
    "iam-user-unused-credentials-check": ["AC-2"],
    # --- Encryption at rest ------------------------------------------------
    "s3-bucket-server-side-encryption-enabled": ["SC-13", "SC-28"],
    "encrypted-volumes": ["SC-13", "SC-28"],
    "rds-storage-encrypted": ["SC-13", "SC-28"],
    "efs-encrypted-check": ["SC-13", "SC-28"],
    "dynamodb-table-encryption-enabled": ["SC-13", "SC-28"],
    "cloudwatch-log-group-encrypted": ["AU-9", "SC-28"],
    "cloud-trail-encryption-enabled": ["AU-9", "SC-28"],
    "kms-cmk-not-scheduled-for-deletion": ["SC-12"],
    # --- Encryption in transit --------------------------------------------
    "s3-bucket-ssl-requests-only": ["SC-8", "SC-13"],
    "elb-acm-certificate-required": ["SC-8", "SC-13"],
    "elb-tls-https-listeners-only": ["SC-8"],
    "redshift-require-tls-ssl": ["SC-8"],
    # --- Boundary protection / network ------------------------------------
    "s3-bucket-public-read-prohibited": ["AC-3", "AC-6", "SC-7"],
    "s3-bucket-public-write-prohibited": ["AC-3", "AC-6", "SC-7"],
    "rds-instance-public-access-check": ["AC-3", "SC-7"],
    "rds-snapshots-public-prohibited": ["AC-3", "SC-7"],
    "ec2-instances-in-vpc": ["SC-7", "AC-4"],
    "restricted-ssh": ["SC-7", "AC-4"],
    "restricted-common-ports": ["SC-7"],
    "vpc-default-security-group-closed": ["SC-7", "AC-4"],
    "vpc-sg-open-only-to-authorized-ports": ["SC-7", "AC-4"],
    "internet-gateway-authorized-vpc-only": ["SC-7", "AC-4"],
    # --- Audit & logging ---------------------------------------------------
    "cloudtrail-enabled": ["AU-2", "AU-3", "AU-12"],
    "multi-region-cloudtrail-enabled": ["AU-2", "AU-12"],
    "cloud-trail-log-file-validation-enabled": ["AU-9", "SI-7"],
    "cloud-trail-cloud-watch-logs-enabled": ["AU-6", "AU-12"],
    "s3-bucket-logging-enabled": ["AU-2", "AU-12"],
    "vpc-flow-logs-enabled": ["AU-2", "AU-12", "SI-4"],
    "elb-logging-enabled": ["AU-2", "AU-12"],
    "cw-loggroup-retention-period-check": ["AU-11"],
    "cloudwatch-alarm-action-check": ["AU-6", "SI-4", "IR-6"],
    # --- Configuration management -----------------------------------------
    "ec2-instance-managed-by-systems-manager": ["CM-2", "CM-8"],
    "ec2-managedinstance-association-compliance-status-check": ["CM-2", "CM-6"],
    "ec2-stopped-instance": ["CM-2", "CM-8"],
    "ec2-security-group-attached-to-eni": ["CM-8"],
    "ec2-instance-no-public-ip": ["SC-7", "CM-7"],
    # --- Risk assessment / monitoring -------------------------------------
    "guardduty-enabled-centralized": ["SI-4", "RA-5"],
    "securityhub-enabled": ["CA-7", "SI-4", "RA-5"],
    "ec2-managedinstance-patch-compliance-status-check": ["SI-2", "RA-5"],
    "ecr-private-image-scanning-enabled": ["RA-5", "SI-2"],
    "guardduty-non-archived-findings": ["SI-4", "IR-6"],
    # --- Contingency planning / backup ------------------------------------
    "db-instance-backup-enabled": ["CP-9"],
    "rds-multi-az-support": ["CP-9", "CP-10"],
    "dynamodb-pitr-enabled": ["CP-9"],
    "s3-bucket-versioning-enabled": ["CP-9", "SI-7"],
    "backup-plan-min-frequency-and-min-retention-check": ["CP-9"],
    "elb-deletion-protection-enabled": ["SC-5", "CP-10"],
    # --- DoS protection / WAF ---------------------------------------------
    "shield-advanced-enabled-autorenew": ["SC-5"],
    "waf-classic-logging-enabled": ["SC-5", "SC-7", "AU-2"],
    "alb-waf-enabled": ["SC-5", "SC-7", "SI-3"],
}


def control_title(control_id: str) -> str:
    """Return a human readable title for a control id (or the id if unknown)."""
    return CONTROL_CATALOG.get(control_id, control_id)


def family_of(control_id: str) -> str:
    """Return the family prefix of a control id, e.g. ``AC-2`` -> ``AC``."""
    return control_id.split("-", 1)[0]


def family_title(family: str) -> str:
    """Return the human readable title for a family id."""
    return CONTROL_FAMILIES.get(family, family)


def controls_for_rule(rule_name: str) -> List[str]:
    """Return the controls a single AWS Config rule provides evidence for."""
    return list(RULE_CONTROL_MAP.get(rule_name, []))


def control_rule_index() -> Dict[str, Set[str]]:
    """Invert ``RULE_CONTROL_MAP`` into ``control_id -> set(rule_name)``."""
    index: Dict[str, Set[str]] = {}
    for rule, controls in RULE_CONTROL_MAP.items():
        for control in controls:
            index.setdefault(control, set()).add(rule)
    return index


def families_in_scope() -> List[str]:
    """Return the sorted family ids that at least one catalog control maps to."""
    return sorted({family_of(c) for c in CONTROL_CATALOG})
