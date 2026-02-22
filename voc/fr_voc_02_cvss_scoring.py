"""
FR-VOC-02: CVSS v3.1 Scoring for Identified Vulnerabilities
Implements full CVSS v3.1 base score calculation per FIRST specification.
"""

import math
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class AttackVector(Enum):
    NETWORK  = ("N", 0.85)
    ADJACENT = ("A", 0.62)
    LOCAL    = ("L", 0.55)
    PHYSICAL = ("P", 0.20)

class AttackComplexity(Enum):
    LOW  = ("L", 0.77)
    HIGH = ("H", 0.44)

class PrivilegesRequired(Enum):
    NONE = ("N", 0.85)
    LOW  = ("L", 0.62)
    HIGH = ("H", 0.27)

class UserInteraction(Enum):
    NONE     = ("N", 0.85)
    REQUIRED = ("R", 0.62)

class Scope(Enum):
    UNCHANGED = "U"
    CHANGED   = "C"

class Impact(Enum):
    NONE = ("N", 0.00)
    LOW  = ("L", 0.22)
    HIGH = ("H", 0.56)


@dataclass
class CVSSVector:
    """Full CVSS v3.1 base vector."""
    attack_vector:       AttackVector
    attack_complexity:   AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction:    UserInteraction
    scope:               Scope
    confidentiality:     Impact
    integrity:           Impact
    availability:        Impact
    cve_id:              Optional[str] = None
    description:         Optional[str] = None


def calculate_cvss_v31(vector: CVSSVector) -> dict:
    """
    FR-VOC-02: Calculate CVSS v3.1 Base Score using official FIRST formula.
    Returns full scoring breakdown.
    """
    av  = vector.attack_vector.value[1]
    ac  = vector.attack_complexity.value[1]

    # PR value changes when scope is Changed
    if vector.scope == Scope.CHANGED:
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
        pr = pr_map[vector.privileges_required.value[0]]
    else:
        pr = vector.privileges_required.value[1]

    ui    = vector.user_interaction.value[1]
    conf  = vector.confidentiality.value[1]
    intg  = vector.integrity.value[1]
    avail = vector.availability.value[1]

    exploitability = 8.22 * av * ac * pr * ui
    iss = 1 - ((1 - conf) * (1 - intg) * (1 - avail))

    if vector.scope == Scope.UNCHANGED:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    else:
        if vector.scope == Scope.UNCHANGED:
            base_score = min((exploitability + impact), 10)
        else:
            base_score = min(1.08 * (exploitability + impact), 10)
        base_score = math.ceil(base_score * 10) / 10

    if base_score == 0.0:   severity = "None"
    elif base_score < 4.0:  severity = "Low"
    elif base_score < 7.0:  severity = "Medium"
    elif base_score < 9.0:  severity = "High"
    else:                   severity = "Critical"

    vector_string = (
        f"CVSS:3.1/AV:{vector.attack_vector.value[0]}"
        f"/AC:{vector.attack_complexity.value[0]}"
        f"/PR:{vector.privileges_required.value[0]}"
        f"/UI:{vector.user_interaction.value[0]}"
        f"/S:{vector.scope.value}"
        f"/C:{vector.confidentiality.value[0]}"
        f"/I:{vector.integrity.value[0]}"
        f"/A:{vector.availability.value[0]}"
    )

    return {
        "cve_id":      vector.cve_id,
        "description": vector.description,
        "vector_string": vector_string,
        "base_score":  base_score,
        "severity":    severity,
        "subscores": {
            "exploitability": round(exploitability, 2),
            "impact":         round(impact, 2),
            "iss":            round(iss, 2)
        },
        "metrics": {
            "attack_vector":       vector.attack_vector.name,
            "attack_complexity":   vector.attack_complexity.name,
            "privileges_required": vector.privileges_required.name,
            "user_interaction":    vector.user_interaction.name,
            "scope":               vector.scope.name,
            "confidentiality":     vector.confidentiality.name,
            "integrity":           vector.integrity.name,
            "availability":        vector.availability.name
        }
    }


def parse_cvss_vector_string(vector_str: str, cve_id: str = None,
                              desc: str = None) -> CVSSVector:
    """Parse a CVSS v3.1 vector string into a CVSSVector object."""
    parts = {}
    for part in vector_str.replace("CVSS:3.1/", "").split("/"):
        k, v = part.split(":")
        parts[k] = v

    av_map = {"N": AttackVector.NETWORK, "A": AttackVector.ADJACENT,
              "L": AttackVector.LOCAL,   "P": AttackVector.PHYSICAL}
    ac_map = {"L": AttackComplexity.LOW, "H": AttackComplexity.HIGH}
    pr_map = {"N": PrivilegesRequired.NONE, "L": PrivilegesRequired.LOW,
              "H": PrivilegesRequired.HIGH}
    ui_map = {"N": UserInteraction.NONE, "R": UserInteraction.REQUIRED}
    s_map  = {"U": Scope.UNCHANGED, "C": Scope.CHANGED}
    i_map  = {"N": Impact.NONE, "L": Impact.LOW, "H": Impact.HIGH}

    return CVSSVector(
        attack_vector=av_map[parts["AV"]],
        attack_complexity=ac_map[parts["AC"]],
        privileges_required=pr_map[parts["PR"]],
        user_interaction=ui_map[parts["UI"]],
        scope=s_map[parts["S"]],
        confidentiality=i_map[parts["C"]],
        integrity=i_map[parts["I"]],
        availability=i_map[parts["A"]],
        cve_id=cve_id,
        description=desc
    )


# ── Known CVE vectors for lab hosts ─────────────────────────────────────────
# Real CVEs mapped to real CVSS v3.1 vectors from NVD.
# Used by: /voc/cvss endpoint, anomaly detector, DB seed, compliance checks.
LAB_CVE_VECTORS = [
    ("CVE-2024-21413", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "MS Outlook Moniker Link RCE"),
    ("CVE-2024-6387",  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "OpenSSH regreSSHion RCE"),
    ("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Log4Shell"),
    ("CVE-2023-23397", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Outlook Privilege Escalation"),
    ("CVE-2024-3400",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "PAN-OS Command Injection"),
    ("CVE-2023-44487", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HTTP/2 Rapid Reset DoS"),
    ("CVE-2024-1709",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "ConnectWise Auth Bypass"),
    ("CVE-2022-30190", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Follina MSDT RCE"),
]

# Backward-compat alias — database.py and main.py still reference this name
DEMO_CVE_VECTORS = LAB_CVE_VECTORS


def score_lab_cves() -> list:
    """Score all lab CVEs and return results."""
    results = []
    for cve_id, vector_str, desc in LAB_CVE_VECTORS:
        vec = parse_cvss_vector_string(vector_str, cve_id, desc)
        result = calculate_cvss_v31(vec)
        results.append(result)
        print(f"[FR-VOC-02] {cve_id}: {result['base_score']} ({result['severity']})")
    return results

# Backward-compat alias — main.py calls this by the old name
def score_all_demo_cves() -> list:
    return score_lab_cves()


if __name__ == "__main__":
    import json
    results = score_lab_cves()
    print("\n=== CVSS v3.1 Scoring Results ===")
    for r in results:
        print(f"{r['cve_id']:20s} Score: {r['base_score']} | {r['severity']:8s} | {r['vector_string']}")