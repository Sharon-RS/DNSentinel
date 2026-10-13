"""
Domain parsing and registrable parent domain extraction utilities.

Implements structured eTLD+1 extraction according to RFC specifications
without naive string suffix matching.
"""

from typing import Optional, Set

# Standard multi-part public suffixes (ccSLDs) recognized in enterprise and security environments
MULTI_PART_PUBLIC_SUFFIXES: Set[str] = {
    # United Kingdom
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "gov.in",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    # South Africa
    "co.za", "net.za", "org.za", "ac.za", "gov.za",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    # Canada
    "gc.ca",
    # Israel
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    # Mexico
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
}


def extract_registrable_domain(domain: Optional[str]) -> Optional[str]:
    """
    Extracts the registrable parent domain (eTLD+1 / effective Second-Level Domain)
    from a fully-qualified or relative DNS domain name.

    Guarantees:
    - Never uses naive substring or suffix matching (e.g. 'notattacker.lab' will NEVER
      match 'attacker.lab').
    - Handles standard single TLDs (e.g., 'attacker.lab' -> 'attacker.lab',
      'evil.tunnel.attacker.lab' -> 'attacker.lab', 'docs.python.org' -> 'python.org').
    - Handles known multi-part public suffixes (e.g., 'sub.c2.co.uk' -> 'c2.co.uk').
    - Normalizes lowercase and strips trailing dots.
    - Returns None if the domain is invalid, empty, or has fewer than 2 labels.
    """
    if domain is None or not isinstance(domain, str):
        return None

    clean = domain.strip().lower()
    if clean.endswith("."):
        clean = clean[:-1]

    if not clean or any(c.isspace() for c in clean) or "/" in clean or "\\" in clean or ":" in clean:
        return None

    labels = [lbl for lbl in clean.split(".") if lbl]
    if len(labels) < 2:
        return clean if labels else None

    # Check for known multi-part public suffix at the tail (e.g. ['co', 'uk'])
    if len(labels) >= 3:
        two_part_suffix = f"{labels[-2]}.{labels[-1]}"
        if two_part_suffix in MULTI_PART_PUBLIC_SUFFIXES:
            # Registrable domain is label preceding suffix + two_part_suffix
            return f"{labels[-3]}.{two_part_suffix}"

    # Default single-part TLD: Registrable domain is last 2 labels (SLD + TLD)
    return f"{labels[-2]}.{labels[-1]}"


def is_same_registrable_domain(domain_a: Optional[str], domain_b: Optional[str]) -> bool:
    """
    Strict comparison checking if two domain names share the exact same
    registrable parent domain. Avoids any suffix substring vulnerability.
    """
    reg_a = extract_registrable_domain(domain_a)
    reg_b = extract_registrable_domain(domain_b)
    if not reg_a or not reg_b:
        return False
    return reg_a == reg_b
