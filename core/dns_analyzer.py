import socket
import dns.resolver
from typing import Dict, Any


def resolve_host(hostname: str) -> Dict[str, Any]:
    """
    Resolves A and CNAME records for a given subdomain.
    Helps identify live assets and potential dangling CNAMEs.
    """
    result = {
        "hostname": hostname,
        "ips": [],
        "cname": None,
        "resolvable": False
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    try:
        answers = resolver.resolve(hostname, "A")
        result["ips"] = [rdata.to_text() for rdata in answers]
        result["resolvable"] = True
    except Exception:
        pass

    try:
        cname_answers = resolver.resolve(hostname, "CNAME")
        for rdata in cname_answers:
            result["cname"] = rdata.target.to_text().rstrip(".")
    except Exception:
        pass

    if not result["resolvable"]:
        try:
            ip = socket.gethostbyname(hostname)
            if ip:
                result["ips"] = [ip]
                result["resolvable"] = True
        except socket.gaierror:
            pass

    return result


def audit_domain_mail_security(domain: str) -> Dict[str, Any]:
    """
    Audits the root domain for MX, SPF, and DMARC records to flag
    email spoofing exposure during scoping assessments.
    """
    mail_audit = {
        "mx_records": [],
        "spf_present": False,
        "spf_record": None,
        "dmarc_present": False,
        "dmarc_record": None,
        "issues": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    try:
        mx_answers = resolver.resolve(domain, "MX")
        mail_audit["mx_records"] = [
            f"{r.exchange.to_text().rstrip('.')} (prio {r.preference})"
            for r in mx_answers
        ]
    except Exception:
        pass

    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt_val = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if txt_val.lower().startswith("v=spf1"):
                mail_audit["spf_present"] = True
                mail_audit["spf_record"] = txt_val
                if "+all" in txt_val.lower():
                    mail_audit["issues"].append("SPF record contains '+all' (allows any host to send mail).")
                elif "?all" in txt_val.lower():
                    mail_audit["issues"].append("SPF record uses neutral '?all' policy instead of '~all' or '-all'.")
    except Exception:
        pass

    if not mail_audit["spf_present"]:
        mail_audit["issues"].append("Missing SPF record on root domain.")

    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_val = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if "v=dmarc1" in txt_val.lower():
                mail_audit["dmarc_present"] = True
                mail_audit["dmarc_record"] = txt_val
                if "p=none" in txt_val.lower():
                    mail_audit["issues"].append("DMARC policy is set to 'p=none' (monitoring only, no enforcement).")
    except Exception:
        pass

    if not mail_audit["dmarc_present"]:
        mail_audit["issues"].append("Missing DMARC record (_dmarc).")

    return mail_audit
