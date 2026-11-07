# Re-export content analyzer from services
from app.services.content_analyzer import (
    is_safe_url,
    get_base_domain,
    safe_fetch_html,
    analyze_html,
    save_findings_to_db,
    analyze_content,
    KNOWN_BRANDS,
    DECEPTIVE_URGENCY_KEYWORDS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    CLICKFIX_PATTERNS,
)

__all__ = [
    "is_safe_url",
    "get_base_domain",
    "safe_fetch_html",
    "analyze_html",
    "save_findings_to_db",
    "analyze_content",
    "KNOWN_BRANDS",
    "DECEPTIVE_URGENCY_KEYWORDS",
    "SUSPICIOUS_SCRIPT_PATTERNS",
    "CLICKFIX_PATTERNS",
]
