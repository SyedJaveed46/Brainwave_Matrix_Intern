import re
import tldextract
from urllib.parse import urlparse
from difflib import SequenceMatcher

# ========= WHITELIST & TRIGGER WORDS =========

SAFE_DOMAINS = [
    "google.com", "facebook.com", "microsoft.com", "apple.com",
    "amazon.com", "paypal.com", "github.com", "linkedin.com",
    "twitter.com"
]

TRICKY_WORDS = [
    "login", "secure", "account", "update", "verify", "signin",
    "auth", "webscr", "bank", "bonus", "reset", "free", "claim",
    "activity", "security", "confirm", "submit", "support"
]

# ---------- little helper funcs ------------

def normalize_url(u):
    """Return normalized URL (remove fragments, query strings)."""
    parsed = urlparse(u)
    if not parsed.scheme:
        u = "http://" + u  # default scheme if missing
        parsed = urlparse(u)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def looks_like_ip(u):
    ip_regex = r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}"
    return re.search(ip_regex, u) is not None

def find_bad_words(u):
    lowered = u.lower()
    return [w for w in TRICKY_WORDS if w in lowered]

def too_many_symbols(u):
    return u.count("-") > 5 or u.count("@") > 1 or u.count("=") > 5

def is_secure(u):
    return u.lower().startswith("https://")

def count_subs(u):
    parts = tldextract.extract(u)
    subs = [s for s in parts.subdomain.split(".") if s.strip() != ""]
    return len(subs)

def get_domain_ascii(u):
    """Return ASCII domain (handles punycode attacks)."""
    parts = tldextract.extract(u)
    try:
        domain_ascii = parts.domain.encode("idna").decode("utf-8")
    except:
        domain_ascii = parts.domain
    return domain_ascii + "." + parts.suffix

def closest_real_site(u):
    domain = get_domain_ascii(u)
    top_score = 0
    closest = None
    for legit in SAFE_DOMAINS:
        sim = SequenceMatcher(None, domain, legit).ratio()
        if sim > top_score:
            top_score = sim
            closest = legit
    return top_score, closest

# ========== MAIN CHECKER ==========

def check_url(u):
    verdict = {}
    u = u.strip()

    if not u:
        verdict["error"] = "No URL entered... try again."
        return verdict

    u = normalize_url(u)
    verdict["original"] = u
    verdict["ip_in_url"] = looks_like_ip(u)
    verdict["bad_words"] = find_bad_words(u)
    verdict["crazy_chars"] = too_many_symbols(u)
    verdict["https"] = is_secure(u)
    verdict["len"] = len(u)
    verdict["subs"] = count_subs(u)
    ratio, legit = closest_real_site(u)
    verdict["closest_match"] = (ratio, legit)

    # ---- improved scoring system (0-10+) ----
    score = 0
    if verdict["ip_in_url"]:
        score += 5
    if verdict["bad_words"]:
        score += 3
    if not verdict["https"]:
        score += 2
    if verdict["crazy_chars"]:
        score += 2
    if verdict["len"] > 100:
        score += 2
    if verdict["subs"] > 3:
        score += 3
    if ratio > 0.85 and legit not in u:
        score += 4

    verdict["score"] = score

    # classify based on score
    if score >= 8:
        verdict["label"] = "⚠️ HIGH RISK: Probably PHISHING"
    elif score >= 4:
        verdict["label"] = "❗ Suspicious"
    else:
        verdict["label"] = "✅ Seems OK"

    return verdict

# ========== CLI ==========

if __name__ == "__main__":
    print("=" * 50)
    print("     Phishing URL Checker (improved version)")
    print("=" * 50)
    print("Paste a URL (or type 'exit' to quit).")
    print("--------------------------------------------------")

    while True:
        user_url = input("URL: ").strip()
        if user_url.lower() == "exit":
            print("Goodbye!")
            break

        outcome = check_url(user_url)

        if "error" in outcome:
            print("Error:", outcome["error"])
            continue

        print(f"\nResult: {outcome['label']}")
        print("Score:", outcome["score"])
        print("Risk Bar:", "🟥" * min(outcome["score"], 10) + "🟩" * (10 - min(outcome["score"], 10)))
        print(" * HTTPS:", "Yes" if outcome["https"] else "No")
        print(" * Contains IP:", "Yes" if outcome["ip_in_url"] else "No")
        print(" * Subdomains:", outcome["subs"])
        print(" * URL length:", outcome["len"])
        if outcome["bad_words"]:
            print(" * Suspicious words:", ", ".join(outcome["bad_words"]))
        if outcome["crazy_chars"]:
            print(" * Lots of odd characters in URL")
        ratio, legit = outcome["closest_match"]
        print(f" * Closest safe domain: {legit} (sim: {ratio:.2f})")
        print("-" * 45, "\n")
