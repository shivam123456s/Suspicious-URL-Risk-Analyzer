import re
import validators
import tldextract
from urllib.parse import urlparse
import whois
import socket


class URLAnalyzer:

    def __init__(self, url):
        self.url = url
        self.score = 0
        self.reasons = []

    # -----------------------------
    # BASIC VALIDATION
    # -----------------------------

    def check_valid_url(self):

        if not validators.url(self.url):
            self.reasons.append("Invalid URL format")
            return False

        return True

    # -----------------------------
    # RULE 1: HTTPS CHECK
    # -----------------------------

    def check_https(self):

        if not self.url.startswith("https"):
            self.score += 20
            self.reasons.append("URL does not use HTTPS")

    # -----------------------------
    # RULE 2: URL LENGTH
    # -----------------------------

    def check_url_length(self):

        length = len(self.url)

        if length >= 75:
            self.score += 20
            self.reasons.append("URL is very long")
        elif length >= 54:
            self.score += 10
            self.reasons.append("URL length is suspicious")

    # -----------------------------
    # RULE 3: IP ADDRESS
    # -----------------------------

    def check_ip_address(self):

        domain = urlparse(self.url).netloc

        pattern = r"\d+\.\d+\.\d+\.\d+"

        if re.match(pattern, domain):
            self.score += 25
            self.reasons.append("Domain uses IP address")

    # -----------------------------
    # RULE 4: URL SHORTENER
    # -----------------------------

    def check_url_shortener(self):

        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly"
        ]

        for s in shorteners:
            if s in self.url:
                self.score += 20
                self.reasons.append("URL uses shortening service")

    # -----------------------------
    # RULE 5: @ SYMBOL
    # -----------------------------

    def check_at_symbol(self):

        if "@" in self.url:
            self.score += 25
            self.reasons.append("URL contains @ symbol")

    # -----------------------------
    # RULE 6: DOUBLE SLASH
    # -----------------------------

    def check_double_slash(self):

        position = self.url.rfind("//")

        if position > 7:
            self.score += 10
            self.reasons.append("Suspicious redirect using //")

    # -----------------------------
    # RULE 7: HYPHEN IN DOMAIN
    # -----------------------------

    def check_hyphen(self):

        domain = urlparse(self.url).netloc

        if "-" in domain:
            self.score += 10
            self.reasons.append("Hyphen detected in domain")

    # -----------------------------
    # RULE 8: SUBDOMAIN COUNT
    # -----------------------------

    def check_subdomain(self):

        extracted = tldextract.extract(self.url)

        subdomain = extracted.subdomain

        dots = subdomain.count(".")

        if dots >= 2:
            self.score += 15
            self.reasons.append("Multiple subdomains detected")

    # -----------------------------
    # RULE 9: NUMBERS IN DOMAIN
    # -----------------------------

    def check_numbers_in_domain(self):

        domain = urlparse(self.url).netloc

        if any(char.isdigit() for char in domain):
            self.score += 10
            self.reasons.append("Numbers detected in domain")

    # -----------------------------
    # RULE 10: HTTPS TOKEN
    # -----------------------------

    def check_https_token(self):

        domain = urlparse(self.url).netloc

        if "https" in domain:
            self.score += 15
            self.reasons.append("HTTPS token inside domain")

    # -----------------------------
    # RULE 11: SUSPICIOUS KEYWORDS
    # -----------------------------

    def check_keywords(self):

        keywords = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "bank",
            "confirm",
            "password"
        ]

        for word in keywords:
            if word in self.url.lower():
                self.score += 10
                self.reasons.append(f"Suspicious keyword: {word}")

    # -----------------------------
    # RULE 12: SUSPICIOUS TLD
    # -----------------------------

    def check_tld(self):

        suspicious = ["xyz", "tk", "ml", "gq", "top"]

        extracted = tldextract.extract(self.url)

        if extracted.suffix in suspicious:
            self.score += 10
            self.reasons.append(f"Suspicious domain extension: {extracted.suffix}")

    # -----------------------------
    # RULE 13: DOMAIN AGE
    # -----------------------------

    def check_domain_age(self):

        try:
            domain = urlparse(self.url).netloc
            w = whois.whois(domain)

            if not w.creation_date:
                self.score += 15
                self.reasons.append("Domain age could not be verified")

        except:
            pass

    # -----------------------------
    # RULE 14: DOMAIN EXPIRY
    # -----------------------------

    def check_domain_expiry(self):

        try:
            domain = urlparse(self.url).netloc
            w = whois.whois(domain)

            if w.expiration_date is None:
                self.score += 10
                self.reasons.append("Domain expiration unknown")

        except:
            pass

    # -----------------------------
    # RULE 15: DNS RECORD
    # -----------------------------

    def check_dns_record(self):

        try:
            domain = urlparse(self.url).netloc
            socket.gethostbyname(domain)
        except:
            self.score += 20
            self.reasons.append("DNS record not found")

    # -----------------------------
    # RULE 16: PORT CHECK
    # -----------------------------

    def check_port(self):

        parsed = urlparse(self.url)

        if parsed.port not in [None, 80, 443]:
            self.score += 10
            self.reasons.append("Non-standard port detected")

    # -----------------------------
    # MAIN ANALYSIS
    # -----------------------------

    def analyze(self):

        if not self.check_valid_url():
            return {"score": 0, "reasons": ["Invalid URL"]}

        self.check_https()
        self.check_url_length()
        self.check_ip_address()
        self.check_url_shortener()
        self.check_at_symbol()
        self.check_double_slash()
        self.check_hyphen()
        self.check_subdomain()
        self.check_numbers_in_domain()
        self.check_https_token()
        self.check_keywords()
        self.check_tld()
        self.check_domain_age()
        self.check_domain_expiry()
        self.check_dns_record()
        self.check_port()

        return {
            "score": self.score,
            "reasons": self.reasons
        }


# -----------------------------
# MAIN PROGRAM
# -----------------------------

if __name__ == "__main__":

    url = input("Enter URL: ")

    analyzer = URLAnalyzer(url)

    result = analyzer.analyze()

    print("\nRisk Score:", result["score"])

    print("\nReasons:")

    for r in result["reasons"]:
        print("-", r)


