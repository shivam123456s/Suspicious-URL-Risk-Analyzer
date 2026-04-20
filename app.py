from flask import Flask, render_template, request
from analyzer import URLAnalyzer
from urllib.parse import urlparse
from datetime import datetime
import socket
import requests
from bs4 import BeautifulSoup
import ssl
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ================= BREACHED DOMAINS =================
BREACHED_DOMAINS = [
    "yahoo.com",
    "linkedin.com",
    "adobe.com",
    "dropbox.com",
    "facebook.com",
]

# ================= VIRUSTOTAL =================
def check_virustotal(url):
    API_KEY = os.getenv("VT_API_KEY")

    if not API_KEY:
        return None

    headers = {"x-apikey": API_KEY}
    data = {"url": url}

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=5
        )

        if response.status_code != 200:
            return None

        url_id = response.json()["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers,
            timeout=5
        )

        return report.json()["data"]["attributes"]["stats"]

    except:
        return None


# ================= SSL CHECK =================
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days

        return {
            "status": "Valid" if days_left > 0 else "Expired",
            "expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_left": days_left,
        }

    except:
        return {
            "status": "No SSL",
            "expiry": "N/A",
            "days_left": "N/A",
        }


# ================= MAIN ROUTE =================
@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    level = None
    report = None
    extra = None
    error = None
    breach_warning = None
    vt_result = None
    ssl_info = None

    if request.method == "POST":

        url = request.form.get("url")
        use_vt = request.form.get("use_vt")

        if not url:
            error = "Please enter a URL"
            return render_template("index.html", error=error)

        try:
            analyzer = URLAnalyzer(url)
            result = analyzer.analyze()

            parsed = urlparse(url)
            domain = parsed.netloc
            protocol = parsed.scheme

            # SSL CHECK
            ssl_info = check_ssl(domain)

            # IP
            try:
                ip = socket.gethostbyname(domain)
            except:
                ip = "Unknown"

            # HTTP REQUEST (FAST + SAFE)
            try:
                headers_req = {"User-Agent": "Mozilla/5.0"}
                response = requests.get(url, headers=headers_req, timeout=3)

                status = response.status_code
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string if soup.title else "No title found"
                headers = response.headers

            except:
                status = "Blocked / Timeout"
                title = "Unknown"
                headers = {}

            # SECURITY HEADERS
            security_headers = {
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Not found"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not found"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Not found"),
            }

            # ================= SCORE =================
            score = result.get("score", 0)

            if protocol != "https":
                score += 20
                result["reasons"].append("Not using HTTPS")

            if ssl_info["status"] != "Valid":
                score += 20
                result["reasons"].append("Invalid SSL certificate")

            if status == "Blocked / Timeout":
                score += 20
                result["reasons"].append("Server not responding")

            missing_headers = [k for k, v in security_headers.items() if v == "Not found"]
            if len(missing_headers) >= 2:
                score += 10
                result["reasons"].append("Missing security headers")

            if domain in BREACHED_DOMAINS:
                score += 10
                breach_warning = "⚠ Domain involved in past breaches"

            score = min(score, 100)
            result["score"] = score

            # LEVEL
            if score <= 30:
                level = "Safe"
            elif score <= 70:
                level = "Suspicious"
            else:
                level = "Dangerous"

            # RATING
            if score <= 20:
                rating = "A"
            elif score <= 40:
                rating = "B"
            elif score <= 60:
                rating = "C"
            else:
                rating = "D"

            # VIRUSTOTAL (OPTIONAL)
            if use_vt:
                vt_result = check_virustotal(url)

            # FINAL DATA
            report = {
                "url": url,
                "domain": domain,
                "protocol": protocol,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            extra = {
                "ip": ip,
                "status": status,
                "title": title,
                "headers": security_headers,
                "rating": rating,
            }

        except:
            error = "Something went wrong"

    return render_template(
        "index.html",
        result=result,
        level=level,
        report=report,
        extra=extra,
        error=error,
        breach_warning=breach_warning,
        vt_result=vt_result,
        ssl_info=ssl_info,
    )


# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)