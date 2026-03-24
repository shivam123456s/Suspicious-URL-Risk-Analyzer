from flask import Flask, render_template, request
from analyzer import URLAnalyzer
from urllib.parse import urlparse
from datetime import datetime
import socket
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Simple breach database (for demo)
BREACHED_DOMAINS = [ 
    
    "yahoo.com",
    "linkedin.com",
    "adobe.com",
    "dropbox.com",
    "facebook.com"
]

@app.route("/", methods=["GET","POST"])
def home():

    result = None
    level = None
    report = None
    extra = None
    breach_warning = None

    if request.method == "POST":

        url = request.form["url"]

        analyzer = URLAnalyzer(url)
        result = analyzer.analyze()

        score = result["score"]

        # Risk level
        if score <= 30:
            level = "Safe"
        elif score <= 60:
            level = "Suspicious"
        else:
            level = "Dangerous"

        parsed = urlparse(url)

        domain = parsed.netloc
        protocol = parsed.scheme
        port = parsed.port

        # IP address
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Unknown"

        # HTTP request
        try:
            response = requests.get(url, timeout=5)
            status = response.status_code

            soup = BeautifulSoup(response.text, "html.parser")

            title = soup.title.string if soup.title else "No title found"

            headers = response.headers

        except:
            status = "No response"
            title = "Unknown"
            headers = {}

        # Security headers
        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options")
        }

        # Security Rating
        if score <= 20:
            rating = "A"
        elif score <= 40:
            rating = "B"
        elif score <= 60:
            rating = "C"
        else:
            rating = "D"

        # Breach check
        if domain in BREACHED_DOMAINS:
            breach_warning = "⚠ This domain has been involved in past data breaches."

        report = {
            "url": url,
            "domain": domain,
            "protocol": protocol,
            "port": port,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        extra = {
            "ip": ip,
            "status": status,
            "title": title,
            "headers": security_headers,
            "rating": rating
        }

    return render_template(
        "index.html",
        result=result,
        level=level,
        report=report,
        extra=extra,
        breach_warning=breach_warning
    )

if __name__ == "__main__":
    app.run(debug=True) 