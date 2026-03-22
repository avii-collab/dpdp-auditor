import os
import re
import uvicorn
import requests
import logging
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# 1. INTEGRATED LOGGER
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TrustScore_Pro")

# 2. INTEGRATED SCANNER
class SecureScanner:
    def __init__(self, timeout=15):
        self.timeout = timeout
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrustScore-Auditor/1.0'}

    def fetch_page_content(self, url: str):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            logger.error(f"Scan failed for {url}: {e}")
            return None

# 3. INTEGRATED ANALYZER (WITH PAYWALL TEASERS)
class DPDPAnalyzer:
    def __init__(self, parsed_html: BeautifulSoup):
        self.soup = parsed_html
        self.privacy_keywords = re.compile(r'(privacy|data protection|dpdp|terms)', re.IGNORECASE)
        self.cookie_keywords = re.compile(r'(cookie|consent|tracking|gdpr|dpdp)', re.IGNORECASE)

    def check_privacy_policy(self) -> Dict[str, Any]:
        links = [a['href'] for a in self.soup.find_all('a', href=True) if self.privacy_keywords.search(a.get_text())]
        passed = len(links) > 0
        return {
            "check": "Privacy Policy",
            "status": "Pass" if passed else "Fail",
            "solution": "Compliant." if passed else "CRITICAL: Missing or non-compliant Privacy Policy (Section 8 violation). Fines reach ₹250 Cr. Unlock to get the exact DPDP-compliant legal template."
        }

    def check_cookie_consent(self) -> Dict[str, Any]:
        found = bool(self.soup.find_all(attrs={"id": self.cookie_keywords, "class": self.cookie_keywords}))
        return {
            "check": "Cookie Banner",
            "status": "Pass" if found else "Warning",
            "solution": "Compliant." if found else "WARNING: Active tracking without explicit consent detected. Unlock to get the compliant cookie banner code and implementation guide."
        }

    def check_form_consent(self) -> Dict[str, Any]:
        forms = self.soup.find_all('form')
        no_consent = sum(1 for f in forms if not f.find_all('input', type='checkbox'))
        passed = (no_consent == 0 and len(forms) > 0)
        return {
            "check": "Form Consent",
            "status": "Pass" if passed else "Fail",
            "solution": "Compliant." if passed else "CRITICAL: Data collection forms lack mandatory explicit consent checkboxes. Unlock to get the legally compliant frontend code."
        }

    def check_privacy_officer(self) -> Dict[str, Any]:
        text = self.soup.get_text(separator=' ', strip=True)
        officer_pattern = re.compile(r'\b(grievance officer|data protection officer|privacy officer)\b', re.IGNORECASE)
        found = officer_pattern.search(text)
        return {
            "check": "Grievance Officer",
            "status": "Pass" if found else "Fail",
            "solution": "Compliant." if found else "CRITICAL: Missing Grievance Officer details (Section 10 violation). Unlock to get the legally required contact section template."
        }

    def run_full_audit(self) -> Dict[str, Any]:
        results = [self.check_privacy_policy(), self.check_cookie_consent(), self.check_form_consent(), self.check_privacy_officer()]
        score = sum(30 if r["status"]=="Pass" else (10 if r["status"]=="Warning" else 0) for r in results)
        risk = "LOW RISK" if score >= 80 else "MODERATE RISK" if score >= 50 else "CRITICAL RISK"
        return {"trust_score": {"score": score, "risk_level": risk}, "detailed_analysis": results}

# 4. API & ROUTES
app = FastAPI(title="TrustScore DPDP Auditor Pro")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    target_url: str

@app.get("/")
def serve_dashboard():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"error": "Dashboard HTML (index.html) not found in root directory."}

@app.post("/api/v1/audit")
def run_audit(request: AuditRequest):
    logger.info(f"Enterprise Audit initiated: {request.target_url}")
    scanner = SecureScanner()
    parsed_html = scanner.fetch_page_content(request.target_url)
    if not parsed_html:
        raise HTTPException(status_code=400, detail="Target website unreachable. Check URL formatting.")
    try:
        analyzer = DPDPAnalyzer(parsed_html)
        report = analyzer.run_full_audit()
        return {"success": True, "target": request.target_url, "report": report}
    except Exception as e:
        logger.error(f"Audit Failure: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during compliance analysis.")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
