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
logger = logging.getLogger("TrustScore_API")

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

# 3. INTEGRATED ANALYZER
class DPDPAnalyzer:
    def __init__(self, parsed_html: BeautifulSoup):
        self.soup = parsed_html
        self.privacy_keywords = re.compile(r'(privacy|data protection|dpdp|terms)', re.IGNORECASE)
        self.cookie_keywords = re.compile(r'(cookie|consent|tracking|gdpr|dpdp)', re.IGNORECASE)

    def check_privacy_policy(self) -> Dict[str, Any]:
        policy_links = [a['href'] for a in self.soup.find_all('a', href=True) if self.privacy_keywords.search(a.get_text())]
        status = "Pass" if policy_links else "Fail"
        return {"check": "Privacy Policy", "status": status, "found_links": list(set(policy_links))}

    def check_cookie_consent(self) -> Dict[str, Any]:
        found = bool(self.soup.find_all(attrs={"id": self.cookie_keywords, "class": self.cookie_keywords}))
        return {"check": "Cookie Banner", "status": "Pass" if found else "Warning", "details": "Found" if found else "Not detected"}

    def check_form_consent(self) -> Dict[str, Any]:
        forms = self.soup.find_all('form')
        failed = sum(1 for f in forms if not f.find_all('input', type='checkbox'))
        status = "Pass" if failed == 0 and forms else "Fail"
        return {"check": "Form Consent", "status": status, "total_forms_found": len(forms)}

    def check_privacy_officer(self) -> Dict[str, Any]:
        text = self.soup.get_text(separator=' ', strip=True)
        officer_pattern = re.compile(r'\b(grievance officer|data protection officer|privacy officer)\b', re.IGNORECASE)
        found = officer_pattern.search(text)
        return {"check": "Grievance Officer", "status": "Pass" if found else "Fail", "matched_text": found.group(0) if found else "None"}

    def run_full_audit(self) -> Dict[str, Any]:
        p, c, f, o = self.check_privacy_policy(), self.check_cookie_consent(), self.check_form_consent(), self.check_privacy_officer()
        score = (30 if p["status"]=="Pass" else 0) + (20 if c["status"]=="Pass" else 10 if c["status"]=="Warning" else 0) + (10 if f["status"]=="Pass" else 0) + (40 if o["status"]=="Pass" else 0)
        risk = "LOW RISK" if score >= 80 else "MODERATE RISK" if score >= 50 else "CRITICAL RISK"
        return {"trust_score": {"score": score, "risk_level": risk}, "checks": {"privacy_policy": p, "cookie_consent": c, "form_consent": f, "privacy_officer": o}}

# 4. API & ROUTES
app = FastAPI(title="TrustScore DPDP Auditor")

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
    return {"error": "index.html not found"}

@app.post("/api/v1/audit")
def run_audit(request: AuditRequest):
    logger.info(f"Auditing: {request.target_url}")
    scanner = SecureScanner(timeout=15)
    parsed_html = scanner.fetch_page_content(request.target_url)
    if not parsed_html:
        raise HTTPException(status_code=400, detail="Could not reach website.")
    try:
        analyzer = DPDPAnalyzer(parsed_html)
        report = analyzer.run_full_audit()
        return {"success": True, "target": request.target_url, "data": report}
    except Exception as e:
        logger.error(f"Audit Error: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis error.")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
