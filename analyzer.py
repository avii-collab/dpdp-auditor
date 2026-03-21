import re
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from utils.logger import setup_secure_logger

logger = setup_secure_logger(__name__)

class DPDPAnalyzer:
    def __init__(self, parsed_html: BeautifulSoup):
        self.soup = parsed_html
        self.privacy_keywords = re.compile(r'(privacy|data protection|dpdp|terms)', re.IGNORECASE)
        self.cookie_keywords = re.compile(r'(cookie|consent|tracking|gdpr|dpdp)', re.IGNORECASE)
        logger.info("DPDP Analyzer initialized with security constraints.")

    def check_privacy_policy(self) -> Dict[str, Any]:
        logger.info("Scanning for Privacy Policy links...")
        policy_links: List[str] = []
        for a_tag in self.soup.find_all('a', href=True):
            text = a_tag.get_text(strip=True)
            if self.privacy_keywords.search(text):
                policy_links.append(a_tag['href'])
        status = "Pass" if policy_links else "Fail"
        return {
            "check": "Privacy Policy Visibility",
            "status": status,
            "found_links": list(set(policy_links)), 
            "severity": "High" if status == "Fail" else "None"
        }

    def check_cookie_consent(self) -> Dict[str, Any]:
        logger.info("Scanning for Cookie Consent mechanisms...")
        consent_found = False
        suspicious_elements = self.soup.find_all(attrs={"id": self.cookie_keywords, "class": self.cookie_keywords})
        if suspicious_elements:
            consent_found = True
        status = "Pass" if consent_found else "Warning"
        return {
            "check": "Cookie Consent Banner",
            "status": status,
            "details": "Potential consent mechanism found" if consent_found else "No obvious consent banner detected in DOM",
            "severity": "Medium" if status == "Warning" else "None"
        }

    def check_form_consent(self) -> Dict[str, Any]:
        logger.info("Auditing data collection forms for explicit consent...")
        forms = self.soup.find_all('form')
        failed_forms = 0
        total_forms = len(forms)
        for index, form in enumerate(forms):
            checkboxes = form.find_all('input', type='checkbox')
            if not checkboxes:
                failed_forms += 1
        status = "Pass" if failed_forms == 0 else "Fail"
        return {
            "check": "Form Consent Checkboxes",
            "status": status if total_forms > 0 else "N/A",
            "total_forms_found": total_forms,
            "forms_missing_consent": failed_forms,
            "severity": "High" if failed_forms > 0 else "None"
        }

    def check_privacy_officer(self) -> Dict[str, Any]:
        logger.info("Hunting for Privacy/Grievance Officer contact info...")
        clean_soup = BeautifulSoup(str(self.soup), 'html.parser')
        for hidden_code in clean_soup(["script", "style", "noscript", "meta", "header", "footer", "nav"]):
            hidden_code.extract()
        text_content = clean_soup.get_text(separator=' ', strip=True)
        
        officer_keywords = re.compile(r'\b(grievance officer|grievance redressal officer|data protection officer|privacy officer)\b', re.IGNORECASE)
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
        found_officer = officer_keywords.search(text_content)
        
        extracted_emails = []
        if found_officer:
            extracted_emails = list(set(email_pattern.findall(text_content)))
            
        status = "Pass" if found_officer else "Fail"
        return {
            "check": "Data Privacy/Grievance Officer",
            "status": status,
            "details": "Officer terminology found in visible text." if found_officer else "No legal officer found in readable content.",
            "matched_text": found_officer.group(0) if found_officer else "None", 
            "possible_contacts": extracted_emails[:3], 
            "severity": "High" if status == "Fail" else "None"
        }

    def run_full_audit(self) -> Dict[str, Any]:
        logger.info("Initiating full DPDP compliance audit...")
        
        # Run all individual checks
        privacy = self.check_privacy_policy()
        cookie = self.check_cookie_consent()
        form = self.check_form_consent()
        officer = self.check_privacy_officer()

        # NEW: The TrustScore Algorithm
        score = 0
        if privacy["status"] == "Pass": score += 30
        if cookie["status"] == "Pass": score += 20
        elif cookie["status"] == "Warning": score += 10 # Partial credit
        if form["status"] in ["Pass", "N/A"]: score += 10
        if officer["status"] == "Pass": score += 40

        # Determine risk level
        risk_level = "CRITICAL RISK"
        if score >= 80: risk_level = "LOW RISK"
        elif score >= 50: risk_level = "MODERATE RISK"

        report = {
            "trust_score": {
                "score": score,
                "out_of": 100,
                "risk_level": risk_level
            },
            "checks": {
                "privacy_policy": privacy,
                "cookie_consent": cookie,
                "form_consent": form,
                "privacy_officer": officer 
            }
        }
        
        logger.info(f"Audit complete. Final TrustScore: {score}/100")
        return report