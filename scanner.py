import requests
import urllib3
from bs4 import BeautifulSoup
from typing import Optional, Dict
from utils.logger import setup_secure_logger
from requests.exceptions import RequestException, Timeout

# Suppress the insecure request warning that pops up when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_secure_logger(__name__)

class SecureScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        # Professional headers to identify the bot and prevent generic blocking
        self.headers: Dict[str, str] = {
            "User-Agent": "DPDPAuditorBot/1.0 (Compliance Scanning)",
            "Accept": "text/html,application/xhtml+xml",
        }

    def fetch_page_content(self, target_url: str) -> Optional[BeautifulSoup]:
        """
        Fetches and parses the HTML of a target URL.
        Bypasses strict local SSL verification to prevent network-level blocking.
        """
        if not target_url.startswith("https://"):
            logger.warning(f"Insecure protocol detected. Forcing HTTPS for {target_url}")
            target_url = target_url.replace("http://", "https://")

        try:
            logger.info(f"Initiating scan for: {target_url}")
            
            # verify=False bypasses the local certificate issuer error
            response = requests.get(
                target_url, 
                headers=self.headers, 
                timeout=self.timeout, 
                verify=False  
            )
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
            
            return BeautifulSoup(response.text, 'html.parser')

        except Timeout:
            logger.error(f"Connection timed out while trying to reach {target_url}")
        except RequestException as e:
            logger.error(f"A connection error occurred: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during scanning: {e}")
            
        return None