import json
import argparse
from core.scanner import SecureScanner
from core.analyzer import DPDPAnalyzer
from utils.logger import setup_secure_logger

logger = setup_secure_logger("DPDP_Main")

def main():
    # Set up the command-line argument parser
    parser = argparse.ArgumentParser(description="Advanced DPDP Compliance Auditor")
    parser.add_argument(
        "url", 
        type=str, 
        help="The target website URL to audit (e.g., https://example.com)"
    )
    
    # Parse the URL provided in the terminal
    args = parser.parse_args()
    target_site = args.url

    logger.info("Starting DPDP Auditor Initialization...")
    
    # Initialize the scanner
    scanner = SecureScanner(timeout=15)
    
    # Fetch the content using the terminal-provided URL
    parsed_html = scanner.fetch_page_content(target_site)
    
    if parsed_html:
        logger.info(f"Successfully retrieved HTML for {target_site}. Proceeding to analysis...")
        
        # Initialize the analyzer
        analyzer = DPDPAnalyzer(parsed_html)
        
        # Run the audit
        audit_report = analyzer.run_full_audit()
        
        # Print the structured report dynamically based on the target
        print(f"\n--- SECURE DPDP AUDIT REPORT FOR {target_site.upper()} ---")
        print(json.dumps(audit_report, indent=4))
        print("-" * 60 + "\n")
        
    else:
        logger.error(f"Audit failed due to unreachable target or parsing error for {target_site}.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nAudit safely aborted by user.")
    except Exception as e:
        logger.critical(f"Fatal systemic error: {e}")