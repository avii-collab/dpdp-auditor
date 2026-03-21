import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn

from core.scanner import SecureScanner
from core.analyzer import DPDPAnalyzer
from utils.logger import setup_secure_logger

logger = setup_secure_logger("DPDP_API")

# Initialize the enterprise FastAPI application
app = FastAPI(
    title="TrustScore DPDP Auditor API",
    description="Enterprise API for scanning web properties for DPDP Act 2023 compliance.",
    version="1.0.0"
)

# Open the gates so the frontend can talk to the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    target_url: str

# --- THE MAGIC FIX: Serve the HTML Dashboard directly from the API ---
@app.get("/")
def serve_dashboard():
    """Serves the frontend UI directly so we don't get browser security blocks."""
    # Checks your main folder first
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    # Checks your core folder (based on your screenshot)
    elif os.path.exists("core/index.html"):
        return FileResponse("core/index.html")
    else:
        return {"error": "Dashboard HTML file not found."}

@app.post("/api/v1/audit")
def run_audit(request: AuditRequest):
    """The main enterprise endpoint that runs the Python engine."""
    logger.info(f"API received audit request for: {request.target_url}")
    
    scanner = SecureScanner(timeout=15)
    parsed_html = scanner.fetch_page_content(request.target_url)
    
    if not parsed_html:
        logger.error(f"API failed to parse target: {request.target_url}")
        raise HTTPException(status_code=400, detail="Audit failed. Target unreachable or parsing error.")
        
    try:
        analyzer = DPDPAnalyzer(parsed_html)
        report = analyzer.run_full_audit()
        logger.info("API successfully generated report.")
        return {
            "success": True,
            "target": request.target_url,
            "data": report
        }
    except Exception as e:
        logger.critical(f"API Analysis error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis.")

if __name__ == "__main__":
    # Runs the server locally
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
    # ... (all your existing code above)

if __name__ == "__main__":
    import os
    # Cloud providers like Render use an environment variable called PORT
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)