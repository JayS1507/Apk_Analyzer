from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import json
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from apk_analyzer import APKAnalyzer
from report_generator import ReportGenerator

app = FastAPI(title="APK Inspector API", version="1.0.0")

# ✅ FIXED CORS (Allow Netlify + Local Dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://apkinciptor.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directories
UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("output")
REPORTS_DIR = Path("reports")

for directory in [UPLOAD_DIR, OUTPUT_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True)

analyzer = APKAnalyzer()
report_gen = ReportGenerator()

analysis_status = {}

@app.get("/")
async def root():
    return {"message": "APK Inspector API is running"}

@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)):

    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Only APK files allowed")

    analysis_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{analysis_id}.apk"

    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    analysis_status[analysis_id] = {
        "status": "uploaded",
        "progress": 0,
        "created_at": datetime.now().isoformat()
    }

    return {"analysis_id": analysis_id, "status": "uploaded"}

@app.post("/analyze/{analysis_id}")
async def analyze_apk(analysis_id: str, background_tasks: BackgroundTasks, password: str | None = None):

    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404)

    background_tasks.add_task(run_analysis, analysis_id, password)

    analysis_status[analysis_id]["status"] = "analyzing"

    return {"message": "Analysis started"}

async def run_analysis(analysis_id: str, password=None):

    try:
        apk_path = UPLOAD_DIR / f"{analysis_id}.apk"
        output_path = OUTPUT_DIR / analysis_id

        result = await analyzer.analyze_apk(str(apk_path), str(output_path), password=password)

        analysis_status[analysis_id]["status"] = "completed"
        analysis_status[analysis_id]["result"] = result

    except Exception as e:
        analysis_status[analysis_id]["status"] = "error"
        analysis_status[analysis_id]["error"] = str(e)

@app.get("/status/{analysis_id}")
async def get_status(analysis_id: str):

    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404)

    return analysis_status[analysis_id]

# -------------------------
# ✅ IMPORTANT PRODUCTION FIX
# -------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))

    uvicorn.run(app, host="0.0.0.0", port=port)
