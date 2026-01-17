from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import subprocess
import json
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List
import asyncio
from datetime import datetime

from apk_analyzer import APKAnalyzer
from report_generator import ReportGenerator

app = FastAPI(title="APK Inspector API", version="1.0.0")

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create necessary directories
UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("output")
REPORTS_DIR = Path("reports")

for directory in [UPLOAD_DIR, OUTPUT_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True)

# Initialize analyzer and report generator
analyzer = APKAnalyzer()
report_gen = ReportGenerator()

# Store analysis status
analysis_status = {}

@app.get("/")
async def root():
    return {"message": "APK Inspector API is running"}

@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    """Upload APK file and return analysis ID"""
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Only APK files are allowed")
    
    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())
    
    # Save uploaded file
    file_path = UPLOAD_DIR / f"{analysis_id}.apk"
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
    
    # Initialize analysis status
    analysis_status[analysis_id] = {
        "status": "uploaded",
        "progress": 0,
        "message": "File uploaded successfully",
        "created_at": datetime.now().isoformat()
    }
    
    return {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "file_size": len(content),
        "status": "uploaded"
    }

@app.post("/analyze/{analysis_id}")
async def analyze_apk(analysis_id: str, background_tasks: BackgroundTasks, password: str | None = None):
    """Start APK analysis in background"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    
    # Start background analysis
    background_tasks.add_task(run_analysis, analysis_id, password)
    
    analysis_status[analysis_id]["status"] = "analyzing"
    analysis_status[analysis_id]["message"] = "Analysis started"
    
    return {"message": "Analysis started", "analysis_id": analysis_id}

async def run_analysis(analysis_id: str, password: str | None = None):
    """Run the actual APK analysis"""
    try:
        analysis_status[analysis_id]["status"] = "analyzing"
        analysis_status[analysis_id]["progress"] = 10
        analysis_status[analysis_id]["message"] = "Decompiling APK..."
        
        # Get file path
        apk_path = UPLOAD_DIR / f"{analysis_id}.apk"
        output_path = OUTPUT_DIR / analysis_id
        
        # Run analysis
        result = await analyzer.analyze_apk(str(apk_path), str(output_path), password=password)
        
        # Update status
        analysis_status[analysis_id]["status"] = "completed"
        analysis_status[analysis_id]["progress"] = 100
        analysis_status[analysis_id]["message"] = "Analysis completed"
        analysis_status[analysis_id]["result"] = result
        analysis_status[analysis_id]["completed_at"] = datetime.now().isoformat()
        
    except Exception as e:
        analysis_status[analysis_id]["status"] = "error"
        analysis_status[analysis_id]["message"] = f"Analysis failed: {str(e)}"
        analysis_status[analysis_id]["error"] = str(e)

@app.get("/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """Get analysis status and results"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    
    return analysis_status[analysis_id]

@app.get("/results/{analysis_id}")
async def get_analysis_results(analysis_id: str):
    """Get detailed analysis results"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")

    status = analysis_status[analysis_id]
    if status["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed yet")

    result = status["result"]

    # Add analysis consistency check
    metadata = result.get("analysis_metadata", {})
    if metadata:
        result["analysis_consistency"] = {
            "analysis_id": metadata.get("analysis_id"),
            "timestamp": metadata.get("timestamp"),
            "tools_used": metadata.get("tools_used", []),
            "deterministic_mode": metadata.get("deterministic_mode", False),
            "file_hash": metadata.get("file_hash")
        }

    return result

@app.get("/report/{analysis_id}")
async def generate_report(analysis_id: str, format: str = "pdf"):
    """Generate and download report"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    
    status = analysis_status[analysis_id]
    if status["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed yet")
    
    result = status["result"]
    
    if format == "pdf":
        report_path = await report_gen.generate_pdf_report(result, analysis_id)
        return FileResponse(
            report_path,
            media_type="application/pdf",
            filename=f"apk_report_{analysis_id}.pdf"
        )
    elif format == "html":
        report_path = await report_gen.generate_html_report(result, analysis_id)
        return FileResponse(
            report_path,
            media_type="text/html",
            filename=f"apk_report_{analysis_id}.html"
        )
    elif format == "json":
        report_path = await report_gen.generate_json_report(result, analysis_id)
        return FileResponse(
            report_path,
            media_type="application/json",
            filename=f"apk_report_{analysis_id}.json"
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'pdf', 'html', or 'json'")

@app.get("/reports")
async def list_reports():
    """List all available reports"""
    reports = []
    for file in REPORTS_DIR.glob("*"):
        if file.is_file():
            reports.append({
                "filename": file.name,
                "created_at": datetime.fromtimestamp(file.stat().st_ctime).isoformat(),
                "size": file.stat().st_size
            })
    return {"reports": reports}

@app.get("/download/{analysis_id}/decompiled")
async def download_decompiled_files(analysis_id: str, tool: str = "jadx"):
    """Download decompiled files as a zip archive"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    
    status = analysis_status[analysis_id]
    if status["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed yet")
    
    # Get the output directory
    output_path = OUTPUT_DIR / analysis_id
    
    if tool == "jadx":
        decompiled_dir = output_path / "jadx_output"
    elif tool == "apktool":
        decompiled_dir = output_path / "apktool_output"
    else:
        raise HTTPException(status_code=400, detail="Invalid tool. Use 'jadx' or 'apktool'")
    
    if not decompiled_dir.exists():
        raise HTTPException(status_code=404, detail=f"Decompiled files not found for tool: {tool}")
    
    # Create a zip file
    import zipfile
    import tempfile
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
        with zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(decompiled_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, decompiled_dir)
                    zipf.write(file_path, arcname)
        
        return FileResponse(
            tmp_file.name,
            media_type="application/zip",
            filename=f"decompiled_{tool}_{analysis_id}.zip"
        )

@app.get("/files/{analysis_id}")
async def list_analysis_files(analysis_id: str):
    """List all files generated during analysis"""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    
    output_path = OUTPUT_DIR / analysis_id
    if not output_path.exists():
        return {"files": [], "message": "No analysis files found"}
    
    files = []
    for root, dirs, filenames in os.walk(output_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, output_path)
            files.append({
                "name": filename,
                "path": rel_path,
                "size": os.path.getsize(file_path),
                "type": "file"
            })
    
    return {"files": files, "analysis_id": analysis_id}

# Simple retrieval-augmented Q&A over analysis results and decompiled files
@app.post("/chat/{analysis_id}")
async def chat_with_analysis(analysis_id: str, query: str):
    """Answer questions about the analyzed app by searching results and code."""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    status = analysis_status[analysis_id]
    if status.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed yet")

    result = status.get("result", {})
    output_path = OUTPUT_DIR / analysis_id

    # 1) Search structured JSON results for key matches
    highlights: List[Dict[str, Any]] = []
    q = (query or "").lower()
    def add_highlight(kind: str, key: str, value: Any):
        try:
            preview = value if isinstance(value, str) else json.dumps(value)[:800]
        except Exception:
            preview = str(value)[:800]
        highlights.append({"type": kind, "key": key, "snippet": preview})

    for k, v in result.items():
        try:
            text = v if isinstance(v, str) else json.dumps(v)
        except Exception:
            text = str(v)
        if q and q in str(text).lower():
            add_highlight("result", k, v)

    # 2) Search decompiled files for keyword matches (limited scan for performance)
    code_hits: List[Dict[str, Any]] = []
    search_dirs = []
    for sub in ["jadx_output", "apktool_output"]:
        p = output_path / sub
        if p.exists():
            search_dirs.append(p)

    max_files_scanned = 800
    files_scanned = 0
    if q:
        for base in search_dirs:
            for root, dirs, files in os.walk(base):
                # Prefer Java, smali, manifest, xml
                prioritized = [f for f in files if f.endswith((".java", ".kt", ".smali", ".xml", "AndroidManifest.xml"))]
                other = [f for f in files if f not in prioritized]
                for file in prioritized + other:
                    if files_scanned >= max_files_scanned:
                        break
                    files_scanned += 1
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                        if q in content.lower():
                            # Provide a short snippet around first occurrence
                            idx = content.lower().find(q)
                            start = max(0, idx - 300)
                            end = min(len(content), idx + 300)
                            snippet = content[start:end]
                            rel = os.path.relpath(file_path, base)
                            code_hits.append({"path": str((Path(base.name) / rel).as_posix()), "snippet": snippet})
                    except Exception:
                        continue
                if files_scanned >= max_files_scanned:
                    break

    # Compose a lightweight answer
    answer_parts = []
    # Heuristics for common questions
    if any(w in q for w in ["package", "application id", "app id"]):
        pkg = result.get("package_name") or "Unknown"
        answer_parts.append(f"Package name: {pkg}")
    if any(w in q for w in ["main activity", "launcher", "entry"]):
        main_activity = result.get("main_activity") or next(iter(result.get("activities", [])), None) or "Unknown"
        answer_parts.append(f"Main activity: {main_activity}")
    if "permission" in q:
        perms = result.get("permissions", [])
        answer_parts.append(f"Permissions count: {len(perms)}")
    if any(w in q for w in ["url", "endpoint", "api"]):
        urls = result.get("urls_found", [])
        answer_parts.append(f"URLs found: {min(len(urls), 50)} shown")

    # Default fallback
    if not answer_parts and highlights:
        # Summarize the keys matched
        keys = list({h["key"] for h in highlights})[:5]
        if keys:
            answer_parts.append("Found relevant data in: " + ", ".join(keys))
    if not answer_parts and code_hits:
        answer_parts.append("Found relevant occurrences in decompiled code.")
    if not answer_parts:
        answer_parts.append("I couldn't find a direct answer. Try rephrasing or use more specific keywords.")

    return {
        "answer": " \n".join(answer_parts),
        "highlights": highlights[:10],
        "code_hits": code_hits[:10],
        "scanned_files": files_scanned
    }

@app.get("/file/{analysis_id}")
async def get_file_content(analysis_id: str, path: str):
    """Fetch a specific decompiled file content by relative path (safe, read-only)."""
    if analysis_id not in analysis_status:
        raise HTTPException(status_code=404, detail="Analysis ID not found")

    base = OUTPUT_DIR / analysis_id
    # Normalize and prevent path traversal
    safe_path = (base / path).resolve()
    if base.resolve() not in safe_path.parents and base.resolve() != safe_path:
        raise HTTPException(status_code=400, detail="Invalid path")
    if not safe_path.exists() or not safe_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    # Limit file size
    max_bytes = 2_000_000
    size = safe_path.stat().st_size
    if size > max_bytes:
        return JSONResponse(status_code=413, content={"error": "File too large to preview", "size": size})

    with open(safe_path, "r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read()
    return {"path": path, "size": size, "content": content}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

