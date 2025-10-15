# APK Inspector - Test Commands

This file contains example commands for testing the APK Inspector application.

## Backend API Testing

### 1. Upload APK File
```bash
curl -X POST -F "file=@sample.apk" http://localhost:8000/upload
```

Expected response:
```json
{
  "analysis_id": "12345678-1234-1234-1234-123456789abc",
  "filename": "sample.apk",
  "file_size": 15728640,
  "status": "uploaded"
}
```

### 2. Start Analysis
```bash
curl -X POST http://localhost:8000/analyze/12345678-1234-1234-1234-123456789abc
```

Expected response:
```json
{
  "message": "Analysis started",
  "analysis_id": "12345678-1234-1234-1234-123456789abc"
}
```

### 3. Check Analysis Status
```bash
curl http://localhost:8000/status/12345678-1234-1234-1234-123456789abc
```

Expected response:
```json
{
  "status": "analyzing",
  "progress": 50,
  "message": "Decompiling APK...",
  "created_at": "2023-12-01T10:30:00"
}
```

### 4. Get Analysis Results
```bash
curl http://localhost:8000/results/12345678-1234-1234-1234-123456789abc
```

Expected response: See `examples/sample_analysis_output.json`

### 5. Generate PDF Report
```bash
curl -X POST "http://localhost:8000/report/12345678-1234-1234-1234-123456789abc?format=pdf" -o report.pdf
```

### 6. Generate HTML Report
```bash
curl -X POST "http://localhost:8000/report/12345678-1234-1234-1234-123456789abc?format=html" -o report.html
```

### 7. List All Reports
```bash
curl http://localhost:8000/reports
```

## Direct Tool Testing

### Test apktool
```bash
apktool d sample.apk -o output_folder
```

### Test jadx
```bash
jadx -d output_java sample.apk
```

### Test androguard (Python)
```python
from androguard.core.bytecodes import apk
a = apk.APK('sample.apk')
print(f"Package: {a.get_package()}")
print(f"Version: {a.get_androidversion_name()}")
print(f"Permissions: {a.get_permissions()}")
```

## Frontend Testing

### 1. Start Frontend
```bash
cd frontend
npm start
```

### 2. Open Browser
Navigate to: http://localhost:3000

### 3. Test Upload
- Drag and drop an APK file
- Or click to select an APK file
- Verify upload success message

### 4. Test Analysis
- Click "Start Analysis" button
- Watch progress indicator
- Verify completion message

### 5. Test Reports
- Click "Download PDF Report"
- Click "Download HTML Report"
- Verify files download successfully

## Error Testing

### Test Invalid File Type
```bash
curl -X POST -F "file=@test.txt" http://localhost:8000/upload
```

Expected response:
```json
{
  "detail": "Only APK files are allowed"
}
```

### Test Non-existent Analysis ID
```bash
curl http://localhost:8000/status/invalid-id
```

Expected response:
```json
{
  "detail": "Analysis ID not found"
}
```

## Performance Testing

### Large APK Test
```bash
# Test with a large APK file (>100MB)
curl -X POST -F "file=@large_app.apk" http://localhost:8000/upload
```

### Multiple Concurrent Uploads
```bash
# Test multiple uploads simultaneously
curl -X POST -F "file=@app1.apk" http://localhost:8000/upload &
curl -X POST -F "file=@app2.apk" http://localhost:8000/upload &
curl -X POST -F "file=@app3.apk" http://localhost:8000/upload &
```

## Security Testing

### Test Malicious APK
- Upload APK with suspicious permissions
- Verify security warnings in report
- Check for URL/IP detection

### Test Corrupted APK
```bash
curl -X POST -F "file=@corrupted.apk" http://localhost:8000/upload
```

## Integration Testing

### Full Workflow Test
1. Upload APK
2. Start analysis
3. Monitor progress
4. Download PDF report
5. Download HTML report
6. Verify all data is consistent

### Browser Compatibility
- Test in Chrome
- Test in Firefox
- Test in Safari
- Test in Edge

## Load Testing

### Multiple Users
- Simulate multiple users uploading APKs
- Monitor server performance
- Check for memory leaks

### Long-running Analysis
- Test with very large APK files
- Monitor timeout handling
- Check progress reporting

