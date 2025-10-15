# APK Inspector

A comprehensive desktop/web application for analyzing Android APK files. Upload an APK, automatically decompile it using open-source tools, and generate detailed reports showing app metadata, permissions, components, security analysis, and more.

## Features

- **APK Upload & Analysis**: Upload APK files through a modern web interface
- **Multi-Tool Decompilation**: Uses apktool, jadx, and androguard for comprehensive analysis
- **Structured Reports**: Generate PDF and HTML reports with detailed analysis
- **Security Analysis**: Detect URLs, IP addresses, and suspicious strings
- **Component Analysis**: Extract activities, services, receivers, and providers
- **Permission Analysis**: List all app permissions
- **Certificate Information**: Extract and display certificate details
- **Real-time Progress**: Live progress updates during analysis

## Project Structure

```
apk-inspector/
├── backend/                 # FastAPI backend
│   ├── main.py             # Main API server
│   ├── apk_analyzer.py     # APK analysis logic
│   ├── report_generator.py # PDF/HTML report generation
│   └── requirements.txt    # Python dependencies
├── frontend/               # React frontend
│   ├── src/
│   │   ├── App.js         # Main React component
│   │   ├── App.css        # Styles
│   │   └── index.js       # Entry point
│   └── package.json       # Node.js dependencies
├── setup_backend.py       # Backend setup script
├── setup_frontend.sh      # Frontend setup script
└── README.md             # This file
```

## Prerequisites

### System Requirements
- Python 3.8 or higher
- Node.js 14 or higher
- Java JDK 8 or higher
- 4GB RAM minimum (8GB recommended)

### Required Tools
- **apktool**: For APK decompilation and manifest parsing
- **jadx**: For Java code decompilation
- **androguard**: Python library for APK analysis

## Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd apk-inspector
```

### 2. Setup Backend
```bash
# Run the automated setup script
python setup_backend.py

# Or manually install dependencies
cd backend
pip install -r requirements.txt
```

### 3. Setup Frontend
```bash
# Run the automated setup script
chmod +x setup_frontend.sh
./setup_frontend.sh

# Or manually install dependencies
cd frontend
npm install
```

### 4. Start the Application

**Terminal 1 - Backend:**
```bash
cd backend
python main.py
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm start
```

### 5. Access the Application
Open your browser and go to: http://localhost:3000

## Manual Installation

### Backend Setup

1. **Install Python Dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Install Analysis Tools:**

   **Windows:**
   - Download Java JDK from Oracle or OpenJDK
   - Download apktool from https://ibotpeaches.github.io/Apktool/
   - Download jadx from https://github.com/skylot/jadx
   - Add all tools to your PATH

   **macOS:**
   ```bash
   brew install openjdk apktool jadx
   ```

   **Linux (Ubuntu/Debian):**
   ```bash
   sudo apt-get update
   sudo apt-get install openjdk-11-jdk apktool jadx
   ```

3. **Start the Backend:**
   ```bash
   python main.py
   ```

### Frontend Setup

1. **Install Node.js Dependencies:**
   ```bash
   cd frontend
   npm install
   ```

2. **Start the Frontend:**
   ```bash
   npm start
   ```

## API Endpoints

### Backend API (http://localhost:8000)

- `POST /upload` - Upload APK file
- `POST /analyze/{analysis_id}` - Start APK analysis
- `GET /status/{analysis_id}` - Get analysis status
- `GET /results/{analysis_id}` - Get analysis results
- `POST /report/{analysis_id}` - Generate report (PDF/HTML)
- `GET /reports` - List available reports

### Example API Usage

```bash
# Upload APK
curl -X POST -F "file=@app.apk" http://localhost:8000/upload

# Start analysis
curl -X POST http://localhost:8000/analyze/{analysis_id}

# Check status
curl http://localhost:8000/status/{analysis_id}

# Download PDF report
curl -X POST http://localhost:8000/report/{analysis_id}?format=pdf
```

## Analysis Output

The application extracts and analyzes:

### Basic Information
- Package name and version
- SDK versions (min/target)
- File size
- Analysis tools used

### Components
- Activities
- Services
- Receivers
- Providers

### Security Analysis
- Permissions
- URLs found in code
- IP addresses
- Suspicious strings (passwords, keys, tokens)

### Certificates
- Subject and issuer information
- Validity dates
- Serial numbers

## Report Formats

### PDF Report
- Professional layout with tables and sections
- Comprehensive analysis summary
- Security warnings highlighted
- Certificate information

### HTML Report
- Interactive web-based report
- Responsive design
- Color-coded sections
- Easy navigation

## Configuration

### Environment Variables
- `REACT_APP_API_URL`: Backend API URL (default: http://localhost:8000)

### Backend Configuration
Edit `backend/main.py` to modify:
- Upload directory paths
- Analysis timeout settings
- CORS origins

## Troubleshooting

### Common Issues

1. **"Tool not found" errors:**
   - Ensure apktool, jadx, and Java are installed and in PATH
   - Restart terminal after installing tools

2. **Permission errors:**
   - Check file permissions for upload/output directories
   - Run with appropriate permissions

3. **Memory errors:**
   - Large APK files may require more RAM
   - Consider increasing system memory

4. **Analysis timeout:**
   - Very large APK files may take longer
   - Check backend logs for specific errors

### Logs
- Backend logs: Check terminal output
- Frontend logs: Check browser console
- Analysis logs: Check backend terminal

## Development

### Adding New Analysis Tools
1. Add tool detection in `apk_analyzer.py`
2. Implement analysis method
3. Update result structure
4. Add to report templates

### Customizing Reports
1. Edit `report_generator.py` for PDF reports
2. Modify HTML template in `report_generator.py`
3. Update frontend display in `App.js`

## Security Considerations

- APK files are temporarily stored during analysis
- Files are automatically cleaned up after analysis
- No APK content is permanently stored
- Analysis runs in isolated processes

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [apktool](https://ibotpeaches.github.io/Apktool/) - APK decompilation
- [jadx](https://github.com/skylot/jadx) - Java decompilation
- [androguard](https://github.com/androguard/androguard) - APK analysis
- [FastAPI](https://fastapi.tiangolo.com/) - Backend framework
- [React](https://reactjs.org/) - Frontend framework

# APK
