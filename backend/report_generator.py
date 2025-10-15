import os
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import json

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

class ReportGenerator:
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    async def generate_pdf_report(self, analysis_result: Dict[str, Any], analysis_id: str) -> str:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            raise Exception("ReportLab not available. Install with: pip install reportlab")
        
        report_path = self.reports_dir / f"apk_report_{analysis_id}.pdf"
        
        doc = SimpleDocTemplate(str(report_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("APK Inspector Report", title_style))
        story.append(Spacer(1, 12))
        
        # Analysis info
        info_style = ParagraphStyle(
            'Info',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.grey
        )
        story.append(Paragraph(f"Analysis ID: {analysis_id}", info_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Spacer(1, 20))
        
        # Basic Information
        story.append(Paragraph("Basic Information", styles['Heading2']))
        basic_info = [
            ["Package Name", analysis_result.get("package_name", "N/A")],
            ["Version Name", analysis_result.get("version_name", "N/A")],
            ["Version Code", analysis_result.get("version_code", "N/A")],
            ["Min SDK", analysis_result.get("min_sdk", "N/A")],
            ["Target SDK", analysis_result.get("target_sdk", "N/A")],
            ["File Size", f"{analysis_result.get('file_size', 0):,} bytes"],
            ["Analysis Tools", ", ".join(analysis_result.get("analysis_tools_used", []))]
        ]
        
        basic_table = Table(basic_info, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(basic_table)
        story.append(Spacer(1, 20))
        
        # Permissions
        if analysis_result.get("permissions"):
            story.append(Paragraph("Permissions", styles['Heading2']))
            permissions = analysis_result["permissions"]
            # Split permissions into chunks for better display
            chunk_size = 3
            for i in range(0, len(permissions), chunk_size):
                chunk = permissions[i:i+chunk_size]
                perm_table = Table([chunk], colWidths=[2*inch] * len(chunk))
                perm_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(perm_table)
            story.append(Spacer(1, 20))
        
        # Components
        story.append(Paragraph("Components", styles['Heading2']))
        
        # Activities
        if analysis_result.get("activities"):
            story.append(Paragraph("Activities", styles['Heading3']))
            activities = analysis_result["activities"]
            for activity in activities[:10]:  # Limit to first 10
                story.append(Paragraph(f"• {activity}", styles['Normal']))
            if len(activities) > 10:
                story.append(Paragraph(f"... and {len(activities) - 10} more", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Services
        if analysis_result.get("services"):
            story.append(Paragraph("Services", styles['Heading3']))
            services = analysis_result["services"]
            for service in services[:10]:
                story.append(Paragraph(f"• {service}", styles['Normal']))
            if len(services) > 10:
                story.append(Paragraph(f"... and {len(services) - 10} more", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Receivers
        if analysis_result.get("receivers"):
            story.append(Paragraph("Receivers", styles['Heading3']))
            receivers = analysis_result["receivers"]
            for receiver in receivers[:10]:
                story.append(Paragraph(f"• {receiver}", styles['Normal']))
            if len(receivers) > 10:
                story.append(Paragraph(f"... and {len(receivers) - 10} more", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Providers
        if analysis_result.get("providers"):
            story.append(Paragraph("Providers", styles['Heading3']))
            providers = analysis_result["providers"]
            for provider in providers[:10]:
                story.append(Paragraph(f"• {provider}", styles['Normal']))
            if len(providers) > 10:
                story.append(Paragraph(f"... and {len(providers) - 10} more", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Security Analysis
        story.append(Paragraph("Security Analysis", styles['Heading2']))
        
        # URLs Found
        if analysis_result.get("urls_found"):
            story.append(Paragraph("URLs Found", styles['Heading3']))
            urls = analysis_result["urls_found"]
            for url in urls[:20]:  # Limit to first 20
                story.append(Paragraph(f"• {url}", styles['Normal']))
            if len(urls) > 20:
                story.append(Paragraph(f"... and {len(urls) - 20} more", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # IPs Found
        if analysis_result.get("ips_found"):
            story.append(Paragraph("IP Addresses Found", styles['Heading3']))
            ips = analysis_result["ips_found"]
            for ip in ips[:20]:
                story.append(Paragraph(f"• {ip}", styles['Normal']))
            if len(ips) > 20:
                story.append(Paragraph(f"... and {len(ips) - 20} more", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Suspicious Strings
        if analysis_result.get("suspicious_strings"):
            story.append(Paragraph("Suspicious Strings", styles['Heading3']))
            suspicious = analysis_result["suspicious_strings"]
            for string in suspicious[:20]:
                story.append(Paragraph(f"• {string}", styles['Normal']))
            if len(suspicious) > 20:
                story.append(Paragraph(f"... and {len(suspicious) - 20} more", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Certificates
        if analysis_result.get("certificates"):
            story.append(Paragraph("Certificates", styles['Heading2']))
            for i, cert in enumerate(analysis_result["certificates"][:3]):  # Limit to first 3
                story.append(Paragraph(f"Certificate {i+1}", styles['Heading3']))
                cert_info = [
                    ["Subject", cert.get("subject", "N/A")],
                    ["Issuer", cert.get("issuer", "N/A")],
                    ["Serial Number", cert.get("serial_number", "N/A")],
                    ["Valid From", cert.get("not_valid_before", "N/A")],
                    ["Valid Until", cert.get("not_valid_after", "N/A")]
                ]
                cert_table = Table(cert_info, colWidths=[2*inch, 4*inch])
                cert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(cert_table)
                story.append(Spacer(1, 10))
        
        # Deep Malware Analysis section (PDF)
        malware = analysis_result.get("malware_profile", {})
        if malware:
            story.append(Paragraph("Deep Malware Analysis", styles['Heading2']))
            # App Metadata quick block
            story.append(Paragraph("App Metadata", styles['Heading3']))
            meta_rows = [
                ["Package Name", analysis_result.get("package_name", "N/A")],
                ["Version", f"{analysis_result.get('version_name','N/A')} ({analysis_result.get('version_code','N/A')})"],
                ["Min SDK", analysis_result.get("min_sdk", "N/A")],
                ["Target SDK", analysis_result.get("target_sdk", "N/A")]
            ]
            meta_table = Table(meta_rows, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 10))

            # Network & C2
            net = malware.get('network', {})
            story.append(Paragraph("Network Connections & C2", styles['Heading3']))
            for label, key in [("Mining Pools", 'mining_pools'), ("WebView/Phishing/Ads", 'webview_ads'), ("Data Exfiltration", 'data_exfiltration'), ("Analytics/Tracking", 'analytics_tracking'), ("Firebase/Google", 'firebase_google')]:
                vals = net.get(key, [])
                if vals:
                    story.append(Paragraph(label, styles['Heading4']))
                    for v in vals[:20]:
                        story.append(Paragraph(f"• {v}", styles['Normal']))
                    story.append(Spacer(1, 6))

            # Malicious Behaviors
            beh = malware.get('behaviors', {})
            story.append(Paragraph("Malicious Behaviors & Capabilities", styles['Heading3']))
            for label, flag in [
                ("Cryptocurrency Mining", 'cryptocurrency_mining'),
                ("Data Exfiltration", 'data_exfiltration'),
                ("Persistence", 'persistence'),
                ("Further Infection", 'further_infection'),
                ("App Enumeration", 'app_enumeration'),
                ("Remote Control", 'remote_control'),
                ("WebView Abuse", 'webview_abuse')
            ]:
                story.append(Paragraph(f"• {label}: {'Yes' if beh.get(flag) else 'No'}", styles['Normal']))
            story.append(Spacer(1, 10))

            # IOCs
            iocs = malware.get('iocs', {})
            story.append(Paragraph("Indicators of Compromise (IOCs)", styles['Heading3']))
            if iocs.get('domains'):
                story.append(Paragraph("Domains", styles['Heading4']))
                for d in iocs['domains'][:30]:
                    story.append(Paragraph(f"• {d}", styles['Normal']))
            if iocs.get('ips_ports'):
                story.append(Paragraph("IP:Port", styles['Heading4']))
                for ip in iocs['ips_ports'][:30]:
                    story.append(Paragraph(f"• {ip}", styles['Normal']))
            if iocs.get('wallets'):
                story.append(Paragraph("Wallets", styles['Heading4']))
                for w in iocs['wallets'][:10]:
                    story.append(Paragraph(f"• {w}", styles['Normal']))
            story.append(Spacer(1, 10))

            # FCM chain
            fcmi = malware.get('fcmi_chain', {})
            story.append(Paragraph("Firebase-based Remote Control Chain", styles['Heading3']))
            story.append(Paragraph(f"• FirebaseMessagingService present: {'Yes' if fcmi.get('has_firebase_messaging_service') else 'No'}", styles['Normal']))
            story.append(Paragraph(f"• ProcessBuilder usage: {'Yes' if fcmi.get('process_builder_usage') else 'No'}", styles['Normal']))
            if fcmi.get('dropped_binary_names'):
                story.append(Paragraph("• Dropped binaries:", styles['Normal']))
                for n in fcmi['dropped_binary_names']:
                    story.append(Paragraph(f"   - {n}", styles['Normal']))
            story.append(Spacer(1, 12))

        # Build PDF
        doc.build(story)
        return str(report_path)
    
    async def generate_html_report(self, analysis_result: Dict[str, Any], analysis_id: str) -> str:
        """Generate HTML report"""
        if not JINJA2_AVAILABLE:
            raise Exception("Jinja2 not available. Install with: pip install jinja2")
        
        report_path = self.reports_dir / f"apk_report_{analysis_id}.html"
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Inspector Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }
        h2 {
            color: #007bff;
            border-left: 4px solid #007bff;
            padding-left: 10px;
            margin-top: 30px;
        }
        h3 {
            color: #555;
            margin-top: 20px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }
        .info-card h4 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .info-card p {
            margin: 5px 0;
            color: #666;
        }
        .list-container {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .list-container ul {
            margin: 0;
            padding-left: 20px;
        }
        .list-container li {
            margin: 5px 0;
            word-break: break-all;
        }
        .security-warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .certificate-info {
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #007bff;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            text-align: center;
        }
        .stat-item {
            background-color: #007bff;
            color: white;
            padding: 20px;
            border-radius: 5px;
            min-width: 120px;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }
        .stat-label {
            font-size: 14px;
            margin-top: 5px;
        }
        .meta-info {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Deep Malware Analysis Report</h1>
        
        <div class="meta-info">
            <p>Analysis ID: {{ analysis_id }}</p>
            <p>Generated: {{ generated_at }}</p>
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <span class="stat-number">{{ analysis_result.permissions|length }}</span>
                <span class="stat-label">Permissions</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{{ analysis_result.activities|length }}</span>
                <span class="stat-label">Activities</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{{ analysis_result.urls_found|length }}</span>
                <span class="stat-label">URLs Found</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{{ analysis_result.certificates|length }}</span>
                <span class="stat-label">Certificates</span>
            </div>
        </div>
        
        <h2>Contents</h2>
        <ol>
            <li>App Metadata</li>
            <li>Permissions Requested</li>
            <li>Declared Components
                <ol>
                    <li>Activities</li>
                    <li>Services</li>
                    <li>Receivers</li>
                    <li>Providers</li>
                </ol>
            </li>
            <li>Network Connections & Command-and-Control (C2)
                <ol>
                    <li>Mining Pools</li>
                    <li>WebView/Phishing/Ads</li>
                    <li>Data Exfiltration</li>
                    <li>Analytics/Tracking</li>
                    <li>Firebase/Google</li>
                </ol>
            </li>
            <li>Malicious Behaviors & Capabilities
                <ol>
                    <li>Cryptocurrency Mining</li>
                    <li>Data Exfiltration</li>
                    <li>Persistence</li>
                    <li>Further Infection</li>
                    <li>App Enumeration</li>
                    <li>Remote Control</li>
                    <li>WebView Abuse</li>
                </ol>
            </li>
            <li>Obfuscation & Evasion</li>
            <li>Interesting Strings & Artifacts</li>
            <li>Potential Indicators of Compromise (IOCs)</li>
            <li>Persistence & Stealth</li>
            <li>Final Investigation Addendum: Firebase-Based Remote Control & Attribution Chain
                <ol>
                    <li>Overview</li>
                    <li>Firebase C2 Integration Chain</li>
                    <li>Attribution and Evidence Chain</li>
                    <li>P2Pool Mining Activity Observed</li>
                    <li>Flow Diagram</li>
                </ol>
            </li>
            <li>Summary</li>
            <li>Conclusion</li>
        </ol>

        <h2>1. App Metadata</h2>
        <div class="info-grid">
            <div class="info-card">
                <h4>Package Information</h4>
                <p><strong>Package Name:</strong> {{ analysis_result.package_name or 'N/A' }}</p>
                <p><strong>Version Name:</strong> {{ analysis_result.version_name or 'N/A' }}</p>
                <p><strong>Version Code:</strong> {{ analysis_result.version_code or 'N/A' }}</p>
            </div>
            <div class="info-card">
                <h4>SDK Information</h4>
                <p><strong>Min SDK:</strong> {{ analysis_result.min_sdk or 'N/A' }}</p>
                <p><strong>Target SDK:</strong> {{ analysis_result.target_sdk or 'N/A' }}</p>
                <p><strong>File Size:</strong> {{ '{:,}'.format(analysis_result.file_size or 0) }} bytes</p>
                {% if analysis_result.uses_cleartext_traffic is not none %}
                <p><strong>Cleartext Traffic Allowed:</strong> {{ 'Yes' if analysis_result.uses_cleartext_traffic else 'No' }}</p>
                {% endif %}
            </div>
            <div class="info-card">
                <h4>Analysis Tools</h4>
                <p><strong>Tools Used:</strong> {{ analysis_result.analysis_tools_used|join(', ') or 'N/A' }}</p>
            </div>
        </div>
        
        {% if analysis_result.permissions %}
        <h2>2. Permissions Requested</h2>
        <div class="list-container">
            <ul>
                {% for permission in analysis_result.permissions %}
                <li>{{ permission }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <h2>3. Declared Components</h2>
        
        {% if analysis_result.activities %}
        <h3>3.1 Activities</h3>
        <div class="list-container">
            <ul>
                {% for activity in analysis_result.activities %}
                <li>{{ activity }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if analysis_result.services %}
        <h3>3.2 Services</h3>
        <div class="list-container">
            <ul>
                {% for service in analysis_result.services %}
                <li>{{ service }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if analysis_result.receivers %}
        <h3>3.3 Receivers</h3>
        <div class="list-container">
            <ul>
                {% for receiver in analysis_result.receivers %}
                <li>{{ receiver }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if analysis_result.providers %}
        <h3>3.4 Providers</h3>
        <div class="list-container">
            <ul>
                {% for provider in analysis_result.providers %}
                <li>{{ provider }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <h2>4. Network Connections & Command-and-Control (C2)</h2>
        {% set malware = analysis_result.malware_profile %}
        {% if malware %}
        {% for label, key in [
            ('4.1 Mining Pools', 'mining_pools'),
            ('4.2 WebView/Phishing/Ads', 'webview_ads'),
            ('4.3 Data Exfiltration', 'data_exfiltration'),
            ('4.4 Analytics/Tracking', 'analytics_tracking'),
            ('4.5 Firebase/Google', 'firebase_google')
        ] %}
        {% set vals = malware.network[key] %}
        {% if vals %}
        <h3>{{ label }}</h3>
        <div class="list-container">
            <ul>
                {% for v in vals %}
                <li>{{ v }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        {% endfor %}
        {% endif %}

        <h2>5. Malicious Behaviors & Capabilities</h2>
        {% if malware %}
        <div class="list-container">
            <ul>
                <li>5.1 Cryptocurrency Mining — {{ 'Yes' if malware.behaviors.cryptocurrency_mining else 'No' }}</li>
                <li>5.2 Data Exfiltration — {{ 'Yes' if malware.behaviors.data_exfiltration else 'No' }}</li>
                <li>5.3 Persistence — {{ 'Yes' if malware.behaviors.persistence else 'No' }}</li>
                <li>5.4 Further Infection — {{ 'Yes' if malware.behaviors.further_infection else 'No' }}</li>
                <li>5.5 App Enumeration — {{ 'Yes' if malware.behaviors.app_enumeration else 'No' }}</li>
                <li>5.6 Remote Control — {{ 'Yes' if malware.behaviors.remote_control else 'No' }}</li>
                <li>5.7 WebView Abuse — {{ 'Yes' if malware.behaviors.webview_abuse else 'No' }}</li>
            </ul>
        </div>
        {% endif %}
        
        {% if analysis_result.urls_found %}
        <h2>6. Obfuscation & Evasion</h2>
        {% if malware and malware.obfuscation_evasion %}
        <div class="list-container">
            <ul>
                {% for item in malware.obfuscation_evasion %}
                <li>{{ item }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <h2>7. Interesting Strings & Artifacts</h2>
        {% if malware and malware.interesting_strings %}
        <div class="list-container">
            <ul>
                {% for s in malware.interesting_strings %}
                <li>{{ s }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <h2>8. Potential Indicators of Compromise (IOCs)</h2>
        {% if malware %}
        {% if malware.iocs.domains %}
        <h3>Domains</h3>
        <div class="security-warning">
            <strong>Warning:</strong> The following domains/IPs/wallets are IOCs:
        </div>
        <div class="list-container">
            <ul>
                {% for d in malware.iocs.domains %}
                <li>{{ d }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        {% if malware.iocs.ips_ports %}
        <h3>IP/Port</h3>
        <div class="list-container">
            <ul>
                {% for ip in malware.iocs.ips_ports %}
                <li>{{ ip }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        {% if malware.iocs.wallets %}
        <h3>Wallets</h3>
        <div class="list-container">
            <ul>
                {% for w in malware.iocs.wallets %}
                <li>{{ w }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        {% endif %}
        {% endif %}

        <h2>9. Persistence & Stealth</h2>
        {% if malware and malware.persistence_stealth %}
        <div class="list-container"><ul>
            {% for p in malware.persistence_stealth %}
            <li>{{ p }}</li>
            {% endfor %}
        </ul></div>
        {% endif %}

        <h2>10. Final Investigation Addendum: Firebase-Based Remote Control & Attribution Chain</h2>
        {% if malware %}
        <h3>10.1 Overview</h3>
        <p>This section summarizes Firebase Cloud Messaging (FCM) based C2 indicators and miner activation flow.</p>
        <h3>10.2 Firebase C2 Integration Chain</h3>
        <div class="list-container"><ul>
            <li>FirebaseMessagingService present: {{ 'Yes' if malware.fcmi_chain.has_firebase_messaging_service else 'No' }}</li>
            <li>ProcessBuilder usage: {{ 'Yes' if malware.fcmi_chain.process_builder_usage else 'No' }}</li>
            {% if malware.fcmi_chain.dropped_binary_names %}
            <li>Dropped binaries: {{ malware.fcmi_chain.dropped_binary_names|join(', ') }}</li>
            {% endif %}
        </ul></div>
        <h3>10.3 Attribution and Evidence Chain</h3>
        <div class="list-container"><ul>
            {% if malware.iocs.wallets %}
            <li>Wallets: {{ malware.iocs.wallets|join(', ') }}</li>
            {% endif %}
            {% if malware.network.mining_pools %}
            <li>Mining Pools: {{ malware.network.mining_pools|join(', ') }}</li>
            {% endif %}
        </ul></div>
        <h3>10.4 P2Pool Mining Activity Observed</h3>
        <p>(If externally confirmed, summarize here.)</p>
        <h3>10.5 Flow Diagram</h3>
        <p>Firebase push -> handler -> miner init -> binary drop -> ProcessBuilder launch -> mining.</p>
        {% endif %}

        <h2>11. Summary</h2>
        <p>This application exhibits the behaviors and indicators listed above. Treat all endpoints and wallets as IOCs.</p>

        <h2>12. Conclusion</h2>
        <p>Immediate mitigation is recommended: block domains/IPs, remove the APK, and reset devices as necessary.</p>

        <h2>External Intelligence</h2>
        {% set intel = analysis_result.external_intel %}
        {% if intel %}
        <div class="info-grid">
            <div class="info-card">
                <h4>VirusTotal</h4>
                {% if intel.virustotal and intel.virustotal.file %}
                <p><strong>Detections:</strong> {{ intel.virustotal.file.attributes.last_analysis_stats.malicious or 0 }}</p>
                {% else %}
                <p>No VT data.</p>
                {% endif %}
            </div>
            <div class="info-card">
                <h4>OTX (AlienVault)</h4>
                <p>{{ intel.otx|length }} indicator records.</p>
            </div>
            <div class="info-card">
                <h4>Google Safe Browsing</h4>
                <p>{{ intel.gsb|length }} matches.</p>
            </div>
            <div class="info-card">
                <h4>Hybrid Analysis</h4>
                {% if intel.hybrid_analysis %}
                <p>Hash lookup results available.</p>
                {% else %}
                <p>No HA data.</p>
                {% endif %}
            </div>
            <div class="info-card">
                <h4>SecurityTrails</h4>
                <p>{{ intel.securitytrails|length }} domain records.</p>
            </div>
            <div class="info-card">
                <h4>P2Pool</h4>
                {% if intel.p2pool %}
                <p>Wallet activity found.</p>
                {% else %}
                <p>No P2Pool data.</p>
                {% endif %}
            </div>
        </div>
        {% if intel.summaries %}
        <h3>Executive Summary</h3>
        <div class="list-container">
            <p>{{ intel.summaries.executive_summary }}</p>
            <h4>Remediation</h4>
            <ul>
                {% for r in intel.summaries.remediation %}
                <li>{{ r }}</li>
        {% endfor %}
            </ul>
        </div>
        {% endif %}
        {% else %}
        <p>No external intelligence available (missing API keys).</p>
        {% endif %}
        
        <div style="margin-top: 50px; text-align: center; color: #666; font-size: 12px;">
            <p>Report generated by APK Inspector</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            analysis_id=analysis_id,
            analysis_result=analysis_result,
            generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_path)


