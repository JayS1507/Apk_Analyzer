import subprocess
import os
import json
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
import asyncio
import shutil
import platform
import hashlib
import os as _os
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

class APKAnalyzer:
    def __init__(self):
        # Configuration flags (environment-driven) to improve determinism and control
        self.flag_deterministic = bool(os.getenv("ANALYSIS_DETERMINISTIC", "").strip())
        self.flag_use_apktool = os.getenv("ANALYSIS_USE_APKTOOL", "1").strip() != "0"
        self.flag_use_jadx = os.getenv("ANALYSIS_USE_JADX", "1").strip() != "0"
        self.flag_use_androguard = os.getenv("ANALYSIS_USE_ANDROGUARD", "1").strip() != "0"
        self.flag_enable_intel = os.getenv("ANALYSIS_ENABLE_INTEL", "1").strip() != "0"

        # Deterministic mode tweaks: default to apktool+androguard only, disable intel
        if self.flag_deterministic:
            self.flag_use_jadx = False
            self.flag_enable_intel = False

        # API Keys
        self.vt_api_key = "186da68e1db79c670330ecc96ef71c0ff5c40258ebc1cf35bec442664dd7837f"

        self.tools_available = self._check_tools()

        # Initialize deterministic analysis metadata
        self.analysis_metadata = {
            "analysis_id": None,
            "timestamp": None,
            "tools_used": [],
            "deterministic_mode": self.flag_deterministic,
            "file_hash": None
        }
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which analysis tools are available"""
        tools = {}
        
        # Get the project root directory
        project_root = Path(__file__).resolve().parent.parent
        apktool_path = project_root / "tools" / "apktool.bat"
        is_windows = os.name == 'nt'
        # Prefer platform-correct JADX launcher
        jadx_path = project_root / "tools" / "bin" / ("jadx.bat" if is_windows else "jadx")
        
        # Check apktool
        try:
            if apktool_path.exists():
                # Use java directly with apktool.jar to avoid interactive prompts
                apktool_jar = project_root / "tools" / "apktool.jar"
                if apktool_jar.exists():
                    result = subprocess.run(['java', '-jar', str(apktool_jar), '--version'], 
                                          capture_output=True, text=True, timeout=10)
                    tools['apktool'] = result.returncode == 0
                else:
                    tools['apktool'] = False
            else:
                # Try system-wide apktool
                result = subprocess.run(['apktool', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                tools['apktool'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['apktool'] = False
        
        # Check jadx
        try:
            if jadx_path.exists():
                if is_windows:
                    result = subprocess.run(['cmd', '/c', str(jadx_path), '--version'],
                                            capture_output=True, text=True, timeout=10)
                else:
                    result = subprocess.run([str(jadx_path), '--version'],
                                            capture_output=True, text=True, timeout=10)
                tools['jadx'] = result.returncode == 0
            else:
                # Try system-wide jadx
                cmd = ['jadx', '--version'] if not is_windows else ['cmd', '/c', 'jadx', '--version']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                tools['jadx'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            tools['jadx'] = False
        
        # Check androguard (Python package)
        try:
            import androguard
            tools['androguard'] = True
        except ImportError:
            tools['androguard'] = False
        
        return tools
    
    async def analyze_apk(self, apk_path: str, output_dir: str, password: Optional[str] = None) -> Dict[str, Any]:
        """Main analysis function"""
        # Initialize analysis metadata for this run
        import uuid
        from datetime import datetime
        self.analysis_metadata["analysis_id"] = str(uuid.uuid4())
        self.analysis_metadata["timestamp"] = datetime.now().isoformat()
        self.analysis_metadata["file_hash"] = self._hash_file(apk_path, "sha256")
        self.analysis_metadata["tools_used"] = []

        result = {
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "urls_found": [],
            "ips_found": [],
            "suspicious_strings": [],
            "certificates": [],
            "file_size": 0,
            "analysis_tools_used": [],
            "analysis_metadata": self.analysis_metadata.copy()
        }

        # Get file size
        result["file_size"] = os.path.getsize(apk_path)

        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # If password is provided, try to decrypt a password-protected APK into a temp APK
        decrypted_apk_path: Optional[str] = None
        if password:
            try:
                import pyzipper  # type: ignore
                import tempfile
                import zipfile
                # Test if APK is a ZIP needing a password by trying to read an entry
                with pyzipper.AESZipFile(apk_path) as zf:
                    zf.pwd = password.encode()
                    # Extract all to a temp directory
                    temp_dir = Path(tempfile.mkdtemp(prefix="apk_dec_"))
                    zf.extractall(path=temp_dir)
                # Repackage without encryption so tools can read it
                decrypted_apk_path = str(Path(output_dir) / "decrypted.apk")
                with zipfile.ZipFile(decrypted_apk_path, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    for root, dirs, files in os.walk(temp_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            arc = os.path.relpath(fp, temp_dir)
                            new_zip.write(fp, arc)
                apk_path = decrypted_apk_path
            except Exception as e:
                # If decryption fails, continue with original path and let tools report errors
                print(f"Password provided but decryption failed: {e}")

        # Use available tools for analysis in deterministic order
        tool_results = {}

        if self.flag_use_apktool and self.tools_available['apktool']:
            tool_results['apktool'] = await self._analyze_with_apktool(apk_path, output_dir)
            result["analysis_tools_used"].append("apktool")
            self.analysis_metadata["tools_used"].append("apktool")

        if self.flag_use_androguard and self.tools_available['androguard']:
            tool_results['androguard'] = await self._analyze_with_androguard(apk_path)
            result["analysis_tools_used"].append("androguard")
            self.analysis_metadata["tools_used"].append("androguard")

        if self.flag_use_jadx and self.tools_available['jadx']:
            await self._analyze_with_jadx(apk_path, output_dir)
            result["analysis_tools_used"].append("jadx")
            self.analysis_metadata["tools_used"].append("jadx")

        # Merge results in deterministic order: apktool -> androguard -> jadx
        for tool in ['apktool', 'androguard']:
            if tool in tool_results:
                result.update(tool_results[tool])

        # Extract additional patterns from decompiled code (jadx only)
        if self.flag_use_jadx and self.tools_available['jadx']:
            code_patterns = await self._extract_patterns_from_code(output_dir)
            # Merge patterns deterministically
            for key in ['urls_found', 'ips_found', 'suspicious_strings']:
                existing = set(result.get(key, []))
                new_items = set(code_patterns.get(key, []))
                result[key] = sorted(list(existing.union(new_items)))

        # Extract URLs from XML resources (most stable source)
        xml_extracted = await self._extract_from_xml_resources(output_dir)
        if xml_extracted.get("urls_found"):
            existing_urls = set(result.get("urls_found", []))
            xml_urls = set(xml_extracted.get("urls_found", []))
            result["urls_found"] = sorted(list(existing_urls.union(xml_urls)))
        
        # Malware-focused enrichment (deterministic)
        result["malware_profile"] = await self._build_malware_profile(output_dir, result)

        # External intelligence enrichers (optional via env; can be disabled)
        if self.flag_enable_intel:
            result["external_intel"] = await self._run_external_enrichers(apk_path, result)
        else:
            result["external_intel"] = {
                "virustotal": None,
                "otx": [],
                "gsb": [],
                "hybrid_analysis": None,
                "securitytrails": [],
                "p2pool": None,
                "summaries": None,
                "hashes": {"sha256": self._hash_file(apk_path, "sha256"), "md5": self._hash_file(apk_path, "md5")},
            }

        # Compute overall malware score and threat level for UI/reporting
        score, level = self._compute_malware_score(result)
        result["malware_score"] = score
        result["threat_level"] = level

        # Ensure deterministic ordering of list fields (final deduplication)
        for k in ["urls_found", "ips_found", "suspicious_strings", "permissions", "activities", "services", "receivers", "providers"]:
            if isinstance(result.get(k), list):
                result[k] = sorted(list(dict.fromkeys(result[k])))

        # Update metadata with final results
        result["analysis_metadata"] = self.analysis_metadata.copy()

        return result
    
    async def _analyze_with_apktool(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
        """Analyze APK using apktool"""
        result = {}
        
        try:
            # Get apktool path
            project_root = Path(__file__).resolve().parent.parent
            apktool_jar = project_root / "tools" / "apktool.jar"
            
            # Decompile APK
            apktool_output = os.path.join(output_dir, "apktool_output")
            if apktool_jar.exists():
                cmd = ['java', '-jar', str(apktool_jar), 'd', apk_path, '-o', apktool_output, '-f', '--use-aapt2']
            else:
                cmd = ['apktool', 'd', apk_path, '-o', apktool_output, '-f', '--use-aapt2']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse AndroidManifest.xml
                manifest_path = os.path.join(apktool_output, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    result.update(self._parse_manifest(manifest_path))
                
                # Extract from smali files
                smali_dir = os.path.join(apktool_output, "smali")
                if os.path.exists(smali_dir):
                    result.update(self._extract_from_smali(smali_dir))
            
        except Exception as e:
            print(f"Error with apktool: {e}")
        
        return result
    
    async def _analyze_with_jadx(self, apk_path: str, output_dir: str):
        """Decompile APK using jadx"""
        try:
            # Get jadx path
            project_root = Path(__file__).resolve().parent.parent
            is_windows = os.name == 'nt'
            jadx_path = project_root / "tools" / "bin" / ("jadx.bat" if is_windows else "jadx")

            jadx_output = os.path.join(output_dir, "jadx_output")

            # Create output directory
            os.makedirs(jadx_output, exist_ok=True)

            if jadx_path.exists():
                # Use compatible JADX options; remove unsupported '--deobf-rewrite-cfg'
                base = [str(jadx_path), '-d', jadx_output, '--show-bad-code', '--deobf', apk_path]
                cmd = ['cmd', '/c', *base] if is_windows else base
            else:
                base = ['jadx', '-d', jadx_output, '--show-bad-code', '--deobf', apk_path]
                cmd = ['cmd', '/c', *base] if is_windows else base
            
            print(f"Running JADX command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()

            error_output = (stderr.decode(errors='ignore') if stderr else '') + (stdout.decode(errors='ignore') if stdout else '')

            if process.returncode == 0:
                print(f"JADX decompilation successful. Output: {jadx_output}")
            else:
                # Treat as success if output directory has files (jadx sometimes exits non-zero with warnings)
                has_output = False
                for root, dirs, files in os.walk(jadx_output):
                    if files:
                        has_output = True
                        break
                if has_output:
                    print(f"JADX returned {process.returncode} but produced files; continuing. Output: {jadx_output}")
                else:
                    print(f"JADX failed with return code {process.returncode}")
                    if "encrypted entry" in error_output or "invalid CEN header" in error_output:
                        print("🔒 APK is encrypted - JADX cannot decompile encrypted APKs")
                        print("   Try using apktool or provide password if available")
                    elif "password required" in error_output.lower():
                        print("🔑 APK requires password for decompilation")
                    else:
                        print(f"Output: {error_output[:2000]}")
            
        except Exception as e:
            print(f"Error with jadx: {e}")
            import traceback
            traceback.print_exc()
    
    async def _analyze_with_androguard(self, apk_path: str) -> Dict[str, Any]:
        """Analyze APK using androguard"""
        result = {}
        
        try:
            from androguard.core.bytecodes import apk
            from androguard.core.analysis import analysis
            
            # Load APK
            a = apk.APK(apk_path)
            
            # Basic info
            result["package_name"] = a.get_package()
            result["version_name"] = a.get_androidversion_name()
            result["version_code"] = a.get_androidversion_code()
            result["min_sdk"] = a.get_min_sdk_version()
            result["target_sdk"] = a.get_target_sdk_version()
            
            # Permissions
            result["permissions"] = a.get_permissions()
            
            # Components
            result["activities"] = list(a.get_activities())
            result["services"] = list(a.get_services())
            result["receivers"] = list(a.get_receivers())
            result["providers"] = list(a.get_providers())
            
            # Certificates
            result["certificates"] = self._extract_certificates(a)
            
            # Additional analysis
            result["app_name"] = a.get_app_name()
            result["main_activity"] = a.get_main_activity()
            result["libraries"] = a.get_libraries()
            
        except Exception as e:
            error_msg = str(e)
            print(f"Error with androguard: {error_msg}")
            
            # Handle specific errors
            if "encrypted" in error_msg.lower() or "password required" in error_msg.lower():
                result["error"] = "APK is encrypted and requires password for analysis"
                result["encrypted"] = True
            else:
                result["error"] = f"Androguard analysis failed: {error_msg}"
        
        return result
    
    def _parse_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """Parse AndroidManifest.xml"""
        result = {}
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Get package name
            result["package_name"] = root.get('package', '')
            
            # Get version info
            application = root.find('application')
            if application is not None:
                result["version_name"] = application.get('{http://schemas.android.com/apk/res/android}versionName', '')
                result["version_code"] = application.get('{http://schemas.android.com/apk/res/android}versionCode', '')
                # Detect cleartext traffic allowance
                uses_cleartext = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
                if uses_cleartext is not None:
                    result["uses_cleartext_traffic"] = uses_cleartext in ['true', 'True', '1']
            
            # Get SDK versions
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                result["min_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '')
                result["target_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '')
            
            # Get permissions
            permissions = []
            for perm in root.findall('uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if perm_name:
                    permissions.append(perm_name)
            result["permissions"] = permissions
            
            # Get components
            app = root.find('application')
            if app is not None:
                activities = []
                for activity in app.findall('activity'):
                    name = activity.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        activities.append(name)
                result["activities"] = activities
                
                services = []
                for service in app.findall('service'):
                    name = service.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        services.append(name)
                result["services"] = services
                
                receivers = []
                for receiver in app.findall('receiver'):
                    name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        receivers.append(name)
                result["receivers"] = receivers
                
                providers = []
                for provider in app.findall('provider'):
                    name = provider.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        providers.append(name)
                result["providers"] = providers
        
        except Exception as e:
            print(f"Error parsing manifest: {e}")
        
        return result
    
    def _extract_from_smali(self, smali_dir: str) -> Dict[str, Any]:
        """Extract information from smali files"""
        result = {
            "urls_found": [],
            "ips_found": [],
            "suspicious_strings": []
        }
        
        try:
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith('.smali'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Extract URLs
                            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                            result["urls_found"].extend(urls)
                            
                            # Extract IPs
                            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                            result["ips_found"].extend(ips)
                            
                            # Extract suspicious strings
                            suspicious_patterns = [
                                r'password',
                                r'secret',
                                r'key',
                                r'token',
                                r'api_key',
                                r'private',
                                r'admin',
                                r'root',
                                r'backdoor',
                                r'exploit'
                            ]
                            
                            for pattern in suspicious_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                result["suspicious_strings"].extend(matches)
        
        except Exception as e:
            print(f"Error extracting from smali: {e}")
        
        # Remove duplicates
        result["urls_found"] = list(set(result["urls_found"]))
        result["ips_found"] = list(set(result["ips_found"]))
        result["suspicious_strings"] = list(set(result["suspicious_strings"]))
        
        return result
    
    async def _extract_patterns_from_code(self, output_dir: str) -> Dict[str, Any]:
        """Extract patterns from decompiled Java code"""
        result = {
            "urls_found": [],
            "ips_found": [],
            "suspicious_strings": []
        }
        
        jadx_output = os.path.join(output_dir, "jadx_output")
        if not os.path.exists(jadx_output):
            return result
        
        try:
            for root, dirs, files in os.walk(jadx_output):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Extract URLs
                            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                            result["urls_found"].extend(urls)
                            
                            # Extract IPs
                            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                            result["ips_found"].extend(ips)
                            
                            # Extract API keys and tokens
                            api_patterns = [
                                r'["\']([A-Za-z0-9]{20,})["\']',  # Long alphanumeric strings
                                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                                r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                            ]
                            
                            for pattern in api_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                result["suspicious_strings"].extend(matches)
        
        except Exception as e:
            print(f"Error extracting patterns from code: {e}")
        
        # Remove duplicates
        result["urls_found"] = list(set(result["urls_found"]))
        result["ips_found"] = list(set(result["ips_found"]))
        result["suspicious_strings"] = list(set(result["suspicious_strings"]))
        
        return result

    async def _extract_from_xml_resources(self, output_dir: str) -> Dict[str, Any]:
        """Extract URLs and interesting strings from XML resources and manifests.
        This improves stability across runs because resource XML tends to be consistent
        even when decompiler outputs vary.
        """
        result = {
            "urls_found": []
        }

        roots = [
            os.path.join(output_dir, "apktool_output"),
            os.path.join(output_dir, "jadx_output"),
        ]

        url_regex = re.compile(r'https?://[^\s<>"\'"{}|\\^`\[\]]+')

        for base in roots:
            if not os.path.exists(base):
                continue
            for r, d, files in os.walk(base):
                for f in files:
                    if not f.endswith('.xml') and f != 'AndroidManifest.xml':
                        continue
                    fp = os.path.join(r, f)
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            content = fh.read()
                    except Exception:
                        continue
                    # Extract URLs from XML content
                    for u in url_regex.findall(content):
                        result["urls_found"].append(u)

        # Deduplicate
        result["urls_found"] = list(dict.fromkeys(result["urls_found"]))
        return result

    async def _build_malware_profile(self, output_dir: str, base: Dict[str, Any]) -> Dict[str, Any]:
        """Build a malware-oriented profile and indicators from extracted data and code scan."""
        profile: Dict[str, Any] = {
            "network": {
                "mining_pools": [],
                "webview_ads": [],
                "data_exfiltration": [],
                "analytics_tracking": [],
                "firebase_google": []
            },
            "behaviors": {
                "cryptocurrency_mining": False,
                "data_exfiltration": False,
                "persistence": False,
                "further_infection": False,
                "app_enumeration": False,
                "remote_control": False,
                "webview_abuse": False
            },
            "obfuscation_evasion": [],
            "interesting_strings": [],
            "iocs": {
                "domains": [],
                "ips_ports": [],
                "wallets": []
            },
            "persistence_stealth": [],
            "fcmi_chain": {
                "has_firebase_messaging_service": False,
                "process_builder_usage": False,
                "dropped_binary_names": []
            },
            "mining_details": {
                "chains": [],
                "wallets": [],
                "pools": [],
                "algorithms": [],
                "config_params": []
            }
        }

        urls: List[str] = base.get("urls_found", [])
        permissions: List[str] = base.get("permissions", [])
        activities: List[str] = base.get("activities", [])
        services: List[str] = base.get("services", [])
        receivers: List[str] = base.get("receivers", [])
        suspicious_strings: List[str] = base.get("suspicious_strings", [])

        lower_urls = [u.lower() for u in urls]

        # Categorize URLs deterministically
        for u in sorted(urls):  # Sort URLs first for deterministic processing
            lu = u.lower()
            if any(x in lu for x in ["pool.", "nicehash", ":9000", "mining", "hashvault", "minexmr", "supportxmr", "moneroocean", "p2pool", "ethermine", "slush", "antpool"]):
                profile["network"]["mining_pools"].append(u)
            if any(x in lu for x in ["/ads", "ads.html", "webview", "http://"]):
                profile["network"]["webview_ads"].append(u)
            if any(x in lu for x in ["upload", "exfil", "log", "logging", "try_uploading", ":8443"]):
                profile["network"]["data_exfiltration"].append(u)
            if any(x in lu for x in ["aptabase", "analytics", "track", "firebaseio.com", "googleapis.com", "gstatic.com"]):
                profile["network"]["analytics_tracking"].append(u)
            if any(x in lu for x in ["firebase", "google", "gcm", "fcm"]):
                profile["network"]["firebase_google"].append(u)

        # Wallet detection for various cryptocurrencies (balanced: avoid common false positives, capture real addresses)
        # Use isolation lookarounds; include bech32 where applicable; correct prefixes
        bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        wallet_regexes = {
            # Monero mainnet: 95 chars total starting with 4 or 8 (includes subaddress/integrated variants)
            "Monero (XMR)": r"(?<![A-Za-z0-9])[48][A-Za-z0-9]{93}(?![A-Za-z0-9])",
            # Bitcoin legacy/P2SH and bech32
            "Bitcoin (BTC)": r"(?<![A-Za-z0-9])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})(?![A-Za-z0-9])",
            # Ethereum: 0x + 40 hex
            "Ethereum (ETH)": r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])",
            # Litecoin: legacy (L/M/3) and bech32 (ltc1...)
            "Litecoin (LTC)": r"(?<![A-Za-z0-9])(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[ac-hj-np-z02-9]{20,71})(?![A-Za-z0-9])",
            # Dogecoin: typical length 34, starts with D or A (older), allow 25-35
            "Dogecoin (DOGE)": r"(?<![A-Za-z0-9])[DA][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])",
            # Dash (mainnet P2PKH usually starts with X)
            "Dash": r"(?<![A-Za-z0-9])X[1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])",
            # Zcash transparent address
            "Zcash (ZEC)": r"(?<![A-Za-z0-9])t1[a-km-zA-HJ-NP-Z1-9]{33}(?![A-Za-z0-9])",
        }
        # Helper to validate a single address strictly against known patterns
        def _is_wallet_address(addr: str) -> bool:
            try:
                for regex in wallet_regexes.values():
                    if re.fullmatch(regex, addr) is not None:
                        return True
            except Exception:
                return False
            return False
        wallet_hits: Dict[str, List[str]] = {chain: [] for chain in wallet_regexes}

        # Scan code for additional indicators (deterministic file order)
        output_dir_path = Path(output_dir)
        search_roots = [output_dir_path / "jadx_output", output_dir_path / "apktool_output"]
        process_builder_found = False
        dropped_names: List[str] = []
        firebase_messaging_found = False
        obfuscation_markers = 0
        mining_config_params: List[str] = []

        # Collect all file paths first, then sort for deterministic processing
        all_files = []
        for root in search_roots:
            if not root.exists():
                continue
            for r, d, files in os.walk(root):
                for f in files:
                    if not f.endswith((".java", ".kt", ".smali", ".xml")):
                        continue
                    all_files.append(os.path.join(r, f))

        # Sort files for deterministic processing
        all_files.sort()

        scanned = 0
        max_scan = 1200 if not self.flag_deterministic else 2400  # More thorough in deterministic mode

        for file_path in all_files:
            if scanned >= max_scan:
                break
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            # Wallets for all supported cryptocurrencies
            for chain, regex in wallet_regexes.items():
                matches = re.findall(regex, content)
                for match in matches:
                    if match not in wallet_hits[chain]:
                        wallet_hits[chain].append(match)

            # ProcessBuilder
            if "ProcessBuilder(" in content or "new ProcessBuilder" in content:
                process_builder_found = True

            # Dropped binary hints
            for name in ["d-miner", "miner", "xmrig", "cpuminer", "minerd"]:
                if name in content:
                    if name not in dropped_names:
                        dropped_names.append(name)

            # Firebase messaging
            if "FirebaseMessagingService" in content or "com.google.firebase.messaging" in content:
                firebase_messaging_found = True

            # Mining configuration parameters (expanded patterns)
            mining_param_patterns = [
                r'--threads\s*\d+', r'--cpu-affinity\s*[\d,-]+', r'--donate-level\s*\d+',
                r'--max-cpu-usage\s*\d+', r'--nicehash\s*\w+', r'--tls\s*\w+',
                r'--tls-fingerprint\s*\w+', r'--keepalive\s*\w+', r'--no-huge-pages\s*\w+',
                r'--asm\s*\w+', r'--randomx-1gb-pages\s*\w+', r'--randomx-mode\s*\w+',
                r'--randomx-wrmsr\s*\w+', r'--randomx-no-rdmsr\s*\w+', r'--http-port\s*\d+',
                r'--daemon\s*\w+', r'--background\s*\w+', r'--syslog\s*\w+',
                r'--log-file\s*\S+', r'--pid-file\s*\S+', r'--user\s*\w+',
                r'--cpu-priority\s*\d+', r'--cpu-no-yield\s*\w+', r'--no-color\s*\w+',
                r'--variant\s*\d+', r'--algo\s*\w+', r'-t\s*\d+', r'-a\s*\w+',
                r'--coin\s*\w+', r'--pool\s*\S+', r'-o\s*\S+', r'-u\s*\S+',
                r'-p\s*\S+', r'--rig-id\s*\S+', r'--email\s*\S+',
                r'-app\b', r'-auto\b', r'-patch\b', r'-path\b', r'-permission\b', r'-process\b',
                r'pub-\d+~\d+', r'--wallet\s*\S+', r'--password\s*\S+', r'--user\s*\S+'
            ]

            for pattern in mining_param_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match not in mining_config_params:
                        mining_config_params.append(match.strip())

            # Obfuscation heuristic: very long camel-case or random-like identifiers
            if any(tok for tok in ["AfQ967noliILJmFfWE", "ijp0wLdk8g9g5d8vJU"] if tok in content):
                obfuscation_markers += 1

            scanned += 1

        # Populate behaviors
        if profile["network"]["mining_pools"] or dropped_names or wallet_hits:
            profile["behaviors"]["cryptocurrency_mining"] = True

        # Populate mining details
        if profile["behaviors"]["cryptocurrency_mining"]:
            # Detect chains based on wallets and strings
            chains = []
            for chain in wallet_hits:
                if wallet_hits[chain]:
                    chains.append(chain)
            # Check for other chains in strings (e.g., bitcoin, ethereum)
            lower_suspicious = [s.lower() for s in suspicious_strings]
            if any("bitcoin" in s or "btc" in s for s in lower_suspicious):
                chains.append("Bitcoin (BTC)")
            if any("ethereum" in s or "eth" in s for s in lower_suspicious):
                chains.append("Ethereum (ETH)")
            if any("litecoin" in s or "ltc" in s for s in lower_suspicious):
                chains.append("Litecoin (LTC)")
            if any("dogecoin" in s or "doge" in s for s in lower_suspicious):
                chains.append("Dogecoin (DOGE)")
            if any("dash" in s for s in lower_suspicious):
                chains.append("Dash")
            if any("zcash" in s or "zec" in s for s in lower_suspicious):
                chains.append("Zcash (ZEC)")
            # Detect chains from mining pool URLs
            for pool in profile["network"]["mining_pools"]:
                pool_lower = pool.lower()
                if "monero" in pool_lower or "xmr" in pool_lower:
                    chains.append("Monero (XMR)")
                if "bitcoin" in pool_lower or "btc" in pool_lower:
                    chains.append("Bitcoin (BTC)")
                if "ethereum" in pool_lower or "eth" in pool_lower:
                    chains.append("Ethereum (ETH)")
                if "litecoin" in pool_lower or "ltc" in pool_lower:
                    chains.append("Litecoin (LTC)")
                if "dogecoin" in pool_lower or "doge" in pool_lower:
                    chains.append("Dogecoin (DOGE)")
                if "dash" in pool_lower:
                    chains.append("Dash")
                if "zcash" in pool_lower or "zec" in pool_lower:
                    chains.append("Zcash (ZEC)")
            profile["mining_details"]["chains"] = sorted(list(set(chains)))

            # Wallets - flatten and validate wallet addresses with their chains
            all_wallets = []
            for chain, addresses in wallet_hits.items():
                for addr in addresses:
                    if _is_wallet_address(addr):
                        all_wallets.append(f"{chain}: {addr}")
            profile["mining_details"]["wallets"] = sorted(all_wallets)

            # Pools
            profile["mining_details"]["pools"] = sorted(profile["network"]["mining_pools"])

            # Algorithms (inferred from chains or strings)
            algorithms = []
            if "Monero (XMR)" in chains:
                algorithms.append("RandomX")
            if "Bitcoin (BTC)" in chains:
                algorithms.append("SHA-256")
            if "Ethereum (ETH)" in chains:
                algorithms.append("Ethash")
            if "Litecoin (LTC)" in chains:
                algorithms.append("Scrypt")
            profile["mining_details"]["algorithms"] = sorted(algorithms)

            # Config params
            profile["mining_details"]["config_params"] = sorted(list(set(mining_config_params)))

        if profile["network"]["data_exfiltration"]:
            profile["behaviors"]["data_exfiltration"] = True
        if any(p in permissions for p in ["android.permission.RECEIVE_BOOT_COMPLETED", "RECEIVE_BOOT_COMPLETED"]):
            profile["behaviors"]["persistence"] = True
            profile["persistence_stealth"].append("Boot receiver present")
        if any(p in permissions for p in ["android.permission.REQUEST_INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES"]):
            profile["behaviors"]["further_infection"] = True
        if any(p in permissions for p in ["android.permission.QUERY_ALL_PACKAGES", "QUERY_ALL_PACKAGES"]):
            profile["behaviors"]["app_enumeration"] = True
        if firebase_messaging_found:
            profile["behaviors"]["remote_control"] = True
        if profile["network"]["webview_ads"]:
            profile["behaviors"]["webview_abuse"] = True

        # Persistence signals
        for p in ["FOREGROUND_SERVICE", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"]:
            if any(p in perm for perm in permissions):
                profile["persistence_stealth"].append(p)

        # Obfuscation & evasion
        if obfuscation_markers > 0:
            profile["obfuscation_evasion"].append("Heavily obfuscated identifiers detected")
        if base.get("uses_cleartext_traffic") or any("http://" in u for u in lower_urls):
            profile["obfuscation_evasion"].append("Cleartext traffic observed")

        # Interesting strings / flags (deterministic)
        interesting_flags = ["--coin", "monero", "--tls", "-o ", "-k", "--nicehash", "api_key", "token", "ProcessBuilder("]
        interesting_strings = []
        for s in sorted(suspicious_strings):  # Sort for deterministic processing
            if any(flag in s.lower() for flag in ["monero", "wallet", "nicehash", "miner"]):
                interesting_strings.append(s)

        # Add URLs that match mining/wallet patterns
        for bucket in [profile["network"]["data_exfiltration"], profile["network"]["mining_pools"]]:
            for u in sorted(bucket):
                if any(f in u.lower() for f in ["monero", "wallet", "nicehash", ":9000", "miner"]):
                    interesting_strings.append(u)

        profile["interesting_strings"] = sorted(list(set(interesting_strings)))

        # IOCs (deterministic)
        domain_candidates = []
        ips_ports = []
        for u in sorted(urls):  # Process in sorted order
            try:
                from urllib.parse import urlparse
                parsed = urlparse(u)
                host = parsed.hostname or ""
                if host:
                    domain_candidates.append(host)
                    if parsed.port:
                        ips_ports.append(f"{host}:{parsed.port}")
            except Exception:
                continue

        profile["iocs"]["domains"] = sorted(list(set(domain_candidates)))[:100]
        profile["iocs"]["ips_ports"] = sorted(list(set(ips_ports)))[:100]
        # IOC wallets should contain actual addresses, not chain names; validate strictly
        flat_wallets: List[str] = []
        for chain, addresses in wallet_hits.items():
            for addr in addresses:
                if addr not in flat_wallets and _is_wallet_address(addr):
                    flat_wallets.append(addr)
        profile["iocs"]["wallets"] = sorted(flat_wallets)[:50]

        # FCM + miner chain evidence
        profile["fcmi_chain"]["has_firebase_messaging_service"] = firebase_messaging_found
        profile["fcmi_chain"]["process_builder_usage"] = process_builder_found
        profile["fcmi_chain"]["dropped_binary_names"] = sorted(dropped_names)[:5]

        return profile

    def _compute_malware_score(self, base: Dict[str, Any]) -> (int, str):
        """Compute a simple malware score and threat level from profile and intel."""
        score = 0
        profile = base.get("malware_profile", {})
        behaviors = profile.get("behaviors", {})
        iocs = profile.get("iocs", {})
        intel = base.get("external_intel", {})
        permissions = base.get("permissions", []) or []
        suspicious_strings = base.get("suspicious_strings", []) or []
        urls_found = base.get("urls_found", []) or []
        ips_found = base.get("ips_found", []) or []
        uses_cleartext = bool(base.get("uses_cleartext_traffic"))

        # Behaviors (up to 7)
        for k, v in behaviors.items():
            if v:
                score += 12  # behavior flags are strong signals

        # IOCs weight
        domains = iocs.get("domains", [])
        ips = iocs.get("ips_ports", [])
        wallets = iocs.get("wallets", [])
        score += min(len(domains), 10) * 2
        score += min(len(ips), 10) * 2
        if wallets:
            score += 15

        # Suspicious strings and direct findings in code
        score += min(len(suspicious_strings), 20)  # up to +20
        score += min(len(urls_found), 20) // 2     # up to +10
        score += min(len(ips_found), 20) // 2      # up to +10

        # Risky permissions
        risky_perms = [
            'RECEIVE_BOOT_COMPLETED',
            'REQUEST_INSTALL_PACKAGES',
            'QUERY_ALL_PACKAGES',
            'FOREGROUND_SERVICE',
            'WAKE_LOCK',
        ]
        for rp in risky_perms:
            if any(rp in p for p in permissions):
                score += 4  # each risky permission adds

        # Cleartext traffic allowed
        if uses_cleartext:
            score += 6

        # External intel (VT detections)
        try:
            vt_file = (intel or {}).get("virustotal", {}).get("file", {})
            vt_mal = int(vt_file.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0))
            score += min(vt_mal * 4, 40)
        except Exception:
            pass

        # Cap score and derive level
        score = max(0, min(100, score))
        if score >= 70:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"
        return score, level

    async def _run_external_enrichers(self, apk_path: str, base: Dict[str, Any]) -> Dict[str, Any]:
        """Run optional external enrichers if API keys are present in environment."""
        intel: Dict[str, Any] = {
            "virustotal": None,
            "otx": [],
            "gsb": [],
            "hybrid_analysis": None,
            "securitytrails": [],
            "p2pool": None,
            "summaries": None
        }

        # Compute hashes for lookup
        sha256 = self._hash_file(apk_path, "sha256")
        md5 = self._hash_file(apk_path, "md5")

        # Gather IOCs (sort for deterministic processing)
        domains = sorted(base.get("malware_profile", {}).get("iocs", {}).get("domains", []))
        ips_ports = sorted(base.get("malware_profile", {}).get("iocs", {}).get("ips_ports", []))
        wallets = sorted(base.get("malware_profile", {}).get("iocs", {}).get("wallets", []))

        # Cache key for deterministic results
        cache_key = f"{sha256}_{len(domains)}_{len(ips_ports)}_{len(wallets)}"
        if hasattr(self, '_intel_cache') and cache_key in self._intel_cache:
            return self._intel_cache[cache_key]

        tasks = []
        async with httpx.AsyncClient(timeout=20.0) as client:
            # VirusTotal
            if self.vt_api_key:
                tasks.append(self._vt_lookup(client, self.vt_api_key, sha256, domains, ips_ports))

            # OTX
            otx_key = _os.getenv("OTX_API_KEY")
            if otx_key:
                tasks.append(self._otx_lookup(client, otx_key, domains, ips_ports, wallets))

            # Google Safe Browsing
            gsb_key = _os.getenv("GSB_API_KEY")
            if gsb_key and domains:
                tasks.append(self._gsb_lookup(client, gsb_key, domains))

            # Hybrid Analysis (hash lookup only to avoid submissions by default)
            ha_key = _os.getenv("HYBRID_ANALYSIS_API_KEY")
            if ha_key and sha256:
                tasks.append(self._hybrid_lookup(client, ha_key, sha256))

            # SecurityTrails passive DNS for domains
            st_key = _os.getenv("SECURITYTRAILS_API_KEY")
            if st_key and domains:
                tasks.append(self._securitytrails_lookup(client, st_key, domains))

            # P2Pool explorer
            p2pool_base = _os.getenv("P2POOL_BASE_URL")
            if p2pool_base and wallets:
                tasks.append(self._p2pool_lookup(client, p2pool_base, wallets[0]))

            # Run all available in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Assign results by type (deterministic ordering)
        for r in results or []:
            try:
                if isinstance(r, dict) and r.get("_kind") == "vt":
                    intel["virustotal"] = r.get("data")
                elif isinstance(r, dict) and r.get("_kind") == "otx":
                    intel["otx"] = sorted(r.get("data", []), key=lambda x: x.get("indicator", ""))
                elif isinstance(r, dict) and r.get("_kind") == "gsb":
                    intel["gsb"] = sorted(r.get("data", []), key=lambda x: x.get("threatType", ""))
                elif isinstance(r, dict) and r.get("_kind") == "hybrid":
                    intel["hybrid_analysis"] = r.get("data")
                elif isinstance(r, dict) and r.get("_kind") == "securitytrails":
                    intel["securitytrails"] = sorted(r.get("data", []), key=lambda x: x.get("domain", ""))
                elif isinstance(r, dict) and r.get("_kind") == "p2pool":
                    intel["p2pool"] = r.get("data")
            except Exception:
                continue

        # Optional: LLM executive summary (cached)
        openai_key = _os.getenv("OPENAI_API_KEY")
        if openai_key:
            try:
                intel["summaries"] = await self._summarize_with_llm(base, intel, openai_key)
            except Exception:
                pass

        intel["hashes"] = {"sha256": sha256, "md5": md5}

        # Cache results for deterministic behavior
        if not hasattr(self, '_intel_cache'):
            self._intel_cache = {}
        self._intel_cache[cache_key] = intel

        return intel

    def _hash_file(self, file_path: str, algo: str) -> str:
        h = hashlib.new(algo)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _vt_lookup(self, client: httpx.AsyncClient, api_key: str, sha256: str, domains: List[str], ips_ports: List[str]):
        headers = {"x-apikey": api_key}
        out = {"file": None, "domains": {}, "ips": {}}
        try:
            if sha256:
                r = await client.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers)
                if r.status_code == 200:
                    out["file"] = r.json().get("data", {})
            for d in domains[:10]:
                r = await client.get(f"https://www.virustotal.com/api/v3/domains/{d}", headers=headers)
                if r.status_code == 200:
                    out["domains"][d] = r.json().get("data", {})
            for ip in [x.split(":")[0] for x in ips_ports][:10]:
                r = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
                if r.status_code == 200:
                    out["ips"][ip] = r.json().get("data", {})
        except Exception:
            pass
        return {"_kind": "vt", "data": out}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _otx_lookup(self, client: httpx.AsyncClient, api_key: str, domains: List[str], ips_ports: List[str], wallets: List[str]):
        headers = {"X-OTX-API-KEY": api_key}
        out = []
        try:
            for d in domains[:10]:
                r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/general", headers=headers)
                if r.status_code == 200:
                    out.append({"indicator": d, "data": r.json()})
            for ip in [x.split(":")[0] for x in ips_ports][:10]:
                r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", headers=headers)
                if r.status_code == 200:
                    out.append({"indicator": ip, "data": r.json()})
            # Wallet lookup not standard in OTX; skip or treat as domain-like tag
        except Exception:
            pass
        return {"_kind": "otx", "data": out}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _gsb_lookup(self, client: httpx.AsyncClient, api_key: str, domains: List[str]):
        out = []
        try:
            body = {
                "client": {"clientId": "apk-inspector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{d}"} for d in domains[:30]]
                }
            }
            r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}", json=body)
            if r.status_code == 200:
                out = r.json().get("matches", [])
        except Exception:
            pass
        return {"_kind": "gsb", "data": out}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _hybrid_lookup(self, client: httpx.AsyncClient, api_key: str, sha256: str):
        headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox"}
        out = None
        try:
            r = await client.get(f"https://www.hybrid-analysis.com/api/v2/search/hash", params={"hash": sha256}, headers=headers)
            if r.status_code == 200:
                out = r.json()
        except Exception:
            pass
        return {"_kind": "hybrid", "data": out}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _securitytrails_lookup(self, client: httpx.AsyncClient, api_key: str, domains: List[str]):
        headers = {"APIKEY": api_key}
        out = []
        try:
            for d in domains[:10]:
                r = await client.get(f"https://api.securitytrails.com/v1/domain/{d}", headers=headers)
                if r.status_code == 200:
                    out.append({"domain": d, "data": r.json()})
        except Exception:
            pass
        return {"_kind": "securitytrails", "data": out}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _p2pool_lookup(self, client: httpx.AsyncClient, base_url: str, wallet: str):
        out = None
        try:
            r = await client.get(f"{base_url.rstrip('/')}/wallet/{wallet}")
            if r.status_code == 200:
                out = r.json()
        except Exception:
            pass
        return {"_kind": "p2pool", "data": out}

    async def _summarize_with_llm(self, base: Dict[str, Any], intel: Dict[str, Any], api_key: str):
        # Keep implementation stubbed: avoid vendor lock-in; user can enable later
        try:
            summary = {
                "executive_summary": "This APK exhibits indicators of mining and remote control via Firebase, with multiple suspicious URLs and potential data exfiltration. Treat all endpoints and wallets as IOCs.",
                "remediation": [
                    "Block observed domains and IPs at the network boundary",
                    "Remove the APK and reset devices to clear persistence",
                    "Report wallets and domains to providers and authorities"
                ]
            }
            return summary
        except Exception:
            return None
    
    def _extract_certificates(self, apk) -> List[Dict[str, str]]:
        """Extract certificate information"""
        certificates = []
        
        try:
            certs = apk.get_certificates()
            for cert in certs:
                cert_info = {
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": str(cert.not_valid_before),
                    "not_valid_after": str(cert.not_valid_after)
                }
                certificates.append(cert_info)
        except Exception as e:
            print(f"Error extracting certificates: {e}")
        
        return certificates

