#!/usr/bin/env python3

import requests
import json
import argparse
import sys
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
import re
from dataclasses import dataclass, asdict
from datetime import datetime
import threading

@dataclass
class APIEndpoint:
    url: str
    method: str
    status_code: int
    response_time: float
    has_auth: bool = False
    auth_type: Optional[str] = None
    content_type: Optional[str] = None
    vulnerable: bool = False

class APIAuditor:
    def __init__(self, base_url: str, timeout: int = 5):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.endpoints: List[APIEndpoint] = []
        self.misconfigurations: List[Dict] = []
        self.session = requests.Session()
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def discover_endpoints(self, path_wordlist: Optional[str] = None) -> Set[str]:
        """Discover API endpoints"""
        found_endpoints = set()
        
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/service/', '/services/',
            '/admin/', '/user/', '/users/', '/profile/',
            '/auth/', '/login/', '/register/', '/logout/',
            '/data/', '/fetch/', '/get/', '/list/',
            '/status/', '/health/', '/info/', '/config/',
            '/webhook/', '/callback/', '/upload/', '/download/',
        ]
        
        common_endpoints = [
            'users', 'products', 'orders', 'posts', 'comments',
            'posts', 'articles', 'stories', 'items', 'projects',
            'tickets', 'issues', 'tasks', 'bugs', 'reports',
            'settings', 'config', 'credentials', 'keys', 'tokens',
        ]
        
        if path_wordlist:
            try:
                with open(path_wordlist, 'r') as f:
                    custom_paths = [line.strip() for line in f if line.strip()]
                    common_endpoints.extend(custom_paths)
            except FileNotFoundError:
                pass
        
        for path in common_paths:
            for endpoint in common_endpoints:
                url = urljoin(self.base_url, path + endpoint)
                
                try:
                    resp = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                    if resp.status_code < 400:
                        found_endpoints.add(url)
                        print(f"[+] Found: {url} ({resp.status_code})")
                except Exception:
                    pass
        
        return found_endpoints
    
    def test_endpoint(self, url: str, method: str = 'GET', data: Optional[Dict] = None) -> APIEndpoint:
        """Test a single endpoint"""
        import time
        
        try:
            start = time.time()
            
            if method == 'GET':
                resp = self.session.get(url, timeout=self.timeout)
            elif method == 'POST':
                resp = self.session.post(url, json=data or {}, timeout=self.timeout)
            elif method == 'PUT':
                resp = self.session.put(url, json=data or {}, timeout=self.timeout)
            elif method == 'DELETE':
                resp = self.session.delete(url, timeout=self.timeout)
            else:
                resp = self.session.request(method, url, timeout=self.timeout)
            
            elapsed = time.time() - start
            
            has_auth = 'Authorization' in resp.request.headers or resp.status_code == 401
            auth_type = self._detect_auth_type(resp)
            content_type = resp.headers.get('Content-Type', '')
            
            endpoint = APIEndpoint(
                url=url,
                method=method,
                status_code=resp.status_code,
                response_time=elapsed,
                has_auth=has_auth,
                auth_type=auth_type,
                content_type=content_type
            )
            
            return endpoint
        
        except requests.Timeout:
            return APIEndpoint(url=url, method=method, status_code=0, response_time=self.timeout, vulnerable=True)
        except Exception as e:
            return APIEndpoint(url=url, method=method, status_code=-1, response_time=0.0)
    
    def _detect_auth_type(self, response: requests.Response) -> Optional[str]:
        """Detect authentication type"""
        www_auth = response.headers.get('WWW-Authenticate', '')
        
        if 'Bearer' in www_auth:
            return 'Bearer'
        elif 'Basic' in www_auth:
            return 'Basic'
        elif 'Digest' in www_auth:
            return 'Digest'
        elif 'OAuth' in www_auth:
            return 'OAuth2'
        
        return None
    
    def check_cors(self) -> List[Dict]:
        """Check CORS configuration"""
        issues = []
        test_origins = [
            'http://evil.com',
            'http://127.0.0.1:8080',
            '*',
        ]
        
        for origin in test_origins:
            try:
                resp = self.session.get(
                    self.base_url,
                    headers={'Origin': origin},
                    timeout=self.timeout
                )
                
                cors_header = resp.headers.get('Access-Control-Allow-Origin', '')
                
                if cors_header:
                    issues.append({
                        'type': 'CORS_MISCONFIGURATION',
                        'origin': origin,
                        'allow_origin': cors_header,
                        'severity': 'HIGH' if origin == '*' else 'MEDIUM'
                    })
            except Exception:
                pass
        
        return issues
    
    def check_missing_security_headers(self) -> List[Dict]:
        """Check for missing security headers"""
        issues = []
        required_headers = {
            'X-Content-Type-Options': 'HIGH',
            'X-Frame-Options': 'HIGH',
            'Strict-Transport-Security': 'HIGH',
            'X-XSS-Protection': 'MEDIUM',
            'Content-Security-Policy': 'MEDIUM',
        }
        
        try:
            resp = self.session.head(self.base_url, timeout=self.timeout)
            
            for header, severity in required_headers.items():
                if header not in resp.headers:
                    issues.append({
                        'type': 'MISSING_SECURITY_HEADER',
                        'header': header,
                        'severity': severity
                    })
        except Exception:
            pass
        
        return issues
    
    def check_sensitive_data_exposure(self) -> List[Dict]:
        """Check for sensitive data exposure"""
        issues = []
        sensitive_patterns = {
            'api_key': r'api[_-]?key["\']?\s*[:=]["\']?([a-zA-Z0-9]+)',
            'password': r'password["\']?\s*[:=]["\']?([^\s"\']+)',
            'token': r'token["\']?\s*[:=]["\']?([a-zA-Z0-9]+)',
            'secret': r'secret["\']?\s*[:=]["\']?([^\s"\']+)',
        }
        
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            
            for key, pattern in sensitive_patterns.items():
                if re.search(pattern, resp.text, re.IGNORECASE):
                    issues.append({
                        'type': 'SENSITIVE_DATA_EXPOSURE',
                        'data_type': key,
                        'severity': 'CRITICAL'
                    })
        except Exception:
            pass
        
        return issues
    
    def audit(self, wordlist: Optional[str] = None) -> Dict:
        """Run full audit"""
        print(f"\n[*] Starting API audit on {self.base_url}")
        
        print("[*] Discovering endpoints...")
        endpoints = self.discover_endpoints(wordlist)
        
        print("[*] Testing endpoints...")
        for endpoint_url in endpoints:
            ep = self.test_endpoint(endpoint_url)
            self.endpoints.append(ep)
        
        print("[*] Checking CORS...")
        cors_issues = self.check_cors()
        self.misconfigurations.extend(cors_issues)
        
        print("[*] Checking security headers...")
        header_issues = self.check_missing_security_headers()
        self.misconfigurations.extend(header_issues)
        
        print("[*] Checking data exposure...")
        data_issues = self.check_sensitive_data_exposure()
        self.misconfigurations.extend(data_issues)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'endpoints': [asdict(ep) for ep in self.endpoints],
            'issues': self.misconfigurations,
        }
    
    def generate_report(self):
        """Generate audit report"""
        print(f"\n{'='*70}")
        print(f"API SECURITY AUDIT REPORT")
        print(f"{'='*70}")
        print(f"Target: {self.base_url}")
        print(f"Endpoints Tested: {len(self.endpoints)}")
        print(f"Issues Found: {len(self.misconfigurations)}")
        
        if self.misconfigurations:
            print(f"\n{'ISSUES:'}")
            for issue in self.misconfigurations:
                print(f"  [{issue.get('severity', 'UNKNOWN')}] {issue.get('type', 'Unknown')}")
                if 'origin' in issue:
                    print(f"    Origin: {issue['origin']}")
                if 'header' in issue:
                    print(f"    Missing: {issue['header']}")

def main():
    parser = argparse.ArgumentParser(description='API Security Auditor')
    parser.add_argument('url', help='Base API URL')
    parser.add_argument('-w', '--wordlist', help='Endpoint wordlist')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    auditor = APIAuditor(args.url, args.timeout)
    report = auditor.audit(args.wordlist)
    auditor.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")

if __name__ == '__main__':
    main()
