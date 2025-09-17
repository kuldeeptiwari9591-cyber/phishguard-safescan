# PhishGuard Advanced Server-Side Feature Extractor
# Comprehensive backend analysis with 36+ security features

import re
import ssl
import socket
import hashlib
import datetime
import urllib.parse
from urllib.parse import urlparse, parse_qs
import dns.resolver
import whois
import requests
from bs4 import BeautifulSoup
import tldextract
import base64
import json
from typing import Dict, List, Tuple, Optional

class AdvancedPhishingDetector:
    """
    Advanced phishing detection system with 36+ security features
    Integrates multiple detection techniques and threat intelligence
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'verify', 'urgent', 'suspended', 'limited', 'confirm',
            'login', 'signin', 'account', 'bank', 'paypal', 'amazon', 'update',
            'billing', 'payment', 'security', 'alert', 'warning', 'locked'
        ]
        
        self.phishing_indicators = [
            'click here', 'verify now', 'update payment', 'confirm identity',
            'account suspended', 'unusual activity', 'security breach',
            'immediate action', 'expires today', 'last warning'
        ]
        
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', 
            '.zip', '.top', '.bid', '.loan', '.work'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'buff.ly', 'short.link', 'tiny.cc', 'is.gd', 'v.gd'
        ]

    def analyze_url_comprehensive(self, url: str) -> Dict:
        """
        Comprehensive URL analysis with all 36 features
        """
        features = {
            'url': url,
            'timestamp': datetime.datetime.now().isoformat(),
            'risk_score': 0,
            'warnings': [],
            'feature_scores': {},
            'domain_info': {},
            'ssl_info': {},
            'content_info': {}
        }
        
        try:
            # Parse URL
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
            domain = parsed.netloc.lower()
            
            # Extract domain components
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain
            domain_name = extracted.domain
            tld = extracted.suffix
            
            features['domain_info'] = {
                'full_domain': domain,
                'subdomain': subdomain,
                'domain_name': domain_name,
                'tld': tld
            }
            
            # Feature 1-5: Basic URL Structure Analysis
            self._analyze_url_structure(url, parsed, features)
            
            # Feature 6-10: Domain Analysis
            self._analyze_domain_features(domain, subdomain, domain_name, tld, features)
            
            # Feature 11-15: Content and Parameter Analysis
            self._analyze_url_content(parsed, features)
            
            # Feature 16-20: SSL and Security Analysis
            self._analyze_ssl_security(domain, features)
            
            # Feature 21-25: WHOIS and Registration Analysis
            self._analyze_domain_registration(domain, features)
            
            # Feature 26-30: DNS and Network Analysis
            self._analyze_dns_network(domain, features)
            
            # Feature 31-36: Advanced Threat Intelligence
            self._analyze_threat_intelligence(url, domain, features)
            
        except Exception as e:
            features['risk_score'] = 90
            features['warnings'].append(f'Analysis error: {str(e)}')
            features['error'] = True
            
        return features

    def _analyze_url_structure(self, url: str, parsed, features: Dict) -> None:
        """Features 1-5: URL structure analysis"""
        
        # Feature 1: URL Length
        url_length = len(url)
        if url_length > 150:
            features['risk_score'] += 25
            features['warnings'].append('Extremely long URL detected')
            features['feature_scores']['url_length'] = 'high_risk'
        elif url_length > 100:
            features['risk_score'] += 15
            features['feature_scores']['url_length'] = 'medium_risk'
        else:
            features['feature_scores']['url_length'] = 'low_risk'
        
        # Feature 2: Protocol Analysis
        if parsed.scheme != 'https':
            features['risk_score'] += 30
            features['warnings'].append('Non-HTTPS protocol detected')
            features['feature_scores']['protocol'] = 'insecure'
        else:
            features['feature_scores']['protocol'] = 'secure'
            
        # Feature 3: Special Character Analysis
        special_chars = len(re.findall(r'[!@#$%^&*()_+={}\[\]:";\'<>?,.\/]', url))
        if special_chars > 20:
            features['risk_score'] += 20
            features['warnings'].append('Excessive special characters in URL')
            features['feature_scores']['special_chars'] = 'high'
        
        # Feature 4: Suspicious Path Patterns
        suspicious_paths = ['login', 'signin', 'account', 'verify', 'secure', 'update']
        path_matches = sum(1 for path in suspicious_paths if path in parsed.path.lower())
        if path_matches > 2:
            features['risk_score'] += 25
            features['warnings'].append('Multiple suspicious keywords in URL path')
        
        # Feature 5: URL Encoding Detection
        encoded_chars = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        if encoded_chars > 10:
            features['risk_score'] += 20
            features['warnings'].append('Excessive URL encoding detected')
            
    def _analyze_domain_features(self, domain: str, subdomain: str, domain_name: str, tld: str, features: Dict) -> None:
        """Features 6-10: Domain-specific analysis"""
        
        # Feature 6: Subdomain Analysis
        subdomain_count = len(subdomain.split('.')) if subdomain else 0
        if subdomain_count > 3:
            features['risk_score'] += 25
            features['warnings'].append('Excessive subdomain levels detected')
        
        # Feature 7: Domain Name Analysis
        if len(domain_name) < 3:
            features['risk_score'] += 20
            features['warnings'].append('Suspiciously short domain name')
        
        hyphen_count = domain_name.count('-')
        if hyphen_count > 3:
            features['risk_score'] += 20
            features['warnings'].append('Excessive hyphens in domain name')
        
        # Feature 8: TLD Analysis
        if f'.{tld}' in self.suspicious_tlds:
            features['risk_score'] += 30
            features['warnings'].append(f'Suspicious top-level domain: .{tld}')
        
        # Feature 9: Domain Similarity (Typosquatting)
        for legit_domain in self.legitimate_domains:
            if self._calculate_domain_similarity(domain_name, legit_domain.split('.')[0]) > 0.8:
                features['risk_score'] += 40
                features['warnings'].append(f'Possible typosquatting of {legit_domain}')
                break
        
        # Feature 10: Numeric Analysis
        numeric_ratio = sum(c.isdigit() for c in domain_name) / len(domain_name) if domain_name else 0
        if numeric_ratio > 0.4:
            features['risk_score'] += 15
            features['warnings'].append('High numeric content in domain name')

    def _analyze_url_content(self, parsed, features: Dict) -> None:
        """Features 11-15: URL content and parameter analysis"""
        
        # Feature 11: Parameter Analysis
        params = parse_qs(parsed.query)
        param_count = len(params)
        
        if param_count > 10:
            features['risk_score'] += 20
            features['warnings'].append('Excessive URL parameters detected')
        
        # Feature 12: Suspicious Parameter Names
        suspicious_params = ['token', 'auth', 'login', 'pass', 'user', 'account']
        for param in params:
            if any(susp in param.lower() for susp in suspicious_params):
                features['risk_score'] += 15
                features['warnings'].append(f'Suspicious parameter detected: {param}')
        
        # Feature 13: Parameter Value Analysis
        for param, values in params.items():
            for value in values:
                if len(value) > 100:  # Unusually long parameter value
                    features['risk_score'] += 10
                    features['warnings'].append('Unusually long parameter value detected')
                
                # Check for encoded content
                try:
                    decoded = base64.b64decode(value)
                    if len(decoded) > 20:  # Significant base64 content
                        features['risk_score'] += 15
                        features['warnings'].append('Base64 encoded parameter detected')
                except:
                    pass
        
        # Feature 14: Fragment Analysis
        if parsed.fragment:
            fragment_length = len(parsed.fragment)
            if fragment_length > 50:
                features['risk_score'] += 10
                features['warnings'].append('Long URL fragment detected')
        
        # Feature 15: Path Depth Analysis
        path_segments = [seg for seg in parsed.path.split('/') if seg]
        if len(path_segments) > 8:
            features['risk_score'] += 15
            features['warnings'].append('Excessive URL path depth')

    def _analyze_ssl_security(self, domain: str, features: Dict) -> None:
        """Features 16-20: SSL and security analysis"""
        
        try:
            # Feature 16: SSL Certificate Validation
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    features['ssl_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore']
                    }
                    
                    # Feature 17: Certificate Expiration
                    expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry_date - datetime.datetime.now()).days
                    
                    if days_to_expiry < 30:
                        features['risk_score'] += 25
                        features['warnings'].append('SSL certificate expires soon')
                    
                    # Feature 18: Certificate Issuer Analysis
                    issuer = features['ssl_info']['issuer'].get('organizationName', '')
                    trusted_issuers = ['Let\'s Encrypt', 'DigiCert', 'GlobalSign', 'Comodo']
                    
                    if not any(trusted in issuer for trusted in trusted_issuers):
                        features['risk_score'] += 20
                        features['warnings'].append('SSL certificate from untrusted issuer')
                    
                    # Feature 19: Subject Alternative Names
                    san_list = cert.get('subjectAltName', [])
                    if len(san_list) > 20:  # Excessive SANs might indicate suspicious cert
                        features['risk_score'] += 15
                        features['warnings'].append('SSL certificate has excessive alternative names')
                    
                    # Feature 20: Certificate Chain Validation
                    # This would require more complex validation in production
                    features['feature_scores']['ssl_valid'] = True
                    
        except Exception as e:
            features['risk_score'] += 35
            features['warnings'].append('SSL certificate validation failed')
            features['ssl_info'] = {'error': str(e)}

    def _analyze_domain_registration(self, domain: str, features: Dict) -> None:
        """Features 21-25: WHOIS and registration analysis"""
        
        try:
            # Feature 21: Domain Age Analysis
            domain_info = whois.whois(domain)
            
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age = (datetime.datetime.now() - creation_date).days
                
                if domain_age < 30:
                    features['risk_score'] += 40
                    features['warnings'].append('Domain registered very recently')
                elif domain_age < 90:
                    features['risk_score'] += 25
                    features['warnings'].append('Domain registered recently')
                
                features['domain_info']['age_days'] = domain_age
            
            # Feature 22: Registration Period Analysis
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    expiry_date = domain_info.expiration_date[0]
                else:
                    expiry_date = domain_info.expiration_date
                
                registration_period = (expiry_date - creation_date).days if creation_date else 0
                
                if registration_period < 365:  # Less than 1 year registration
                    features['risk_score'] += 20
                    features['warnings'].append('Short domain registration period')
            
            # Feature 23: Registrar Analysis
            registrar = domain_info.registrar
            if registrar:
                # Check for suspicious registrars (this would be a curated list)
                suspicious_registrars = ['NAMECHEAP', 'GODADDY']  # Example
                if any(susp in registrar.upper() for susp in suspicious_registrars):
                    features['risk_score'] += 10
            
            # Feature 24: Privacy Protection Analysis
            if 'privacy' in str(domain_info).lower() or 'protected' in str(domain_info).lower():
                features['risk_score'] += 15
                features['warnings'].append('Domain uses privacy protection')
            
            # Feature 25: Registrant Information Analysis
            if not domain_info.org and not domain_info.name:
                features['risk_score'] += 20
                features['warnings'].append('Missing registrant information')
                
        except Exception as e:
            features['risk_score'] += 15
            features['warnings'].append('WHOIS lookup failed')

    def _analyze_dns_network(self, domain: str, features: Dict) -> None:
        """Features 26-30: DNS and network analysis"""
        
        try:
            # Feature 26: DNS Record Analysis
            a_records = dns.resolver.resolve(domain, 'A')
            features['dns_info'] = {
                'a_records': [str(record) for record in a_records],
                'record_count': len(a_records)
            }
            
            # Feature 27: IP Geolocation Analysis
            # This would integrate with IP geolocation services
            # For now, simulate analysis
            
            # Feature 28: MX Record Analysis
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if len(mx_records) == 0:
                    features['risk_score'] += 10
                    features['warnings'].append('No MX records found')
            except:
                features['risk_score'] += 5
            
            # Feature 29: NS Record Analysis
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                features['dns_info']['ns_records'] = [str(record) for record in ns_records]
            except:
                features['risk_score'] += 10
                features['warnings'].append('NS record lookup failed')
            
            # Feature 30: TTL Analysis
            for record in a_records:
                if hasattr(record, 'ttl') and record.ttl < 300:  # Very low TTL
                    features['risk_score'] += 15
                    features['warnings'].append('Suspiciously low DNS TTL')
                    break
                    
        except Exception as e:
            features['risk_score'] += 20
            features['warnings'].append('DNS analysis failed')

    def _analyze_threat_intelligence(self, url: str, domain: str, features: Dict) -> None:
        """Features 31-36: Advanced threat intelligence"""
        
        # Feature 31: URL Reputation Check
        # This would integrate with threat intelligence APIs
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        features['url_hash'] = url_hash
        
        # Feature 32: Domain Blacklist Check
        # Simulate blacklist check
        if self._is_domain_blacklisted(domain):
            features['risk_score'] = 100
            features['warnings'].append('CRITICAL: Domain found in blacklist')
        
        # Feature 33: Content Fetching and Analysis
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            # Feature 34: HTTP Response Analysis
            if response.status_code != 200:
                features['risk_score'] += 15
                features['warnings'].append(f'HTTP error: {response.status_code}')
            
            # Feature 35: Content Analysis
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for suspicious forms
            forms = soup.find_all('form')
            for form in forms:
                if form.get('action', '').startswith('http://'):  # Insecure form action
                    features['risk_score'] += 30
                    features['warnings'].append('Insecure form submission detected')
            
            # Check for suspicious scripts
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and 'eval(' in script.string:
                    features['risk_score'] += 25
                    features['warnings'].append('Suspicious JavaScript detected')
            
            # Feature 36: Meta Tag Analysis
            title = soup.find('title')
            if title and any(keyword in title.text.lower() for keyword in self.suspicious_keywords):
                features['risk_score'] += 20
                features['warnings'].append('Suspicious keywords in page title')
                
        except Exception as e:
            features['warnings'].append('Content analysis failed')

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using Levenshtein distance"""
        def levenshtein(s1, s2):
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        distance = levenshtein(domain1, domain2)
        max_len = max(len(domain1), len(domain2))
        return 1 - (distance / max_len) if max_len > 0 else 0

    def _is_domain_blacklisted(self, domain: str) -> bool:
        """Check if domain is in blacklist (simulation)"""
        # In production, this would check against real threat intelligence feeds
        blacklisted_domains = [
            'malicious-site.com', 'phishing-test.net', 'scam-example.org',
            'fake-bank.com', 'suspicious-domain.tk'
        ]
        return domain in blacklisted_domains

    def analyze_email(self, email_data: Dict) -> Dict:
        """Comprehensive email analysis"""
        features = {
            'timestamp': datetime.datetime.now().isoformat(),
            'risk_score': 0,
            'warnings': [],
            'sender_analysis': {},
            'content_analysis': {},
            'header_analysis': {}
        }
        
        sender = email_data.get('sender', '')
        subject = email_data.get('subject', '')
        content = email_data.get('content', '')
        headers = email_data.get('headers', '')
        
        # Sender analysis
        if '@' in sender:
            sender_domain = sender.split('@')[1].lower()
            features['sender_analysis']['domain'] = sender_domain
            
            # Check sender domain reputation
            if self._is_domain_blacklisted(sender_domain):
                features['risk_score'] += 50
                features['warnings'].append('Sender domain is blacklisted')
        
        # Subject analysis
        urgent_words = ['urgent', 'immediate', 'expires', 'limited time', 'act now']
        subject_urgency = sum(1 for word in urgent_words if word in subject.lower())
        if subject_urgency > 1:
            features['risk_score'] += 25
            features['warnings'].append('Subject contains multiple urgency indicators')
        
        # Content analysis
        phishing_phrases = sum(1 for phrase in self.phishing_indicators if phrase in content.lower())
        if phishing_phrases > 2:
            features['risk_score'] += 40
            features['warnings'].append('Content contains multiple phishing phrases')
        
        # URL extraction and analysis
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        for url in urls:
            url_analysis = self.analyze_url_comprehensive(url)
            if url_analysis['risk_score'] > 60:
                features['risk_score'] += 30
                features['warnings'].append('Email contains high-risk URL')
        
        features['content_analysis'] = {
            'url_count': len(urls),
            'phishing_phrases': phishing_phrases,
            'subject_urgency': subject_urgency
        }
        
        return features

# Example usage and testing
if __name__ == "__main__":
    detector = AdvancedPhishingDetector()
    
    # Test URL analysis
    test_urls = [
        'https://paypal-security-update.com/login',
        'http://bit.ly/suspicious-link',
        'https://google.com',
        'https://amaz0n-security.tk/update-payment'
    ]
    
    print("PhishGuard Advanced Analysis Results:")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = detector.analyze_url_comprehensive(url)
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Warnings: {len(result['warnings'])}")
        for warning in result['warnings'][:3]:  # Show first 3 warnings
            print(f"  - {warning}")
        print("-" * 30)