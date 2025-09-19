# PhishGuard Enhanced Server-Side Feature Extractor
# Advanced backend analysis with 36+ security features and ML-inspired techniques

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
import math
import statistics
from typing import Dict, List, Tuple, Optional, Any
from collections import Counter
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedPhishingDetector:
    """
    Enhanced phishing detection system with 36+ security features
    Integrates multiple detection techniques, threat intelligence, and ML-inspired analysis
    """
    
    def __init__(self):
        # Enhanced suspicious keywords with weighted scoring
        self.suspicious_keywords = {
            'secure': 15, 'verify': 20, 'urgent': 25, 'suspended': 30, 'limited': 20,
            'confirm': 20, 'login': 18, 'signin': 18, 'account': 15, 'bank': 25,
            'paypal': 30, 'amazon': 25, 'update': 18, 'billing': 22, 'payment': 22,
            'security': 20, 'alert': 25, 'warning': 25, 'locked': 28, 'expired': 25,
            'validation': 22, 'authentication': 25, 'credential': 30, 'identity': 25
        }
        
        # Enhanced phishing indicators with context analysis
        self.phishing_indicators = [
            'click here', 'verify now', 'update payment', 'confirm identity',
            'account suspended', 'unusual activity', 'security breach',
            'immediate action', 'expires today', 'last warning', 'final notice',
            'temporary suspension', 'reactivate account', 'confirm information'
        ]
        
        # Comprehensive legitimate domain database
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'meta.com', 'twitter.com', 'x.com', 'linkedin.com', 
            'github.com', 'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com',
            'instagram.com', 'youtube.com', 'gmail.com', 'outlook.com', 'yahoo.com',
            'dropbox.com', 'salesforce.com', 'adobe.com', 'zoom.us'
        ]
        
        # Enhanced suspicious TLD database
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip', '.top', 
            '.bid', '.loan', '.work', '.science', '.party', '.date', '.review',
            '.cricket', '.stream', '.trade', '.accountant', '.faith', '.win'
        ]
        
        # Comprehensive URL shortener database
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
            'short.link', 'tiny.cc', 'is.gd', 'v.gd', 'cutt.ly', 'rebrand.ly',
            'clickmeter.com', 'clicky.me', 'bc.vc', 'shorte.st', 'adf.ly'
        ]
        
        # Threat intelligence databases (simulated)
        self.known_malicious_domains = set([
            'phishing-example.com', 'fake-bank.net', 'scam-site.org',
            'malicious-site.tk', 'phish-test.ml', 'dangerous-link.ga'
        ])
        
        # Dynamic DNS providers
        self.dynamic_dns_providers = [
            'dyndns', 'no-ip', 'freedns', 'changeip', '3utilities',
            'dynu', 'dnsdynamic', 'freemyip'
        ]

    def analyze_url_comprehensive(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL analysis with enhanced security features
        """
        features = {
            'url': url,
            'timestamp': datetime.datetime.now().isoformat(),
            'risk_score': 0,
            'warnings': [],
            'feature_scores': {},
            'domain_info': {},
            'ssl_info': {},
            'content_info': {},
            'threat_intelligence': {},
            'confidence_score': 0
        }
        
        try:
            # Parse URL with enhanced validation
            parsed = self._parse_url_safely(url)
            if not parsed:
                raise ValueError("Invalid URL format")
                
            domain = parsed.netloc.lower()
            
            # Extract domain components with validation
            try:
                extracted = tldextract.extract(url)
                subdomain = extracted.subdomain
                domain_name = extracted.domain
                tld = extracted.suffix
            except Exception as e:
                logger.warning(f"TLD extraction failed: {e}")
                subdomain, domain_name, tld = self._manual_domain_extraction(domain)
            
            features['domain_info'] = {
                'full_domain': domain,
                'subdomain': subdomain,
                'domain_name': domain_name,
                'tld': tld,
                'domain_length': len(domain)
            }
            
            # Feature Analysis Pipeline
            self._analyze_url_structure_enhanced(url, parsed, features)
            self._analyze_domain_features_enhanced(domain, subdomain, domain_name, tld, features)
            self._analyze_content_parameters_enhanced(parsed, features)
            self._analyze_ssl_security_enhanced(domain, features)
            self._analyze_domain_registration_enhanced(domain, features)
            self._analyze_dns_network_enhanced(domain, features)
            self._analyze_threat_intelligence_enhanced(url, domain, features)
            self._calculate_risk_confidence(features)
            
        except Exception as e:
            logger.error(f"Analysis error for {url}: {e}")
            features['risk_score'] = 95
            features['warnings'].append(f'Critical analysis error: {str(e)}')
            features['error'] = True
            features['confidence_score'] = 0
            
        return features

    def _parse_url_safely(self, url: str) -> Optional[urlparse]:
        """Safely parse URL with multiple fallback methods"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            return parsed
        except Exception:
            return None

    def _manual_domain_extraction(self, domain: str) -> Tuple[str, str, str]:
        """Manual domain extraction as fallback"""
        parts = domain.split('.')
        if len(parts) < 2:
            return '', domain, ''
        
        tld = parts[-1]
        domain_name = parts[-2] if len(parts) >= 2 else ''
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        
        return subdomain, domain_name, tld

    def _analyze_url_structure_enhanced(self, url: str, parsed, features: Dict) -> None:
        """Enhanced URL structure analysis with security features"""
        
        # Advanced URL Length Analysis
        url_length = len(url)
        length_score = self._calculate_length_score(url_length)
        features['risk_score'] += length_score['risk']
        features['warnings'].extend(length_score['warnings'])
        features['feature_scores']['url_length'] = length_score['category']
        
        # Protocol Security Analysis
        protocol_analysis = self._analyze_protocol_security(parsed, url)
        features['risk_score'] += protocol_analysis['risk']
        features['warnings'].extend(protocol_analysis['warnings'])
        features['feature_scores'].update(protocol_analysis['features'])
        
        # Character Composition Analysis
        char_analysis = self._analyze_character_composition(url)
        features['risk_score'] += char_analysis['risk']
        features['warnings'].extend(char_analysis['warnings'])
        features['feature_scores']['character_analysis'] = char_analysis['features']
        
        # Entropy and Randomness Analysis
        entropy_analysis = self._calculate_url_entropy(url)
        if entropy_analysis['suspicious']:
            features['risk_score'] += entropy_analysis['risk']
            features['warnings'].extend(entropy_analysis['warnings'])
        features['feature_scores']['entropy'] = entropy_analysis
        
        # Path Structure Analysis
        path_analysis = self._analyze_path_structure(parsed)
        features['risk_score'] += path_analysis['risk']
        features['warnings'].extend(path_analysis['warnings'])
        features['feature_scores']['path_analysis'] = path_analysis['features']

    def _calculate_length_score(self, length: int) -> Dict:
        """Calculate risk score based on URL length with thresholds"""
        if length > 250:
            return {'risk': 35, 'warnings': ['Extremely long URL (>250 chars) - advanced obfuscation'], 'category': 'extreme'}
        elif length > 200:
            return {'risk': 30, 'warnings': ['Very long URL (>200 chars) - possible obfuscation'], 'category': 'very_long'}
        elif length > 150:
            return {'risk': 20, 'warnings': ['Long URL detected - potential hiding'], 'category': 'long'}
        elif length > 100:
            return {'risk': 10, 'warnings': [], 'category': 'moderate'}
        else:
            return {'risk': 0, 'warnings': [], 'category': 'normal'}

    def _analyze_protocol_security(self, parsed, url: str) -> Dict:
        """Enhanced protocol security analysis"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        # Basic HTTPS check
        if parsed.scheme != 'https':
            analysis['risk'] += 35
            analysis['warnings'].append('Non-HTTPS protocol - data transmission not encrypted')
            analysis['features']['protocol_secure'] = False
        else:
            analysis['features']['protocol_secure'] = True
        
        # Mixed content detection
        if 'http://' in url and 'https://' in url:
            analysis['risk'] += 30
            analysis['warnings'].append('Mixed content detected - protocol inconsistency')
            analysis['features']['mixed_content'] = True
        
        # Protocol confusion attacks
        if url.count('://') > 1:
            analysis['risk'] += 40
            analysis['warnings'].append('Multiple protocol declarations - potential confusion attack')
            analysis['features']['protocol_confusion'] = True
        
        return analysis

    def _analyze_character_composition(self, url: str) -> Dict:
        """Analyze character composition for suspicious patterns"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        # Special character analysis
        special_chars = re.findall(r'[!@#$%^&*()_+={}\[\]:";\'<>?,.\/~`]', url)
        special_ratio = len(special_chars) / len(url)
        
        if special_ratio > 0.15:
            analysis['risk'] += 20
            analysis['warnings'].append('High concentration of special characters')
        
        analysis['features']['special_char_ratio'] = special_ratio
        analysis['features']['special_char_count'] = len(special_chars)
        
        # Numeric character analysis
        numeric_chars = re.findall(r'\d', url)
        numeric_ratio = len(numeric_chars) / len(url)
        
        if numeric_ratio > 0.3:
            analysis['risk'] += 15
            analysis['warnings'].append('High numeric content - possible generated URL')
        
        analysis['features']['numeric_ratio'] = numeric_ratio
        
        # Case variation analysis
        uppercase_count = sum(1 for c in url if c.isupper())
        lowercase_count = sum(1 for c in url if c.islower())
        
        if uppercase_count > 0 and lowercase_count > 0:
            case_variation = min(uppercase_count, lowercase_count) / max(uppercase_count, lowercase_count)
            if case_variation > 0.3:
                analysis['risk'] += 10
                analysis['warnings'].append('Unusual case variation pattern')
        
        return analysis

    def _calculate_url_entropy(self, url: str) -> Dict:
        """Calculate Shannon entropy for randomness detection"""
        try:
            # Calculate character frequency
            char_counts = Counter(url.lower())
            total_chars = len(url)
            
            # Calculate Shannon entropy
            entropy = -sum((count/total_chars) * math.log2(count/total_chars) 
                          for count in char_counts.values())
            
            # Analyze entropy thresholds
            suspicious = False
            risk = 0
            warnings = []
            
            if entropy > 4.5:
                suspicious = True
                risk = 25
                warnings.append('Very high entropy - likely randomly generated')
            elif entropy > 4.0:
                suspicious = True
                risk = 15
                warnings.append('High entropy - possible random generation')
            
            return {
                'suspicious': suspicious,
                'risk': risk,
                'warnings': warnings,
                'entropy_score': entropy,
                'randomness_level': 'high' if entropy > 4.0 else 'normal'
            }
        except Exception as e:
            logger.warning(f"Entropy calculation failed: {e}")
            return {'suspicious': False, 'risk': 0, 'warnings': [], 'entropy_score': 0}

    def _analyze_path_structure(self, parsed) -> Dict:
        """Analyze URL path structure for suspicious patterns"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        path = parsed.path
        path_segments = [seg for seg in path.split('/') if seg]
        
        # Path depth analysis
        depth = len(path_segments)
        if depth > 10:
            analysis['risk'] += 20
            analysis['warnings'].append('Excessive path depth - possible obfuscation')
        elif depth > 6:
            analysis['risk'] += 10
        
        analysis['features']['path_depth'] = depth
        
        # Suspicious path patterns
        suspicious_patterns = [
            r'\.\./', r'%2e%2e%2f', r'admin', r'config', r'backup',
            r'test', r'temp', r'debug', r'dev', r'staging'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                analysis['risk'] += 12
                analysis['warnings'].append(f'Suspicious path pattern detected')
                break
        
        # File extension analysis
        if '.' in path:
            extension = path.split('.')[-1].lower()
            dangerous_extensions = [
                'exe', 'scr', 'bat', 'com', 'pif', 'cmd', 'jar', 'zip', 'rar'
            ]
            if extension in dangerous_extensions:
                analysis['risk'] += 30
                analysis['warnings'].append(f'Dangerous file extension: .{extension}')
                analysis['features']['dangerous_extension'] = extension
        
        return analysis

    def _analyze_domain_features_enhanced(self, domain: str, subdomain: str, 
                                        domain_name: str, tld: str, features: Dict) -> None:
        """Enhanced domain feature analysis with security techniques"""
        
        # Advanced subdomain analysis
        subdomain_analysis = self._analyze_subdomains_advanced(subdomain, domain)
        features['risk_score'] += subdomain_analysis['risk']
        features['warnings'].extend(subdomain_analysis['warnings'])
        features['feature_scores']['subdomain_analysis'] = subdomain_analysis['features']
        
        # Domain name composition analysis
        composition_analysis = self._analyze_domain_composition(domain_name)
        features['risk_score'] += composition_analysis['risk']
        features['warnings'].extend(composition_analysis['warnings'])
        features['feature_scores']['domain_composition'] = composition_analysis
        
        # TLD analysis with geopolitical context
        tld_analysis = self._analyze_tld_enhanced(tld, domain)
        features['risk_score'] += tld_analysis['risk']
        features['warnings'].extend(tld_analysis['warnings'])
        features['feature_scores']['tld_analysis'] = tld_analysis['features']
        
        # Typosquatting detection with advanced algorithms
        typo_analysis = self._detect_typosquatting_advanced(domain_name, domain)
        features['risk_score'] += typo_analysis['risk']
        features['warnings'].extend(typo_analysis['warnings'])
        features['threat_intelligence']['typosquatting'] = typo_analysis
        
        # Brand impersonation detection
        brand_analysis = self._detect_brand_impersonation(domain)
        features['risk_score'] += brand_analysis['risk']
        features['warnings'].extend(brand_analysis['warnings'])
        features['threat_intelligence']['brand_impersonation'] = brand_analysis

    def _analyze_subdomains_advanced(self, subdomain: str, full_domain: str) -> Dict:
        """Advanced subdomain analysis with pattern recognition"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        if not subdomain:
            analysis['features']['subdomain_count'] = 0
            return analysis
        
        subdomain_parts = subdomain.split('.')
        subdomain_count = len(subdomain_parts)
        
        # Excessive subdomain analysis
        if subdomain_count > 5:
            analysis['risk'] += 35
            analysis['warnings'].append('Excessive subdomain levels - possible abuse')
        elif subdomain_count > 3:
            analysis['risk'] += 20
            analysis['warnings'].append('High subdomain levels detected')
        
        analysis['features']['subdomain_count'] = subdomain_count
        
        # Suspicious subdomain patterns
        suspicious_subdomains = [
            'secure', 'login', 'auth', 'verify', 'account', 'update',
            'service', 'support', 'admin', 'mail', 'webmail'
        ]
        
        for part in subdomain_parts:
            if part.lower() in suspicious_subdomains:
                analysis['risk'] += 15
                analysis['warnings'].append(f'Suspicious subdomain: {part}')
        
        # Random subdomain detection
        for part in subdomain_parts:
            if len(part) > 8 and self._is_random_string(part):
                analysis['risk'] += 20
                analysis['warnings'].append('Random subdomain detected')
                break
        
        return analysis

    def _is_random_string(self, s: str) -> bool:
        """Detect if string appears randomly generated"""
        if len(s) < 4:
            return False
        
        # Check for alternating patterns
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        vowel_count = sum(1 for c in s.lower() if c in vowels)
        consonant_count = sum(1 for c in s.lower() if c in consonants)
        
        # Random strings often have poor vowel/consonant balance
        if vowel_count == 0 or consonant_count == 0:
            return True
        
        ratio = vowel_count / consonant_count
        return ratio < 0.1 or ratio > 3.0

    def _analyze_domain_composition(self, domain_name: str) -> Dict:
        """Analyze domain name composition for suspicious patterns"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        if not domain_name:
            return analysis
        
        # Length analysis
        length = len(domain_name)
        if length < 3:
            analysis['risk'] += 25
            analysis['warnings'].append('Suspiciously short domain name')
        elif length > 25:
            analysis['risk'] += 15
            analysis['warnings'].append('Unusually long domain name')
        
        analysis['features']['domain_length'] = length
        
        # Character analysis
        hyphen_count = domain_name.count('-')
        numeric_count = sum(1 for c in domain_name if c.isdigit())
        
        # Hyphen analysis
        if hyphen_count > 4:
            analysis['risk'] += 25
            analysis['warnings'].append('Excessive hyphens in domain')
        
        # Numeric analysis
        numeric_ratio = numeric_count / length if length > 0 else 0
        if numeric_ratio > 0.5:
            analysis['risk'] += 20
            analysis['warnings'].append('High numeric content in domain')
        
        analysis['features'].update({
            'hyphen_count': hyphen_count,
            'numeric_ratio': numeric_ratio,
            'contains_numbers': numeric_count > 0
        })
        
        # Dictionary word analysis
        word_analysis = self._analyze_dictionary_words(domain_name)
        analysis['risk'] += word_analysis['risk']
        analysis['warnings'].extend(word_analysis['warnings'])
        analysis['features']['word_analysis'] = word_analysis['features']
        
        return analysis

    def _analyze_dictionary_words(self, domain_name: str) -> Dict:
        """Analyze presence of dictionary words in domain"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        # Common words that appear in phishing domains
        phishing_words = [
            'secure', 'safe', 'verify', 'confirm', 'account', 'login',
            'signin', 'update', 'service', 'support', 'help', 'center'
        ]
        
        domain_lower = domain_name.lower()
        found_words = []
        
        for word in phishing_words:
            if word in domain_lower:
                found_words.append(word)
                analysis['risk'] += 12
        
        if len(found_words) > 1:
            analysis['warnings'].append(f'Multiple suspicious words: {", ".join(found_words)}')
        elif found_words:
            analysis['warnings'].append(f'Suspicious word detected: {found_words[0]}')
        
        analysis['features'] = {
            'suspicious_words': found_words,
            'word_count': len(found_words)
        }
        
        return analysis

    def _analyze_tld_enhanced(self, tld: str, domain: str) -> Dict:
        """Enhanced TLD analysis with geopolitical context"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        if not tld:
            return analysis
        
        full_tld = f'.{tld}'
        
        # Suspicious TLD check
        if full_tld in self.suspicious_tlds:
            analysis['risk'] += 30
            analysis['warnings'].append(f'High-risk TLD detected: {full_tld}')
            analysis['features']['suspicious_tld'] = True
        else:
            analysis['features']['suspicious_tld'] = False
        
        # Country code analysis
        ccTLDs_high_risk = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if full_tld in ccTLDs_high_risk:
            analysis['risk'] += 25
            analysis['warnings'].append('High-risk country code TLD')
        
        # New gTLD analysis
        new_gtlds = ['.click', '.download', '.zip', '.top', '.loan', '.work']
        if full_tld in new_gtlds:
            analysis['risk'] += 20
            analysis['warnings'].append('New gTLD with elevated risk profile')
        
        analysis['features']['tld'] = tld
        analysis['features']['tld_category'] = self._categorize_tld(tld)
        
        return analysis

    def _categorize_tld(self, tld: str) -> str:
        """Categorize TLD by type and risk level"""
        if tld in ['com', 'org', 'net', 'edu', 'gov']:
            return 'traditional'
        elif tld in ['tk', 'ml', 'ga', 'cf']:
            return 'high_risk_free'
        elif len(tld) == 2:
            return 'country_code'
        else:
            return 'new_gtld'

    def _detect_typosquatting_advanced(self, domain_name: str, full_domain: str) -> Dict:
        """Advanced typosquatting detection using multiple algorithms"""
        analysis = {'risk': 0, 'warnings': [], 'targets': [], 'similarities': []}
        
        for legit_domain in self.legitimate_domains:
            legit_name = legit_domain.split('.')[0]
            
            # Multiple similarity algorithms
            similarities = {
                'levenshtein': self._levenshtein_similarity(domain_name, legit_name),
                'jaro_winkler': self._jaro_winkler_similarity(domain_name, legit_name),
                'phonetic': self._phonetic_similarity(domain_name, legit_name)
            }
            
            max_similarity = max(similarities.values())
            
            # Typosquatting detection thresholds
            if max_similarity > 0.85 and domain_name != legit_name:
                analysis['risk'] += 50
                analysis['warnings'].append(f'High similarity to {legit_domain} ({max_similarity:.2f})')
                analysis['targets'].append({
                    'domain': legit_domain,
                    'similarity': max_similarity,
                    'algorithm': max(similarities, key=similarities.get)
                })
            elif max_similarity > 0.75:
                analysis['risk'] += 35
                analysis['warnings'].append(f'Possible typosquatting of {legit_domain}')
        
        return analysis

    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Calculate Levenshtein similarity"""
        if len(s1) < len(s2):
            return self._levenshtein_similarity(s2, s1)
        
        if len(s2) == 0:
            return 0.0
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        distance = previous_row[-1]
        return 1 - distance / max(len(s1), len(s2))

    def _jaro_winkler_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaro-Winkler similarity (simplified implementation)"""
        if s1 == s2:
            return 1.0
        
        len_1, len_2 = len(s1), len(s2)
        if len_1 == 0 or len_2 == 0:
            return 0.0
        
        match_window = max(len_1, len_2) // 2 - 1
        if match_window < 0:
            match_window = 0
        
        s1_matches = [False] * len_1
        s2_matches = [False] * len_2
        
        matches = 0
        transpositions = 0
        
        # Find matches
        for i in range(len_1):
            start = max(0, i - match_window)
            end = min(i + match_window + 1, len_2)
            
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = s2_matches[j] = True
                matches += 1
                break
        
        if matches == 0:
            return 0.0
        
        # Count transpositions
        k = 0
        for i in range(len_1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
        
        jaro = (matches/len_1 + matches/len_2 + (matches-transpositions/2)/matches) / 3
        
        # Winkler modification
        prefix = 0
        for i in range(min(len_1, len_2, 4)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break
        
        return jaro + 0.1 * prefix * (1 - jaro)

    def _phonetic_similarity(self, s1: str, s2: str) -> float:
        """Simplified phonetic similarity based on character substitutions"""
        substitutions = {
            '0': 'o', '1': 'i', '1': 'l', '3': 'e', '5': 's',
            '6': 'g', '7': 't', '8': 'b', '9': 'g'
        }
        
        def normalize_phonetic(s):
            s = s.lower()
            for digit, letter in substitutions.items():
                s = s.replace(digit, letter)
            return s
        
        norm_s1 = normalize_phonetic(s1)
        norm_s2 = normalize_phonetic(s2)
        
        return self._levenshtein_similarity(norm_s1, norm_s2)

    def _detect_brand_impersonation(self, domain: str) -> Dict:
        """Detect brand impersonation attempts"""
        analysis = {'risk': 0, 'warnings': [], 'impersonated_brands': []}
        
        # Brand keywords and their variations
        brand_patterns = {
            'microsoft': ['microsoft', 'microsft', 'micosoft', 'office365', 'outlook'],
            'google': ['google', 'gmail', 'googIe', 'g00gle'],
            'apple': ['apple', 'icloud', 'appIe', 'app1e'],
            'amazon': ['amazon', 'amaz0n', 'amazom'],
            'paypal': ['paypal', 'paypaI', 'pay-pal', 'payp4l'],
            'facebook': ['facebook', 'fb', 'meta', 'faceb00k'],
            'bank': ['bank', 'banking', 'bnk', 'b4nk']
        }
        
        domain_lower = domain.lower()
        
        for brand, variations in brand_patterns.items():
            for variation in variations:
                if variation in domain_lower and not domain_lower.startswith(f'{brand}.'):
                    analysis['risk'] += 35
                    analysis['warnings'].append(f'Potential {brand} impersonation detected')
                    analysis['impersonated_brands'].append(brand)
                    break
        
        return analysis

    def _analyze_content_parameters_enhanced(self, parsed, features: Dict) -> None:
        """Enhanced content and parameter analysis"""
        
        # Advanced parameter analysis
        param_analysis = self._analyze_parameters_advanced(parsed)
        features['risk_score'] += param_analysis['risk']
        features['warnings'].extend(param_analysis['warnings'])
        features['feature_scores']['parameter_analysis'] = param_analysis['features']
        
        # Query string analysis
        query_analysis = self._analyze_query_string(parsed.query)
        features['risk_score'] += query_analysis['risk']
        features['warnings'].extend(query_analysis['warnings'])
        features['ml_features']['query_analysis'] = query_analysis
        
        # Fragment analysis
        if parsed.fragment:
            fragment_analysis = self._analyze_fragment(parsed.fragment)
            features['risk_score'] += fragment_analysis['risk']
            features['warnings'].extend(fragment_analysis['warnings'])

    def _analyze_parameters_advanced(self, parsed) -> Dict:
        """Advanced URL parameter analysis"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        params = parse_qs(parsed.query)
        param_count = len(params)
        
        # Parameter count analysis
        if param_count > 20:
            analysis['risk'] += 30
            analysis['warnings'].append('Excessive parameters - possible parameter pollution')
        elif param_count > 10:
            analysis['risk'] += 15
            analysis['warnings'].append('High parameter count detected')
        
        analysis['features']['param_count'] = param_count
        
        # Suspicious parameter names
        suspicious_params = [
            'token', 'auth', 'login', 'pass', 'password', 'user', 'username',
            'account', 'verify', 'confirm', 'session', 'cookie', 'key',
            'secret', 'admin', 'root', 'debug', 'test'
        ]
        
        suspicious_found = []
        for param_name in params.keys():
            param_lower = param_name.lower()
            for suspicious in suspicious_params:
                if suspicious in param_lower:
                    suspicious_found.append(param_name)
                    analysis['risk'] += 18
                    break
        
        if suspicious_found:
            analysis['warnings'].append(f'Suspicious parameters: {", ".join(suspicious_found)}')
        
        # Parameter value analysis
        for param_name, param_values in params.items():
            for value in param_values:
                # Long parameter values
                if len(value) > 200:
                    analysis['risk'] += 15
                    analysis['warnings'].append(f'Unusually long parameter value: {param_name}')
                
                # Base64 detection
                if self._is_base64(value) and len(value) > 20:
                    analysis['risk'] += 20
                    analysis['warnings'].append(f'Base64 encoded parameter: {param_name}')
                
                # SQL injection patterns
                if self._contains_sql_patterns(value):
                    analysis['risk'] += 25
                    analysis['warnings'].append('Potential SQL injection pattern in parameters')
                
                # XSS patterns
                if self._contains_xss_patterns(value):
                    analysis['risk'] += 25
                    analysis['warnings'].append('Potential XSS pattern in parameters')
        
        return analysis

    def _is_base64(self, s: str) -> bool:
        """Check if string is base64 encoded"""
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

    def _contains_sql_patterns(self, value: str) -> bool:
        """Check for SQL injection patterns"""
        sql_patterns = [
            r"union\s+select", r"drop\s+table", r"insert\s+into",
            r"delete\s+from", r"update\s+set", r"or\s+1\s*=\s*1",
            r"and\s+1\s*=\s*1", r"'.*or.*'", r'".*or.*"'
        ]
        
        value_lower = value.lower()
        return any(re.search(pattern, value_lower) for pattern in sql_patterns)

    def _contains_xss_patterns(self, value: str) -> bool:
        """Check for XSS patterns"""
        xss_patterns = [
            r"<script", r"javascript:", r"vbscript:", r"onload=",
            r"onerror=", r"onclick=", r"alert\(", r"document\.cookie"
        ]
        
        value_lower = value.lower()
        return any(re.search(pattern, value_lower) for pattern in xss_patterns)

    def _analyze_query_string(self, query: str) -> Dict:
        """Analyze query string for suspicious patterns"""
        analysis = {'risk': 0, 'warnings': [], 'features': {}}
        
        if not query:
            return analysis
        
        # Query length analysis
        query_length = len(query)
        if query_length > 500:
            analysis['risk'] += 20
            analysis['warnings'].append('Extremely long query string')
        
        # Encoding analysis
        encoded_chars = len(re.findall(r'%[0-9A-Fa-f]{2}', query))
        encoding_ratio = encoded_chars / len(query) if query else 0
        
        if encoding_ratio > 0.2:
            analysis['risk'] += 18
            analysis['warnings'].append('High URL encoding in query string')
        
        analysis['features'] = {
            'query_length': query_length,
            'encoding_ratio': encoding_ratio,
            'encoded_chars': encoded_chars
        }
        
        return analysis

    def _analyze_fragment(self, fragment: str) -> Dict:
        """Analyze URL fragment for suspicious content"""
        analysis = {'risk': 0, 'warnings': []}
        
        if len(fragment) > 100:
            analysis['risk'] += 15
            analysis['warnings'].append('Long URL fragment - possible data hiding')
        
        # Check for suspicious patterns in fragment
        if re.search(r'(token|auth|login|pass)', fragment, re.IGNORECASE):
            analysis['risk'] += 20
            analysis['warnings'].append('Sensitive keywords in URL fragment')
        
        return analysis

    def _analyze_ssl_security_enhanced(self, domain: str, features: Dict) -> None:
        """Enhanced SSL security analysis with detailed certificate inspection"""
        
        try:
            # Create SSL context with verification
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Comprehensive certificate analysis
                    cert_analysis = self._analyze_certificate_comprehensive(cert, domain)
                    features['risk_score'] += cert_analysis['risk']
                    features['warnings'].extend(cert_analysis['warnings'])
                    features['ssl_info'] = cert_analysis['certificate_info']
                    
        except socket.timeout:
            features['risk_score'] += 25
            features['warnings'].append('SSL connection timeout - possible connectivity issues')
            features['ssl_info'] = {'error': 'timeout'}
        except ssl.SSLError as e:
            features['risk_score'] += 40
            features['warnings'].append(f'SSL/TLS error: {str(e)}')
            features['ssl_info'] = {'error': 'ssl_error', 'details': str(e)}
        except Exception as e:
            features['risk_score'] += 35
            features['warnings'].append('SSL certificate validation failed')
            features['ssl_info'] = {'error': 'validation_failed', 'details': str(e)}

    def _analyze_certificate_comprehensive(self, cert: Dict, domain: str) -> Dict:
        """Comprehensive SSL certificate analysis"""
        analysis = {'risk': 0, 'warnings': [], 'certificate_info': {}}
        
        try:
            # Extract certificate information
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            analysis['certificate_info'] = {
                'subject': subject,
                'issuer': issuer,
                'version': cert.get('version'),
                'serial_number': cert.get('serialNumber'),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter'),
                'signature_algorithm': cert.get('signatureAlgorithm')
            }
            
            # Certificate expiration analysis
            if cert.get('notAfter'):
                try:
                    expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry_date - datetime.datetime.now()).days
                    
                    if days_to_expiry < 0:
                        analysis['risk'] += 50
                        analysis['warnings'].append('SSL certificate has expired')
                    elif days_to_expiry < 30:
                        analysis['risk'] += 30
                        analysis['warnings'].append('SSL certificate expires soon')
                    elif days_to_expiry < 90:
                        analysis['risk'] += 15
                        analysis['warnings'].append('SSL certificate expires within 90 days')
                    
                    analysis['certificate_info']['days_to_expiry'] = days_to_expiry
                except ValueError as e:
                    logger.warning(f"Date parsing error: {e}")
            
            # Certificate issuer analysis
            issuer_name = issuer.get('organizationName', '').lower()
            trusted_issuers = [
                'let\'s encrypt', 'digicert', 'globalsign', 'comodo',
                'sectigo', 'godaddy', 'entrust', 'verisign', 'thawte',
                'geotrust', 'rapidssl', 'cloudflare'
            ]
            
            is_trusted_issuer = any(trusted in issuer_name for trusted in trusted_issuers)
            if not is_trusted_issuer and issuer_name:
                analysis['risk'] += 25
                analysis['warnings'].append(f'Certificate from less common issuer: {issuer_name}')
            
            # Subject Alternative Names analysis
            san_list = cert.get('subjectAltName', [])
            if len(san_list) > 50:
                analysis['risk'] += 20
                analysis['warnings'].append('Certificate has excessive alternative names')
            
            # Wildcard certificate analysis
            cn = subject.get('commonName', '')
            if cn.startswith('*.'):
                analysis['certificate_info']['is_wildcard'] = True
                # Wildcard certificates can be riskier if used improperly
                if len(san_list) > 20:
                    analysis['risk'] += 15
                    analysis['warnings'].append('Wildcard certificate with many SANs')
            
            # Self-signed certificate detection
            if subject == issuer:
                analysis['risk'] += 40
                analysis['warnings'].append('Self-signed certificate detected')
                analysis['certificate_info']['is_self_signed'] = True
            
        except Exception as e:
            analysis['risk'] += 20
            analysis['warnings'].append('Certificate analysis failed')
            logger.error(f"Certificate analysis error: {e}")
        
        return analysis

    def _analyze_domain_registration_enhanced(self, domain: str, features: Dict) -> None:
        """Enhanced domain registration analysis with WHOIS intelligence"""
        
        try:
            # WHOIS lookup with enhanced analysis
            domain_info = whois.whois(domain)
            whois_analysis = self._analyze_whois_comprehensive(domain_info)
            
            features['risk_score'] += whois_analysis['risk']
            features['warnings'].extend(whois_analysis['warnings'])
            features['domain_info'].update(whois_analysis['domain_info'])
            
        except Exception as e:
            features['risk_score'] += 20
            features['warnings'].append('WHOIS lookup failed - domain information unavailable')
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    def _analyze_whois_comprehensive(self, domain_info) -> Dict:
        """Comprehensive WHOIS analysis"""
        analysis = {'risk': 0, 'warnings': [], 'domain_info': {}}
        
        try:
            # Domain age analysis
            creation_date = self._extract_date(domain_info.creation_date)
            if creation_date:
                domain_age = (datetime.datetime.now() - creation_date).days
                
                if domain_age < 7:
                    analysis['risk'] += 50
                    analysis['warnings'].append('Domain registered within last week - highly suspicious')
                elif domain_age < 30:
                    analysis['risk'] += 40
                    analysis['warnings'].append('Very new domain registration (<30 days)')
                elif domain_age < 90:
                    analysis['risk'] += 25
                    analysis['warnings'].append('Recent domain registration (<90 days)')
                elif domain_age < 365:
                    analysis['risk'] += 15
                    analysis['warnings'].append('Domain registered within last year')
                
                analysis['domain_info']['age_days'] = domain_age
                analysis['domain_info']['creation_date'] = creation_date.isoformat()
            
            # Registration period analysis
            expiry_date = self._extract_date(domain_info.expiration_date)
            if creation_date and expiry_date:
                registration_period = (expiry_date - creation_date).days
                
                if registration_period < 365:
                    analysis['risk'] += 25
                    analysis['warnings'].append('Short registration period (<1 year)')
                elif registration_period < 730:
                    analysis['risk'] += 10
                    analysis['warnings'].append('Registration period less than 2 years')
                
                analysis['domain_info']['registration_period_days'] = registration_period
            
            # Registrar analysis
            registrar = domain_info.registrar
            if registrar:
                analysis['domain_info']['registrar'] = registrar
                
                # Check for registrars commonly used by malicious actors
                suspicious_registrars = [
                    'namecheap', 'godaddy', 'enom', 'dynadot'  # Note: These aren't inherently suspicious
                ]
                # This is just an example - in practice, you'd use threat intelligence
                
            # Privacy protection analysis
            whois_text = str(domain_info).lower()
            if any(keyword in whois_text for keyword in ['privacy', 'protected', 'redacted', 'whoisguard']):
                analysis['risk'] += 15
                analysis['warnings'].append('Domain uses privacy protection')
                analysis['domain_info']['privacy_protected'] = True
            
            # Registrant information analysis
            if not domain_info.org and not domain_info.name:
                analysis['risk'] += 20
                analysis['warnings'].append('Missing registrant information')
                analysis['domain_info']['missing_registrant_info'] = True
            
            # Multiple registration analysis
            if hasattr(domain_info, 'name_servers') and domain_info.name_servers:
                ns_count = len(domain_info.name_servers)
                if ns_count > 10:
                    analysis['risk'] += 10
                    analysis['warnings'].append('Unusual number of name servers')
                analysis['domain_info']['name_server_count'] = ns_count
            
        except Exception as e:
            analysis['risk'] += 10
            analysis['warnings'].append('WHOIS analysis incomplete')
            logger.warning(f"WHOIS analysis error: {e}")
        
        return analysis

    def _extract_date(self, date_value):
        """Extract datetime from various date formats"""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime.datetime):
            return date_value
        
        return None

    def _analyze_dns_network_enhanced(self, domain: str, features: Dict) -> None:
        """Enhanced DNS and network analysis"""
        
        try:
            # Comprehensive DNS analysis
            dns_analysis = self._perform_dns_analysis(domain)
            features['risk_score'] += dns_analysis['risk']
            features['warnings'].extend(dns_analysis['warnings'])
            features['dns_info'] = dns_analysis['dns_info']
            
        except Exception as e:
            features['risk_score'] += 15
            features['warnings'].append('DNS analysis failed')
            logger.warning(f"DNS analysis failed for {domain}: {e}")

    def _perform_dns_analysis(self, domain: str) -> Dict:
        """Perform comprehensive DNS analysis"""
        analysis = {'risk': 0, 'warnings': [], 'dns_info': {}}
        
        try:
            # A record analysis
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                ip_addresses = [str(record) for record in a_records]
                analysis['dns_info']['a_records'] = ip_addresses
                
                # IP geolocation analysis (simplified)
                for ip in ip_addresses:
                    if self._is_suspicious_ip(ip):
                        analysis['risk'] += 25
                        analysis['warnings'].append(f'Suspicious IP address detected: {ip}')
                
            except dns.resolver.NXDOMAIN:
                analysis['risk'] += 30
                analysis['warnings'].append('Domain does not exist (NXDOMAIN)')
            except dns.resolver.NoAnswer:
                analysis['risk'] += 20
                analysis['warnings'].append('No A records found')
            
            # MX record analysis
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_list = [str(record) for record in mx_records]
                analysis['dns_info']['mx_records'] = mx_list
                
                if len(mx_list) == 0:
                    analysis['risk'] += 10
                    analysis['warnings'].append('No MX records found')
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                analysis['risk'] += 5
                analysis['warnings'].append('No MX records configured')
            
            # NS record analysis
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                ns_list = [str(record) for record in ns_records]
                analysis['dns_info']['ns_records'] = ns_list
                
                # Check for suspicious name servers
                for ns in ns_list:
                    if any(suspicious in ns.lower() for suspicious in self.dynamic_dns_providers):
                        analysis['risk'] += 20
                        analysis['warnings'].append(f'Dynamic DNS provider detected: {ns}')
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                analysis['risk'] += 15
                analysis['warnings'].append('NS record lookup failed')
            
            # TTL analysis
            try:
                answer = dns.resolver.resolve(domain, 'A')
                ttl = answer.rrset.ttl
                analysis['dns_info']['ttl'] = ttl
                
                if ttl < 300:  # Very low TTL
                    analysis['risk'] += 20
                    analysis['warnings'].append('Suspiciously low DNS TTL')
                elif ttl < 3600:  # Low TTL
                    analysis['risk'] += 10
                    analysis['warnings'].append('Low DNS TTL detected')
                
            except Exception:
                pass
            
        except Exception as e:
            analysis['risk'] += 10
            analysis['warnings'].append('DNS analysis incomplete')
            logger.warning(f"DNS analysis error: {e}")
        
        return analysis

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        # This would integrate with threat intelligence feeds
        # For now, check for private/reserved ranges being used publicly
        
        suspicious_ranges = [
            '127.',     # Loopback
            '10.',      # Private Class A
            '172.16.',  # Private Class B (simplified check)
            '192.168.', # Private Class C
            '169.254.', # Link-local
            '224.',     # Multicast
            '240.'      # Reserved
        ]
        
        return any(ip.startswith(range_) for range_ in suspicious_ranges)

    def _analyze_threat_intelligence_enhanced(self, url: str, domain: str, features: Dict) -> None:
        """Enhanced threat intelligence analysis"""
        
        # Known malicious domain check
        if domain in self.known_malicious_domains:
            features['risk_score'] = 100
            features['warnings'].append('CRITICAL: Domain found in known malicious database')
            features['threat_intelligence']['known_malicious'] = True
            return
        
        # URL reputation analysis
        reputation_analysis = self._analyze_url_reputation(url, domain)
        features['risk_score'] += reputation_analysis['risk']
        features['warnings'].extend(reputation_analysis['warnings'])
        features['threat_intelligence']['reputation'] = reputation_analysis
        
        # Pattern-based threat detection
        pattern_analysis = self._detect_threat_patterns(url, domain)
        features['risk_score'] += pattern_analysis['risk']
        features['warnings'].extend(pattern_analysis['warnings'])
        features['threat_intelligence']['patterns'] = pattern_analysis
        
        # Behavioral analysis
        behavior_analysis = self._analyze_threat_behavior(url, domain, features)
        features['risk_score'] += behavior_analysis['risk']
        features['warnings'].extend(behavior_analysis['warnings'])
        features['threat_intelligence']['behavior'] = behavior_analysis

    def _analyze_url_reputation(self, url: str, domain: str) -> Dict:
        """Analyze URL reputation using various indicators"""
        analysis = {'risk': 0, 'warnings': [], 'reputation_score': 0, 'indicators': []}
        
        # URL hash analysis
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        analysis['url_hash'] = url_hash
        
        # Domain reputation simulation
        reputation_score = self._calculate_domain_reputation(domain)
        analysis['reputation_score'] = reputation_score
        
        if reputation_score < 30:
            analysis['risk'] += 35
            analysis['warnings'].append('Poor domain reputation score')
        elif reputation_score < 50:
            analysis['risk'] += 20
            analysis['warnings'].append('Below average domain reputation')
        
        # Blacklist simulation
        if self._simulate_blacklist_check(domain):
            analysis['risk'] += 50
            analysis['warnings'].append('Domain found in security blacklists')
            analysis['indicators'].append('blacklisted')
        
        return analysis

    def _calculate_domain_reputation(self, domain: str) -> int:
        """Calculate domain reputation score (simulated)"""
        # This would integrate with real reputation services
        # For simulation, use domain characteristics
        
        score = 50  # Base score
        
        # Length-based adjustments
        if len(domain) < 5:
            score -= 20
        elif len(domain) > 30:
            score -= 10
        
        # TLD-based adjustments
        tld = domain.split('.')[-1]
        if tld in ['com', 'org', 'net']:
            score += 10
        elif tld in ['tk', 'ml', 'ga', 'cf']:
            score -= 30
        
        # Character-based adjustments
        if '-' in domain:
            score -= 5 * domain.count('-')
        
        if any(char.isdigit() for char in domain):
            score -= 10
        
        return max(0, min(100, score))

    def _simulate_blacklist_check(self, domain: str) -> bool:
        """Simulate blacklist check (would use real threat intelligence)"""
        # Simulate based on domain characteristics
        suspicious_indicators = [
            len(domain) < 5,
            domain.count('-') > 3,
            any(keyword in domain for keyword in ['secure', 'verify', 'login']),
            domain.endswith(('.tk', '.ml', '.ga', '.cf'))
        ]
        
        return sum(suspicious_indicators) >= 3

    def _detect_threat_patterns(self, url: str, domain: str) -> Dict:
        """Detect threat patterns in URL structure"""
        analysis = {'risk': 0, 'warnings': [], 'patterns': []}
        
        # Advanced pattern matching
        threat_patterns = [
            {
                'pattern': r'[a-z0-9]{20,}',
                'risk': 20,
                'name': 'long_random_string',
                'description': 'Long random string detected'
            },
            {
                'pattern': r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
                'risk': 30,
                'name': 'ip_address',
                'description': 'IP address instead of domain'
            },
            {
                'pattern': r'data:image|javascript:|vbscript:',
                'risk': 40,
                'name': 'dangerous_protocol',
                'description': 'Dangerous protocol detected'
            },
            {
                'pattern': r'%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}',
                'risk': 25,
                'name': 'heavy_encoding',
                'description': 'Heavy URL encoding detected'
            }
        ]
        
        url_lower = url.lower()
        
        for pattern_info in threat_patterns:
            if re.search(pattern_info['pattern'], url_lower):
                analysis['risk'] += pattern_info['risk']
                analysis['warnings'].append(pattern_info['description'])
                analysis['patterns'].append(pattern_info['name'])
        
        return analysis

    def _analyze_threat_behavior(self, url: str, domain: str, features: Dict) -> Dict:
        """Analyze behavioral patterns that indicate threats"""
        analysis = {'risk': 0, 'warnings': [], 'behavior_score': 0}
        
        # Collect behavioral indicators
        indicators = []
        
        # URL structure indicators
        if features['feature_scores'].get('url_length') in ['extreme', 'very_long']:
            indicators.append('excessive_length')
        
        if features['ml_features'].get('entropy', {}).get('suspicious', False):
            indicators.append('high_entropy')
        
        # Domain indicators
        domain_info = features.get('domain_info', {})
        if domain_info.get('age_days', 365) < 30:
            indicators.append('new_domain')
        
        if features['feature_scores'].get('subdomain_analysis', {}).get('subdomain_count', 0) > 3:
            indicators.append('excessive_subdomains')
        
        # SSL indicators
        ssl_info = features.get('ssl_info', {})
        if ssl_info.get('error'):
            indicators.append('ssl_issues')
        
        # Calculate behavior score
        behavior_score = len(indicators) * 10
        analysis['behavior_score'] = behavior_score
        
        if behavior_score > 30:
            analysis['risk'] += 25
            analysis['warnings'].append('Multiple suspicious behavioral indicators')
        elif behavior_score > 20:
            analysis['risk'] += 15
            analysis['warnings'].append('Several behavioral red flags detected')
        
        analysis['indicators'] = indicators
        
        return analysis

    def _perform_ml_inspired_analysis(self, url: str, domain: str, features: Dict) -> None:
        """Perform ML-inspired analysis for advanced threat detection"""
        
        # Feature vector analysis
        vector_analysis = self._create_feature_vector(url, domain, features)
        features['ml_features']['feature_vector'] = vector_analysis
        
        # Anomaly detection
        anomaly_analysis = self._detect_anomalies_advanced(vector_analysis)
        features['risk_score'] += anomaly_analysis['risk']
        features['warnings'].extend(anomaly_analysis['warnings'])
        features['ml_features']['anomaly_detection'] = anomaly_analysis
        
        # Clustering analysis
        cluster_analysis = self._perform_clustering_analysis(vector_analysis)
        features['ml_features']['cluster_analysis'] = cluster_analysis
        
        if cluster_analysis['cluster'] == 'malicious':
            features['risk_score'] += 30
            features['warnings'].append('URL characteristics match malicious cluster')

    def _create_feature_vector(self, url: str, domain: str, features: Dict) -> Dict:
        """Create comprehensive feature vector for ML analysis"""
        vector = {
            'url_length': len(url),
            'domain_length': len(domain),
            'subdomain_count': features.get('domain_info', {}).get('subdomain_count', 0),
            'hyphen_count': domain.count('-'),
            'numeric_ratio': sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
            'special_char_ratio': len(re.findall(r'[!@#$%^&*()_+={}\[\]:";\'<>?,.\/~`]', url)) / len(url),
            'entropy': features.get('ml_features', {}).get('entropy', {}).get('entropy_score', 0),
            'suspicious_keywords': len(features.get('threat_intelligence', {}).get('reputation', {}).get('indicators', [])),
            'ssl_valid': not bool(features.get('ssl_info', {}).get('error')),
            'domain_age': features.get('domain_info', {}).get('age_days', 365),
            'has_suspicious_tld': features.get('feature_scores', {}).get('tld_analysis', {}).get('suspicious_tld', False),
            'typosquatting_detected': bool(features.get('threat_intelligence', {}).get('typosquatting', {}).get('targets'))
        }
        
        return vector

    def _detect_anomalies_advanced(self, feature_vector: Dict) -> Dict:
        """Advanced anomaly detection based on feature vector"""
        analysis = {'risk': 0, 'warnings': [], 'anomaly_score': 0, 'anomalies': []}
        
        # Define normal ranges for features
        normal_ranges = {
            'url_length': (10, 100),
            'domain_length': (5, 25),
            'subdomain_count': (0, 2),
            'hyphen_count': (0, 2),
            'numeric_ratio': (0, 0.2),
            'special_char_ratio': (0, 0.1),
            'entropy': (2.0, 4.0),
            'domain_age': (365, float('inf'))
        }
        
        anomaly_count = 0
        
        for feature, (min_val, max_val) in normal_ranges.items():
            if feature in feature_vector:
                value = feature_vector[feature]
                if value < min_val or value > max_val:
                    anomaly_count += 1
                    analysis['anomalies'].append(feature)
        
        # Calculate anomaly score
        anomaly_score = (anomaly_count / len(normal_ranges)) * 100
        analysis['anomaly_score'] = anomaly_score
        
        if anomaly_score > 50:
            analysis['risk'] += 30
            analysis['warnings'].append('High anomaly score - unusual characteristics')
        elif anomaly_score > 30:
            analysis['risk'] += 15
            analysis['warnings'].append('Moderate anomaly score detected')
        
        return analysis

    def _perform_clustering_analysis(self, feature_vector: Dict) -> Dict:
        """Simulate clustering analysis to categorize URLs"""
        analysis = {'cluster': 'normal', 'confidence': 0.5}
        
        # Simple rule-based clustering simulation
        malicious_indicators = 0
        
        # Check for malicious characteristics
        if feature_vector.get('url_length', 0) > 150:
            malicious_indicators += 1
        
        if feature_vector.get('entropy', 0) > 4.5:
            malicious_indicators += 1
        
        if feature_vector.get('domain_age', 365) < 30:
            malicious_indicators += 1
        
        if feature_vector.get('typosquatting_detected', False):
            malicious_indicators += 2
        
        if feature_vector.get('has_suspicious_tld', False):
            malicious_indicators += 1
        
        # Determine cluster
        if malicious_indicators >= 4:
            analysis['cluster'] = 'malicious'
            analysis['confidence'] = 0.9
        elif malicious_indicators >= 2:
            analysis['cluster'] = 'suspicious'
            analysis['confidence'] = 0.7
        else:
            analysis['cluster'] = 'normal'
            analysis['confidence'] = 0.6
        
        return analysis

    def _calculate_risk_confidence(self, features: Dict) -> None:
        """Calculate overall confidence score for the analysis"""
        confidence = 100
        
        # Reduce confidence for missing data
        if features.get('ssl_info', {}).get('error'):
            confidence -= 15
        
        if features.get('domain_info', {}).get('age_days') is None:
            confidence -= 10
        
        if not features.get('dns_info', {}).get('a_records'):
            confidence -= 10
        
        if features.get('error'):
            confidence -= 30
        
        # Increase confidence for comprehensive analysis
        if len(features.get('warnings', [])) > 5:
            confidence += 5
        
        if features.get('threat_intelligence', {}).get('reputation', {}).get('reputation_score', 0) > 0:
            confidence += 5
        
        features['confidence_score'] = max(0, min(100, confidence))

# Example usage and testing
if __name__ == "__main__":
    detector = AdvancedPhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://g00gle-secure-login.tk",
        "http://192.168.1.1:8080/admin/login.php",
        "https://paypal-security-update.ml/verify-account?token=abc123"
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = detector.analyze_url_comprehensive(url)
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Confidence: {result['confidence_score']}%")
        print(f"Warnings: {len(result['warnings'])}")
        for warning in result['warnings'][:3]:  # Show first 3 warnings
            print(f"  - {warning}")
        print("-" * 50)