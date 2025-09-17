# PhishGuard Flask Backend API
# Advanced phishing detection server with comprehensive analysis

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime
from feature_extractor import AdvancedPhishingDetector
import requests
from typing import Dict, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize the phishing detector
detector = AdvancedPhishingDetector()

# API Keys (use environment variables in production)
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
WHOISXML_API_KEY = os.getenv('WHOISXML_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Rate limiting storage (use Redis in production)
request_counts = {}

class APIError(Exception):
    """Custom API Error"""
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code

@app.errorhandler(APIError)
def handle_api_error(error):
    response = jsonify({'error': error.message})
    response.status_code = error.status_code
    return response

@app.route('/')
def index():
    """Serve the main HTML page"""
    try:
        with open('index.html', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishGuard API</title>
        </head>
        <body>
            <h1>PhishGuard Advanced Phishing Detection API</h1>
            <h2>Available Endpoints:</h2>
            <ul>
                <li>POST /api/analyze-url - Analyze URL for phishing</li>
                <li>POST /api/analyze-email - Analyze email content</li>
                <li>POST /api/analyze-website - Comprehensive website scan</li>
                <li>POST /api/bulk-analyze - Bulk URL analysis</li>
                <li>GET /api/health - Health check</li>
                <li>GET /api/stats - API statistics</li>
            </ul>
            <p>For documentation, visit /api/docs</p>
        </body>
        </html>
        ''')

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'features': 36
    })

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """
    Comprehensive URL analysis endpoint
    Expected JSON: {"url": "https://example.com", "deep_analysis": true}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            raise APIError('URL is required', 400)
        
        url = data['url'].strip()
        deep_analysis = data.get('deep_analysis', True)
        real_time_check = data.get('real_time_check', True)
        
        if not url:
            raise APIError('URL cannot be empty', 400)
        
        logger.info(f"Analyzing URL: {url}")
        
        # Perform comprehensive analysis
        analysis_result = detector.analyze_url_comprehensive(url)
        
        # Add real-time threat intelligence if enabled
        if real_time_check and GOOGLE_SAFE_BROWSING_API_KEY:
            safe_browsing_result = check_google_safe_browsing(url)
            analysis_result['safe_browsing'] = safe_browsing_result
            
            if safe_browsing_result.get('threat_detected'):
                analysis_result['risk_score'] = 100
                analysis_result['warnings'].append('CRITICAL: URL flagged by Google Safe Browsing')
        
        # Add VirusTotal check if API key available
        if VIRUSTOTAL_API_KEY:
            vt_result = check_virustotal(url)
            analysis_result['virustotal'] = vt_result
            
            if vt_result.get('malicious_count', 0) > 0:
                analysis_result['risk_score'] = min(analysis_result['risk_score'] + 30, 100)
                analysis_result['warnings'].append(f'Flagged by {vt_result["malicious_count"]} security vendors')
        
        # Determine final risk level
        analysis_result['risk_level'] = get_risk_level(analysis_result['risk_score'])
        
        # Log analysis
        log_analysis(url, analysis_result, 'url')
        
        return jsonify(analysis_result)
        
    except APIError:
        raise
    except Exception as e:
        logger.error(f"URL analysis error: {str(e)}")
        raise APIError(f'Analysis failed: {str(e)}', 500)

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """
    Email phishing analysis endpoint
    Expected JSON: {
        "sender": "email@domain.com",
        "subject": "Email subject",
        "content": "Email content",
        "headers": "Email headers (optional)"
    }
    """
    try:
        data = request.get_json()
        
        required_fields = ['sender', 'subject', 'content']
        for field in required_fields:
            if not data or field not in data:
                raise APIError(f'{field} is required', 400)
        
        logger.info(f"Analyzing email from: {data['sender']}")
        
        # Perform email analysis
        analysis_result = detector.analyze_email(data)
        
        # Additional header analysis if provided
        if data.get('headers'):
            header_analysis = analyze_email_headers(data['headers'])
            analysis_result['header_analysis'] = header_analysis
            
            if header_analysis.get('spf_fail') or header_analysis.get('dkim_fail'):
                analysis_result['risk_score'] += 25
                analysis_result['warnings'].append('Email failed authentication checks')
        
        analysis_result['risk_level'] = get_risk_level(analysis_result['risk_score'])
        
        # Log analysis
        log_analysis(data['sender'], analysis_result, 'email')
        
        return jsonify(analysis_result)
        
    except APIError:
        raise
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}")
        raise APIError(f'Email analysis failed: {str(e)}', 500)

@app.route('/api/analyze-website', methods=['POST'])
def analyze_website():
    """
    Comprehensive website security scan
    Expected JSON: {
        "website": "https://example.com",
        "checks": {
            "ssl": true,
            "domain": true,
            "content": true,
            "behavior": true,
            "seo": true,
            "social": true
        }
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'website' not in data:
            raise APIError('Website URL is required', 400)
        
        website = data['website'].strip()
        checks = data.get('checks', {
            'ssl': True, 'domain': True, 'content': True,
            'behavior': True, 'seo': True, 'social': True
        })
        
        logger.info(f"Scanning website: {website}")
        
        # Perform comprehensive website analysis
        scan_result = perform_website_scan(website, checks)
        
        # Add additional security checks
        if checks.get('ssl', True):
            ssl_analysis = analyze_ssl_comprehensive(website)
            scan_result['ssl_analysis'] = ssl_analysis
            
            if ssl_analysis.get('vulnerabilities'):
                scan_result['risk_score'] += 20
                scan_result['warnings'].extend(ssl_analysis['vulnerabilities'])
        
        scan_result['risk_level'] = get_risk_level(scan_result['risk_score'])
        
        # Log analysis
        log_analysis(website, scan_result, 'website')
        
        return jsonify(scan_result)
        
    except APIError:
        raise
    except Exception as e:
        logger.error(f"Website scan error: {str(e)}")
        raise APIError(f'Website scan failed: {str(e)}', 500)

@app.route('/api/bulk-analyze', methods=['POST'])
def bulk_analyze():
    """
    Bulk URL analysis endpoint
    Expected JSON: {
        "urls": ["url1", "url2", ...],
        "max_urls": 50
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            raise APIError('URLs list is required', 400)
        
        urls = data['urls']
        max_urls = min(data.get('max_urls', 50), 100)  # Limit to prevent abuse
        
        if len(urls) > max_urls:
            raise APIError(f'Maximum {max_urls} URLs allowed', 400)
        
        logger.info(f"Bulk analyzing {len(urls)} URLs")
        
        results = []
        for i, url in enumerate(urls[:max_urls]):
            try:
                # Quick analysis for bulk processing
                result = detector.analyze_url_comprehensive(url)
                result['index'] = i + 1
                results.append(result)
            except Exception as e:
                results.append({
                    'index': i + 1,
                    'url': url,
                    'error': str(e),
                    'risk_score': 0,
                    'warnings': [f'Analysis failed: {str(e)}']
                })
        
        # Generate summary statistics
        summary = generate_bulk_summary(results)
        
        response = {
            'total_analyzed': len(results),
            'summary': summary,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response)
        
    except APIError:
        raise
    except Exception as e:
        logger.error(f"Bulk analysis error: {str(e)}")
        raise APIError(f'Bulk analysis failed: {str(e)}', 500)

@app.route('/api/stats')
def get_stats():
    """Get API usage statistics"""
    # In production, this would query a database
    return jsonify({
        'total_analyses': 1000,  # Mock data
        'urls_analyzed': 650,
        'emails_analyzed': 250,
        'websites_scanned': 100,
        'threats_detected': 45,
        'accuracy_rate': 94.2,
        'last_updated': datetime.now().isoformat()
    })

# Helper Functions

def check_google_safe_browsing(url: str) -> Dict:
    """Check URL against Google Safe Browsing API"""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {'error': 'API key not configured'}
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "2.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            return {
                'threat_detected': bool(result.get('matches')),
                'threats': result.get('matches', []),
                'api_response': 'success'
            }
        else:
            return {'error': f'API returned status {response.status_code}'}
            
    except Exception as e:
        return {'error': str(e)}

def check_virustotal(url: str) -> Dict:
    """Check URL against VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return {'error': 'API key not configured'}
    
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        # First, submit URL for analysis
        submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        submit_data = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
        
        submit_response = requests.post(submit_url, data=submit_data, timeout=10)
        
        if submit_response.status_code == 200:
            # Get existing report if available
            report_url = "https://www.virustotal.com/vtapi/v2/url/report"
            report_data = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
            
            report_response = requests.get(report_url, params=report_data, timeout=10)
            
            if report_response.status_code == 200:
                report = report_response.json()
                
                if report.get('response_code') == 1:  # Report found
                    return {
                        'scan_date': report.get('scan_date'),
                        'total_scans': report.get('total'),
                        'positive_scans': report.get('positives'),
                        'malicious_count': report.get('positives', 0),
                        'permalink': report.get('permalink')
                    }
        
        return {'status': 'queued', 'message': 'Analysis queued'}
        
    except Exception as e:
        return {'error': str(e)}

def analyze_email_headers(headers: str) -> Dict:
    """Analyze email headers for authentication and routing"""
    analysis = {
        'spf_pass': False,
        'dkim_pass': False,
        'dmarc_pass': False,
        'received_hops': 0,
        'suspicious_routes': []
    }
    
    # Simple header analysis (would be more comprehensive in production)
    if 'spf=pass' in headers.lower():
        analysis['spf_pass'] = True
    elif 'spf=fail' in headers.lower():
        analysis['spf_fail'] = True
    
    if 'dkim=pass' in headers.lower():
        analysis['dkim_pass'] = True
    elif 'dkim=fail' in headers.lower():
        analysis['dkim_fail'] = True
    
    # Count received headers (mail hops)
    analysis['received_hops'] = headers.lower().count('received:')
    
    if analysis['received_hops'] > 10:
        analysis['suspicious_routes'].append('Excessive mail routing hops')
    
    return analysis

def perform_website_scan(website: str, checks: Dict) -> Dict:
    """Perform comprehensive website security scan"""
    scan_result = {
        'website': website,
        'timestamp': datetime.now().isoformat(),
        'risk_score': 0,
        'warnings': [],
        'checks': []
    }
    
    # Use the detector's comprehensive analysis
    url_analysis = detector.analyze_url_comprehensive(website)
    
    # Merge results
    scan_result['risk_score'] = url_analysis['risk_score']
    scan_result['warnings'] = url_analysis['warnings']
    
    # Convert to check format
    for feature, score in url_analysis.get('feature_scores', {}).items():
        status = 'pass' if score in ['low_risk', 'secure'] else 'fail' if score in ['high_risk', 'insecure'] else 'warning'
        scan_result['checks'].append({
            'name': feature.replace('_', ' ').title(),
            'status': status,
            'message': f'Feature analysis: {score}'
        })
    
    return scan_result

def analyze_ssl_comprehensive(domain: str) -> Dict:
    """Comprehensive SSL analysis"""
    # This would integrate with SSL testing services
    return {
        'grade': 'A+',  # Mock data
        'vulnerabilities': [],
        'certificate_valid': True,
        'protocol_support': ['TLS 1.2', 'TLS 1.3']
    }

def get_risk_level(score: int) -> str:
    """Convert risk score to risk level"""
    if score >= 80:
        return 'Critical'
    elif score >= 60:
        return 'High'
    elif score >= 30:
        return 'Medium'
    else:
        return 'Low'

def generate_bulk_summary(results: List[Dict]) -> Dict:
    """Generate summary statistics for bulk analysis"""
    total = len(results)
    
    risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    total_score = 0
    
    for result in results:
        if 'error' not in result:
            risk_level = get_risk_level(result['risk_score'])
            risk_counts[risk_level] += 1
            total_score += result['risk_score']
    
    return {
        'total_analyzed': total,
        'average_risk_score': total_score / total if total > 0 else 0,
        'risk_distribution': risk_counts,
        'high_risk_percentage': ((risk_counts['Critical'] + risk_counts['High']) / total * 100) if total > 0 else 0
    }

def log_analysis(identifier: str, result: Dict, analysis_type: str) -> None:
    """Log analysis for monitoring and statistics"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': analysis_type,
        'identifier': identifier,
        'risk_score': result.get('risk_score', 0),
        'risk_level': result.get('risk_level', 'Unknown'),
        'warnings_count': len(result.get('warnings', []))
    }
    
    logger.info(f"Analysis logged: {json.dumps(log_entry)}")

# Static file serving
@app.route('/style.css')
def serve_css():
    try:
        with open('style.css', 'r') as f:
            return f.read(), 200, {'Content-Type': 'text/css'}
    except FileNotFoundError:
        return '', 404

@app.route('/script.js')
def serve_js():
    try:
        with open('script.js', 'r') as f:
            return f.read(), 200, {'Content-Type': 'application/javascript'}
    except FileNotFoundError:
        return '', 404

@app.route('/feature_script.js')
def serve_feature_js():
    try:
        with open('feature_script.js', 'r') as f:
            return f.read(), 200, {'Content-Type': 'application/javascript'}
    except FileNotFoundError:
        return '', 404

if __name__ == '__main__':
    # Development server
    print("=" * 60)
    print("PhishGuard Advanced Phishing Detection System")
    print("Version 2.0.0 - 36 Security Features")
    print("=" * 60)
    print("Starting Flask development server...")
    print("Available at: http://localhost:5000")
    print("API Documentation: http://localhost:5000/api/docs")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)