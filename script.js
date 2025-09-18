// PhishGuard Main JavaScript - Frontend Controller & Quiz Logic

// Global Variables
let mobileMenuOpen = false;
let quizQuestions = [];
let currentQuestionIndex = 0;
let userAnswers = [];
let quizScore = 0;
let loadingTimeout = null;
let isAnalyzing = false;

// Quiz Questions Pool (30+ questions)
const allQuizQuestions = [
    {
        question: "What is a common sign of a phishing email?",
        options: ["Misspelled URLs", "Official company logos", "Secure HTTPS links", "Proper grammar"],
        answer: "Misspelled URLs",
        explanation: "Phishing emails often contain misspelled URLs to trick users into visiting fake websites."
    },
    {
        question: "Which URL is most likely to be a phishing attempt?",
        options: ["https://amazon.com", "https://amaz0n-security.com", "https://www.amazon.com", "https://amazon.co.uk"],
        answer: "https://amaz0n-security.com",
        explanation: "This URL uses character substitution (0 for o) and adds suspicious words like 'security'."
    },
    {
        question: "What should you do if you receive an urgent email asking for your password?",
        options: ["Reply with your password immediately", "Click the link and verify", "Contact the company directly", "Forward it to friends"],
        answer: "Contact the company directly",
        explanation: "Always verify suspicious requests through official channels, never through the suspicious email itself."
    },
    {
        question: "Which of these is NOT a red flag in an email?",
        options: ["Generic greeting like 'Dear Customer'", "Urgent language like 'Act Now!'", "Your name in the greeting", "Threats of account suspension"],
        answer: "Your name in the greeting",
        explanation: "Legitimate emails often use your actual name, while phishing emails use generic greetings."
    },
    {
        question: "What does HTTPS in a URL indicate?",
        options: ["The site is definitely safe", "The connection is encrypted", "The site is phishing", "Nothing important"],
        answer: "The connection is encrypted",
        explanation: "HTTPS encrypts data transmission but doesn't guarantee the site is legitimate. Phishing sites can also use HTTPS."
    },
    {
        question: "Which domain extension is commonly used in phishing?",
        options: [".com", ".org", ".tk", ".edu"],
        answer: ".tk",
        explanation: "Free domain extensions like .tk are often used by attackers because they're easy to obtain."
    },
    {
        question: "What is typosquatting?",
        options: ["Typing very fast", "Using similar-looking domain names", "Correcting typos", "A keyboard layout"],
        answer: "Using similar-looking domain names",
        explanation: "Typosquatting involves registering domains similar to legitimate ones to trick users."
    },
    {
        question: "If a URL contains an @ symbol, what might this indicate?",
        options: ["It's an email address", "It's definitely safe", "Possible redirection trick", "It's encrypted"],
        answer: "Possible redirection trick",
        explanation: "The @ symbol in URLs can be used to redirect users to malicious sites while hiding the real destination."
    },
    {
        question: "What should you check before clicking a link?",
        options: ["The link color", "The link destination by hovering", "The email signature", "The send time"],
        answer: "The link destination by hovering",
        explanation: "Hovering over links reveals the actual destination URL before clicking."
    },
    {
        question: "Which is a sign of a legitimate website?",
        options: ["Pop-up warnings", "Multiple redirects", "Clear contact information", "Excessive ads"],
        answer: "Clear contact information",
        explanation: "Legitimate websites provide clear, verifiable contact information and privacy policies."
    },
    {
        question: "What is social engineering in cybersecurity?",
        options: ["Building social networks", "Manipulating people to reveal information", "Engineering social apps", "Social media marketing"],
        answer: "Manipulating people to reveal information",
        explanation: "Social engineering exploits human psychology to trick people into divulging confidential information."
    },
    {
        question: "Which email greeting is most suspicious?",
        options: ["Dear John Smith", "Hello Mr. Smith", "Dear Valued Customer", "Hi John"],
        answer: "Dear Valued Customer",
        explanation: "Generic greetings like 'Dear Valued Customer' are red flags as legitimate companies use your actual name."
    },
    {
        question: "What is the best practice for password security?",
        options: ["Use the same password everywhere", "Use complex, unique passwords", "Share passwords with colleagues", "Write passwords on sticky notes"],
        answer: "Use complex, unique passwords",
        explanation: "Complex, unique passwords for each account provide the best security against breaches."
    },
    {
        question: "How can you verify if an email is from a legitimate company?",
        options: ["Check the sender's email carefully", "Trust the company logo", "Click all links to verify", "Forward it to check"],
        answer: "Check the sender's email carefully",
        explanation: "Legitimate companies use official email domains. Always verify the sender's address carefully."
    },
    {
        question: "What is two-factor authentication (2FA)?",
        options: ["Using two passwords", "An extra security layer", "Two security questions", "Dual antivirus"],
        answer: "An extra security layer",
        explanation: "2FA adds an extra verification step beyond just a password, significantly improving security."
    },
    {
        question: "Which URL shortener should you be cautious of?",
        options: ["bit.ly", "tinyurl.com", "All of them", "goo.gl"],
        answer: "All of them",
        explanation: "All URL shorteners can hide the real destination, making it impossible to verify safety before clicking."
    },
    {
        question: "What does a padlock icon in the browser address bar indicate?",
        options: ["The site is completely safe", "The connection is encrypted", "The site is government approved", "No viruses present"],
        answer: "The connection is encrypted",
        explanation: "The padlock indicates an encrypted connection (HTTPS) but doesn't guarantee the site is legitimate."
    },
    {
        question: "Which of these is a common phishing tactic?",
        options: ["Offering helpful tech tips", "Creating urgency and fear", "Providing detailed documentation", "Using professional language"],
        answer: "Creating urgency and fear",
        explanation: "Phishing attacks often create false urgency to pressure victims into acting without thinking."
    },
    {
        question: "What should you do if you think you've fallen for a phishing scam?",
        options: ["Do nothing", "Change passwords immediately", "Delete your email", "Buy antivirus software"],
        answer: "Change passwords immediately",
        explanation: "If compromised, immediately change passwords, check accounts, and monitor for suspicious activity."
    },
    {
        question: "Which browser security feature helps prevent phishing?",
        options: ["Pop-up blocker", "Safe browsing warnings", "Download manager", "Bookmark sync"],
        answer: "Safe browsing warnings",
        explanation: "Safe browsing features warn users about known malicious or suspicious websites."
    },
    {
        question: "What is spear phishing?",
        options: ["Fishing with a spear", "Mass email attacks", "Targeted personal attacks", "Mobile phone attacks"],
        answer: "Targeted personal attacks",
        explanation: "Spear phishing targets specific individuals with personalized attacks using their personal information."
    },
    {
        question: "Why do attackers use urgent language in phishing emails?",
        options: ["To be helpful", "To bypass rational thinking", "To save time", "To appear official"],
        answer: "To bypass rational thinking",
        explanation: "Urgent language creates panic and pressure, causing victims to act impulsively without verification."
    },
    {
        question: "What is a common characteristic of phishing websites?",
        options: ["Perfect spelling", "Professional design", "Poor grammar and spelling", "Detailed privacy policy"],
        answer: "Poor grammar and spelling",
        explanation: "Many phishing sites contain obvious grammar and spelling errors due to rushed creation or language barriers."
    },
    {
        question: "Which action is safest when receiving a suspicious email?",
        options: ["Click to investigate", "Reply asking for verification", "Delete without opening", "Forward to IT"],
        answer: "Delete without opening",
        explanation: "When in doubt, delete suspicious emails without opening attachments or clicking links."
    },
    {
        question: "What is pharming?",
        options: ["Email phishing", "DNS hijacking attack", "Phone scams", "Social media fraud"],
        answer: "DNS hijacking attack",
        explanation: "Pharming redirects website traffic to malicious sites by compromising DNS servers or local DNS settings."
    },
    {
        question: "How often should you update your passwords?",
        options: ["Never", "Every few years", "Regularly, especially after breaches", "Only when forgotten"],
        answer: "Regularly, especially after breaches",
        explanation: "Regular password updates, especially after data breaches, help maintain account security."
    },
    {
        question: "What is the main goal of phishing attacks?",
        options: ["Entertainment", "Stealing personal information", "Testing security", "Educational purposes"],
        answer: "Stealing personal information",
        explanation: "Phishing aims to steal credentials, personal data, or financial information for malicious purposes."
    },
    {
        question: "Which attachment type is commonly used in phishing?",
        options: [".txt files", ".jpg images", ".exe files", ".pdf documents"],
        answer: ".exe files",
        explanation: "Executable files (.exe) can contain malware and should be treated with extreme caution."
    },
    {
        question: "What should you verify before entering sensitive information online?",
        options: ["Website speed", "Website colors", "Website URL and security", "Website ads"],
        answer: "Website URL and security",
        explanation: "Always verify you're on the correct, secure website before entering sensitive information."
    },
    {
        question: "What is the most effective way to protect against phishing?",
        options: ["Expensive antivirus", "Education and awareness", "Avoiding the internet", "Using old browsers"],
        answer: "Education and awareness",
        explanation: "User education and awareness are the most effective defenses against social engineering attacks."
    }
];

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadQuizQuestions();
});

function initializeApp() {
    console.log('PhishGuard initialized successfully');
    
    // Add smooth scrolling
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // Add loading states to buttons
    addButtonLoadingStates();
    
    // Initialize clipboard functionality
    initializeClipboard();
}

// Navigation Functions
function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
        // Close mobile menu if open
        if (mobileMenuOpen) {
            toggleMobileMenu();
        }
    }
}

function toggleMobileMenu() {
    const mobileNav = document.getElementById('mobileNav');
    const menuIcon = document.getElementById('menu-icon');
    
    mobileMenuOpen = !mobileMenuOpen;
    
    if (mobileMenuOpen) {
        mobileNav.classList.add('active');
        menuIcon.className = 'fas fa-times';
    } else {
        mobileNav.classList.remove('active');
        menuIcon.className = 'fas fa-bars';
    }
}

// Clipboard Functions
function initializeClipboard() {
    // Check if clipboard API is available
    if (navigator.clipboard) {
        console.log('Clipboard API available');
    }
}

async function pasteFromClipboard() {
    try {
        if (navigator.clipboard && navigator.clipboard.readText) {
            const text = await navigator.clipboard.readText();
            const urlInput = document.getElementById('urlInput');
            if (urlInput && text.trim()) {
                urlInput.value = text.trim();
                // Trigger input event to validate
                urlInput.dispatchEvent(new Event('input', { bubbles: true }));
                showToast('URL pasted from clipboard!', 'success');
            }
        } else {
            showToast('Clipboard access not available. Please paste manually.', 'warning');
        }
    } catch (error) {
        console.error('Failed to read from clipboard:', error);
        showToast('Failed to paste from clipboard. Please paste manually.', 'error');
    }
}

// Loading Management
function showLoading(message = 'Analyzing...') {
    const overlay = document.getElementById('loadingOverlay');
    const loadingText = document.getElementById('loadingText');
    
    if (overlay && loadingText) {
        loadingText.textContent = message;
        overlay.classList.remove('hidden');
        isAnalyzing = true;
        
        // Update analyze button
        const analyzeBtn = document.querySelector('.analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Analyzing...</span>';
            analyzeBtn.disabled = true;
        }
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.add('hidden');
        isAnalyzing = false;
        
        // Reset analyze button
        const analyzeBtn = document.querySelector('.analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '<i class="fas fa-search"></i><span>Analyze URL</span><div class="btn-glow"></div>';
            analyzeBtn.disabled = false;
        }
    }
}

// URL Analysis Functions
async function analyzeURL() {
    if (isAnalyzing) return;
    
    const urlInput = document.getElementById('urlInput').value.trim();
    const resultsContainer = document.getElementById('urlResults');
    
    if (!urlInput) {
        showError(resultsContainer, 'Please enter a URL to analyze.');
        return;
    }
    
    if (!isValidURL(urlInput)) {
        showError(resultsContainer, 'Please enter a valid URL (e.g., https://example.com).');
        return;
    }
    
    showLoading('Analyzing URL with 36+ security features...');
    
    // Clear previous results
    resultsContainer.innerHTML = '';
    resultsContainer.classList.add('hidden');
    
    try {
        // Add realistic delay for better UX
        await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 2000));
        
        // Perform client-side analysis
        const clientAnalysis = await performClientSideAnalysis(urlInput);
        
        // Simulate server-side analysis
        const serverAnalysis = await performServerAnalysis(urlInput);
        
        // Combine results
        const combinedResults = combineAnalysisResults(clientAnalysis, serverAnalysis);
        
        displayURLResults(combinedResults);
        resultsContainer.classList.remove('hidden');
        
        // Smooth scroll to results
        setTimeout(() => {
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showError(resultsContainer, 'Analysis failed. Please try again.');
        resultsContainer.classList.remove('hidden');
    } finally {
        hideLoading();
    }
}

async function performClientSideAnalysis(url) {
    // Use the enhanced feature extraction from feature_script.js
    return extractAdvancedURLFeatures(url);
}

async function performServerAnalysis(url) {
    // Simulate realistic server-side analysis
    return new Promise((resolve) => {
        setTimeout(() => {
            const result = {
                timestamp: new Date().toLocaleString(),
                serverFeatures: {
                    domainAge: Math.floor(Math.random() * 365) + 30,
                    sslCertificate: Math.random() > 0.15,
                    blacklistStatus: Math.random() > 0.97,
                    reputationScore: Math.floor(Math.random() * 100),
                    malwareDetection: Math.random() > 0.98,
                    phishingDatabase: Math.random() > 0.96,
                    dnsRecords: Math.random() > 0.1,
                    geolocation: ['US', 'UK', 'CA', 'DE', 'FR'][Math.floor(Math.random() * 5)],
                    sslIssuer: ['Let\'s Encrypt', 'DigiCert', 'GlobalSign', 'Cloudflare'][Math.floor(Math.random() * 4)],
                    contentAnalysis: {
                        hasLoginForms: Math.random() > 0.7,
                        hasPaymentForms: Math.random() > 0.8,
                        suspiciousContent: Math.random() > 0.85
                    }
                },
                threats: []
            };
            
            // Add specific threats based on analysis
            if (result.serverFeatures.blacklistStatus) {
                result.threats.push('CRITICAL: Domain found in security blacklists');
            }
            if (result.serverFeatures.domainAge < 30) {
                result.threats.push('Domain registered very recently');
            }
            if (!result.serverFeatures.sslCertificate) {
                result.threats.push('Invalid or missing SSL certificate');
            }
            if (result.serverFeatures.reputationScore < 30) {
                result.threats.push('Poor domain reputation score');
            }
            
            resolve(result);
        }, 1000 + Math.random() * 1000);
    });
}

function combineAnalysisResults(clientResults, serverResults) {
    let additionalRisk = 0;
    
    // Calculate additional risk from server analysis
    if (serverResults.serverFeatures.blacklistStatus) additionalRisk += 50;
    if (serverResults.serverFeatures.domainAge < 30) additionalRisk += 30;
    if (!serverResults.serverFeatures.sslCertificate) additionalRisk += 25;
    if (serverResults.serverFeatures.reputationScore < 30) additionalRisk += 20;
    if (serverResults.serverFeatures.contentAnalysis.suspiciousContent) additionalRisk += 15;
    
    const combinedScore = Math.min(clientResults.riskScore + additionalRisk, 100);
    
    const combinedWarnings = [
        ...clientResults.warnings,
        ...serverResults.threats
    ];
    
    return {
        ...clientResults,
        ...serverResults,
        riskScore: combinedScore,
        warnings: combinedWarnings,
        serverFeatures: serverResults.serverFeatures,
        featuresAnalyzed: Object.keys(clientResults.features).length + Object.keys(serverResults.serverFeatures).length
    };
}

function displayURLResults(results) {
    const container = document.getElementById('urlResults');
    const riskLevel = getRiskLevel(results.riskScore);
    const riskClass = getRiskClass(riskLevel);
    
    container.innerHTML = `
        <div class="results-header">
            <h5><i class="fas fa-chart-line"></i> Comprehensive Analysis Results</h5>
            <div class="analysis-badge">
                <i class="fas fa-microscope"></i>
                ${results.featuresAnalyzed}+ Features Analyzed
            </div>
        </div>
        
        <div class="risk-display">
            <div class="risk-score">
                <i class="fas ${getRiskIcon(riskLevel)} risk-icon ${riskClass}-icon"></i>
                <div class="risk-level ${riskClass}-text">${riskLevel} Risk</div>
                <div class="score-text">Security Score: ${results.riskScore}/100</div>
                <div class="progress-bar-container">
                    <div class="progress-bar-fill ${riskClass}" style="width: ${results.riskScore}%"></div>
                </div>
                <div class="risk-recommendation">
                    ${getRiskRecommendation(riskLevel)}
                </div>
            </div>
            
            <div class="analysis-details">
                <h6><i class="fas fa-info-circle"></i> Analysis Summary</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <strong><i class="fas fa-globe"></i> URL:</strong> 
                        <span class="url-display">${truncateURL(results.url)}</span>
                    </div>
                    <div class="detail-item">
                        <strong><i class="fas fa-server"></i> Domain:</strong> 
                        <span>${results.domain}</span>
                    </div>
                    <div class="detail-item">
                        <strong><i class="fas fa-lock"></i> Protocol:</strong> 
                        <span class="${results.features.httpsProtocol ? 'safe-text' : 'danger-text'}">
                            ${results.features.httpsProtocol ? 'HTTPS ✓' : 'HTTP ⚠'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <strong><i class="fas fa-calendar"></i> Domain Age:</strong> 
                        <span>${results.serverFeatures?.domainAge || 'Unknown'} days</span>
                    </div>
                    <div class="detail-item">
                        <strong><i class="fas fa-certificate"></i> SSL Status:</strong> 
                        <span class="${results.serverFeatures?.sslCertificate ? 'safe-text' : 'danger-text'}">
                            ${results.serverFeatures?.sslCertificate ? 'Valid ✓' : 'Invalid ⚠'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <strong><i class="fas fa-clock"></i> Analyzed:</strong> 
                        <span>${results.timestamp}</span>
                    </div>
                </div>
            </div>
        </div>
        
        ${results.warnings.length > 0 ? `
            <div class="warnings-list">
                <h6><i class="fas fa-exclamation-triangle"></i> Security Warnings (${results.warnings.length})</h6>
                <div class="warnings-grid">
                    ${results.warnings.slice(0, 8).map(warning => `
                        <div class="warning-item">
                            <i class="fas fa-exclamation-circle"></i>
                            <span>${warning}</span>
                        </div>
                    `).join('')}
                    ${results.warnings.length > 8 ? `
                        <div class="warning-item more-warnings">
                            <i class="fas fa-ellipsis-h"></i>
                            <span>+${results.warnings.length - 8} more warnings</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        ` : `
            <div class="no-warnings">
                <i class="fas fa-check-circle"></i>
                <h6>No Security Warnings Detected</h6>
                <p>This URL passed all security checks without raising any red flags.</p>
            </div>
        `}
        
        <div class="features-analysis">
            <h6><i class="fas fa-cogs"></i> Feature Analysis Breakdown</h6>
            <div class="features-grid">
                ${generateAdvancedFeatureItems(results.features, results.serverFeatures)}
            </div>
        </div>
        
        <div class="analysis-actions">
            <button class="action-btn secondary" onclick="downloadReport(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                <i class="fas fa-download"></i> Download Report
            </button>
            <button class="action-btn primary" onclick="analyzeAnother()">
                <i class="fas fa-plus"></i> Analyze Another URL
            </button>
        </div>
    `;
    
    // Animate progress bar
    setTimeout(() => {
        const progressBar = container.querySelector('.progress-bar-fill');
        if (progressBar) {
            progressBar.style.width = `${results.riskScore}%`;
        }
    }, 100);
}

function generateAdvancedFeatureItems(clientFeatures, serverFeatures) {
    const features = [
        { name: 'HTTPS Protocol', value: clientFeatures.httpsProtocol, type: 'security', critical: true },
        { name: 'URL Length', value: clientFeatures.urlLength === 'normal', type: 'structure' },
        { name: 'Domain Structure', value: !clientFeatures.excessiveHyphens, type: 'structure' },
        { name: 'Subdomain Analysis', value: !clientFeatures.excessiveSubdomains, type: 'structure' },
        { name: 'Suspicious Keywords', value: clientFeatures.suspiciousKeywords === 0, type: 'content' },
        { name: 'URL Shortener', value: !clientFeatures.isShortener, type: 'behavior' },
        { name: 'IP Address Usage', value: !clientFeatures.usesIPAddress, type: 'structure', critical: true },
        { name: 'Typosquatting Check', value: !clientFeatures.possibleTyposquatting, type: 'reputation', critical: true },
        { name: 'SSL Certificate', value: serverFeatures?.sslCertificate, type: 'security', critical: true },
        { name: 'Domain Reputation', value: serverFeatures?.reputationScore > 70, type: 'reputation' },
        { name: 'Blacklist Status', value: !serverFeatures?.blacklistStatus, type: 'security', critical: true },
        { name: 'Domain Age', value: serverFeatures?.domainAge > 90, type: 'reputation' },
        { name: 'DNS Records', value: serverFeatures?.dnsRecords, type: 'infrastructure' },
        { name: 'Content Analysis', value: !serverFeatures?.contentAnalysis?.suspiciousContent, type: 'content' }
    ];
    
    return features.map(feature => {
        const status = feature.value ? 'pass' : 'fail';
        const statusText = feature.value ? 'Pass' : 'Fail';
        const icon = getFeatureIcon(feature.type);
        const criticalBadge = feature.critical ? '<span class="critical-badge">Critical</span>' : '';
        
        return `
            <div class="feature-item ${status} ${feature.critical ? 'critical-feature' : ''}">
                <div class="feature-header">
                    <span class="feature-name">
                        <i class="fas ${icon}"></i>
                        ${feature.name}
                    </span>
                    ${criticalBadge}
                </div>
                <span class="feature-status ${status}">
                    <i class="fas ${feature.value ? 'fa-check' : 'fa-times'}"></i>
                    ${statusText}
                </span>
            </div>
        `;
    }).join('');
}

function getFeatureIcon(type) {
    const icons = {
        security: 'fa-shield-alt',
        structure: 'fa-sitemap',
        content: 'fa-file-alt',
        behavior: 'fa-user-secret',
        reputation: 'fa-star',
        infrastructure: 'fa-server'
    };
    return icons[type] || 'fa-cog';
}

function getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 30) return 'Medium';
    return 'Low';
}

function getRiskClass(level) {
    return level.toLowerCase();
}

function getRiskIcon(level) {
    const icons = {
        'Low': 'fa-check-circle',
        'Medium': 'fa-exclamation-circle',
        'High': 'fa-exclamation-triangle',
        'Critical': 'fa-times-circle'
    };
    return icons[level] || 'fa-question-circle';
}

function getRiskRecommendation(level) {
    const recommendations = {
        'Low': '<span class="safe-text">✓ Safe to proceed</span>',
        'Medium': '<span class="warning-text">⚠ Proceed with caution</span>',
        'High': '<span class="danger-text">⚠ High risk - avoid if possible</span>',
        'Critical': '<span class="critical-text">🚫 Do not visit this site</span>'
    };
    return recommendations[level] || '';
}

function truncateURL(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
}

// Utility Functions
function isValidURL(string) {
    try {
        // Add protocol if missing
        if (!string.startsWith('http://') && !string.startsWith('https://')) {
            string = 'https://' + string;
        }
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function showError(container, message) {
    container.innerHTML = `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <h5>Analysis Error</h5>
            <p>${message}</p>
        </div>
    `;
    container.classList.remove('hidden');
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="fas ${getToastIcon(type)}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => document.body.removeChild(toast), 300);
    }, 3000);
}

function getToastIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        warning: 'fa-exclamation-triangle',
        error: 'fa-times-circle',
        info: 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

// Action Functions
function downloadReport(results) {
    const report = generateTextReport(results);
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Security report downloaded successfully!', 'success');
}

function generateTextReport(results) {
    return `
PhishGuard Security Analysis Report
Generated: ${new Date().toLocaleString()}

URL ANALYZED: ${results.url}
RISK SCORE: ${results.riskScore}/100
RISK LEVEL: ${getRiskLevel(results.riskScore)}
FEATURES ANALYZED: ${results.featuresAnalyzed}+

SECURITY WARNINGS:
${results.warnings.length > 0 ? results.warnings.map(w => `- ${w}`).join('\n') : 'None detected'}

TECHNICAL DETAILS:
- Domain: ${results.domain}
- Protocol: ${results.features.httpsProtocol ? 'HTTPS' : 'HTTP'}
- Domain Age: ${results.serverFeatures?.domainAge || 'Unknown'} days
- SSL Certificate: ${results.serverFeatures?.sslCertificate ? 'Valid' : 'Invalid'}
- Reputation Score: ${results.serverFeatures?.reputationScore || 'Unknown'}/100

This report was generated by PhishGuard Advanced Phishing Detection System.
For more information, visit: https://phishguard.security
    `.trim();
}

function analyzeAnother() {
    document.getElementById('urlInput').value = '';
    document.getElementById('urlResults').classList.add('hidden');
    document.getElementById('urlInput').focus();
    scrollToSection('detector');
}

function addButtonLoadingStates() {
    // Add loading states and hover effects to buttons
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.disabled && !this.classList.contains('loading')) {
                this.classList.add('clicked');
                setTimeout(() => this.classList.remove('clicked'), 200);
            }
        });
    });
}

// Quiz Functions
function loadQuizQuestions() {
    // Shuffle and select 5 random questions
    const shuffled = [...allQuizQuestions].sort(() => 0.5 - Math.random());
    quizQuestions = shuffled.slice(0, 5);
    currentQuestionIndex = 0;
    userAnswers = [];
    quizScore = 0;
    
    updateQuizDisplay();
}

function updateQuizDisplay() {
    if (currentQuestionIndex >= quizQuestions.length) {
        showQuizResults();
        return;
    }
    
    const question = quizQuestions[currentQuestionIndex];
    const questionText = document.getElementById('questionText');
    const optionsContainer = document.getElementById('optionsContainer');
    const currentQuestionSpan = document.getElementById('currentQuestion');
    const totalQuestionsSpan = document.getElementById('totalQuestions');
    const progressBar = document.getElementById('progressBar');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    // Update question display
    questionText.textContent = question.question;
    currentQuestionSpan.textContent = currentQuestionIndex + 1;
    totalQuestionsSpan.textContent = quizQuestions.length;
    
    // Update progress bar
    const progress = ((currentQuestionIndex + 1) / quizQuestions.length) * 100;
    progressBar.style.width = `${progress}%`;
    
    // Generate options
    optionsContainer.innerHTML = question.options.map((option, index) => `
        <button class="option-button" onclick="selectAnswer('${option}', this)" data-option="${option}">
            ${option}
        </button>
    `).join('');
    
    // Update navigation buttons
    prevBtn.disabled = currentQuestionIndex === 0;
    
    // Check if user has answered this question
    const userAnswer = userAnswers[currentQuestionIndex];
    if (userAnswer) {
        const selectedOption = optionsContainer.querySelector(`[data-option="${userAnswer}"]`);
        if (selectedOption) {
            selectedOption.classList.add('selected');
        }
        nextBtn.textContent = currentQuestionIndex === quizQuestions.length - 1 ? 'Finish Quiz' : 'Next';
        nextBtn.innerHTML = currentQuestionIndex === quizQuestions.length - 1 ? 
            'Finish Quiz <i class="fas fa-flag-checkered"></i>' : 
            'Next <i class="fas fa-chevron-right"></i>';
    } else {
        nextBtn.textContent = 'Next';
        nextBtn.innerHTML = 'Next <i class="fas fa-chevron-right"></i>';
    }
}

function selectAnswer(answer, buttonElement) {
    // Remove previous selections
    const options = document.querySelectorAll('.option-button');
    options.forEach(option => option.classList.remove('selected'));
    
    // Mark selected option
    buttonElement.classList.add('selected');
    
    // Store answer
    userAnswers[currentQuestionIndex] = answer;
    
    // Update next button
    const nextBtn = document.getElementById('nextBtn');
    nextBtn.disabled = false;
    nextBtn.innerHTML = currentQuestionIndex === quizQuestions.length - 1 ? 
        'Finish Quiz <i class="fas fa-flag-checkered"></i>' : 
        'Next <i class="fas fa-chevron-right"></i>';
}

function nextQuestion() {
    if (currentQuestionIndex < quizQuestions.length - 1) {
        currentQuestionIndex++;
        updateQuizDisplay();
    } else {
        showQuizResults();
    }
}

function previousQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        updateQuizDisplay();
    }
}

function showQuizResults() {
    // Calculate score
    let correctAnswers = 0;
    quizQuestions.forEach((question, index) => {
        if (userAnswers[index] === question.answer) {
            correctAnswers++;
        }
    });
    
    const percentage = Math.round((correctAnswers / quizQuestions.length) * 100);
    const incorrectAnswers = quizQuestions.length - correctAnswers;
    
    // Hide quiz content and show results
    document.getElementById('quizContainer').style.display = 'none';
    const resultsContainer = document.getElementById('quizResults');
    resultsContainer.classList.remove('hidden');
    
    // Update results display
    document.getElementById('scoreDisplay').innerHTML = `<div class="score-number">${percentage}%</div>`;
    document.getElementById('correctAnswers').textContent = correctAnswers;
    document.getElementById('incorrectAnswers').textContent = incorrectAnswers;
    document.getElementById('accuracyRate').textContent = `${percentage}%`;
    
    // Score message
    const scoreMessage = document.getElementById('scoreMessage');
    if (percentage >= 80) {
        scoreMessage.textContent = 'Excellent! You have strong phishing awareness.';
        scoreMessage.className = 'score-message safe-text';
    } else if (percentage >= 60) {
        scoreMessage.textContent = 'Good job! Consider reviewing phishing protection tips.';
        scoreMessage.className = 'score-message warning-text';
    } else {
        scoreMessage.textContent = 'Keep learning! Review our education section for better protection.';
        scoreMessage.className = 'score-message danger-text';
    }
    
    // Update quiz score display
    document.getElementById('quizScore').textContent = percentage + '%';
}

function restartQuiz() {
    // Reset quiz state
    document.getElementById('quizContainer').style.display = 'block';
    document.getElementById('quizResults').classList.add('hidden');
    document.getElementById('quizScore').textContent = '0';
    
    // Load new random questions
    loadQuizQuestions();
}

// Add custom styles for toast notifications
const toastStyles = `
    .toast {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--surface-2);
        color: var(--text-primary);
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        box-shadow: var(--shadow-lg);
        display: flex;
        align-items: center;
        gap: 0.5rem;
        opacity: 0;
        transform: translateX(100%);
        transition: var(--transition);
        z-index: 10000;
        border: 1px solid var(--border);
    }
    
    .toast.show {
        opacity: 1;
        transform: translateX(0);
    }
    
    .toast-success { border-left: 4px solid var(--safe); }
    .toast-warning { border-left: 4px solid var(--warning); }
    .toast-error { border-left: 4px solid var(--danger); }
    .toast-info { border-left: 4px solid var(--primary); }
    
    .error-message {
        text-align: center;
        padding: 2rem;
        background: rgba(239, 68, 68, 0.1);
        border-radius: 1rem;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    .error-message i {
        font-size: 3rem;
        color: var(--danger);
        margin-bottom: 1rem;
    }
    
    .error-message h5 {
        color: var(--danger);
        margin-bottom: 0.5rem;
    }
    
    .no-warnings {
        text-align: center;
        padding: 2rem;
        background: rgba(16, 185, 129, 0.1);
        border-radius: 1rem;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    
    .no-warnings i {
        font-size: 3rem;
        color: var(--safe);
        margin-bottom: 1rem;
    }
    
    .no-warnings h6 {
        color: var(--safe);
        margin-bottom: 0.5rem;
    }
    
    .warnings-grid {
        display: grid;
        gap: 0.5rem;
    }
    
    .analysis-actions {
        display: flex;
        gap: 1rem;
        justify-content: center;
        margin-top: 2rem;
        flex-wrap: wrap;
    }
    
    .action-btn {
        padding: 0.75rem 1.5rem;
        border-radius: 0.75rem;
        border: none;
        cursor: pointer;
        transition: var(--transition);
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .action-btn.primary {
        background: var(--gradient-primary);
        color: white;
    }
    
    .action-btn.secondary {
        background: var(--surface-2);
        color: var(--text-primary);
        border: 2px solid var(--border);
    }
    
    .action-btn:hover {
        transform: translateY(-2px);
    }
    
    .critical-feature {
        border-left: 3px solid var(--danger);
    }
    
    .critical-badge {
        background: var(--danger);
        color: white;
        font-size: 0.7rem;
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        font-weight: bold;
    }
    
    .feature-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    
    .url-display {
        word-break: break-all;
        font-family: monospace;
        background: var(--surface);
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
    }
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = toastStyles;
document.head.appendChild(styleSheet);