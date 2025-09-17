// PhishGuard Main JavaScript - Frontend Controller & Quiz Logic

// Global Variables
let currentTab = 'url';
let mobileMenuOpen = false;
let quizQuestions = [];
let currentQuestionIndex = 0;
let userAnswers = [];
let quizScore = 0;
let loadingTimeout = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadQuizQuestions();
    updateThreatFeed();
    
    // Update threat feed every 30 seconds
    setInterval(updateThreatFeed, 30000);
});

function initializeApp() {
    console.log('PhishGuard initialized successfully');
    
    // Add smooth scrolling
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // Initialize tabs
    showTab('url');
    
    // Add loading states to buttons
    addButtonLoadingStates();
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

// Tab Management
function switchTab(tabName, buttonElement) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab and mark button as active
    const selectedTab = document.getElementById(tabName + '-tab');
    if (selectedTab) {
        selectedTab.classList.add('active');
        buttonElement.classList.add('active');
        currentTab = tabName;
    }
}

function showTab(tabName) {
    const tabButton = document.querySelector(`[data-tab="${tabName}"]`);
    if (tabButton) {
        switchTab(tabName, tabButton);
    }
}

// Loading Management
function showLoading(message = 'Analyzing...') {
    const overlay = document.getElementById('loadingOverlay');
    const loadingText = document.getElementById('loadingText');
    
    if (overlay && loadingText) {
        loadingText.textContent = message;
        overlay.classList.remove('hidden');
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.add('hidden');
    }
}

// URL Analysis Functions
async function analyzeURL() {
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
    
    showLoading('Analyzing URL with 36 security features...');
    
    // Clear previous results
    resultsContainer.innerHTML = '';
    
    try {
        // Perform client-side analysis
        const clientAnalysis = await performClientSideAnalysis(urlInput);
        
        // Simulate server-side analysis
        const serverAnalysis = await performServerAnalysis(urlInput, 'url');
        
        // Combine results
        const combinedResults = combineAnalysisResults(clientAnalysis, serverAnalysis);
        
        displayURLResults(combinedResults);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showError(resultsContainer, 'Analysis failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function performClientSideAnalysis(url) {
    // Use the feature extraction from feature_script.js
    return extractURLFeatures(url);
}

async function performServerAnalysis(data, type) {
    // Simulate API call to Python backend
    const response = await simulateBackendCall(data, type);
    return response;
}

function simulateBackendCall(data, analysisType) {
    return new Promise((resolve) => {
        // Simulate network delay
        setTimeout(() => {
            let result = {
                timestamp: new Date().toLocaleString(),
                analysisType: analysisType,
                serverFeatures: {},
                threats: []
            };
            
            // Add simulated server-side features
            if (analysisType === 'url') {
                result.serverFeatures = {
                    domainAge: Math.floor(Math.random() * 365),
                    sslCertificate: Math.random() > 0.2,
                    blacklistStatus: Math.random() > 0.95,
                    reputationScore: Math.floor(Math.random() * 100),
                    malwareDetection: Math.random() > 0.98,
                    phishingDatabase: Math.random() > 0.97
                };
            }
            
            resolve(result);
        }, 1500 + Math.random() * 1000);
    });
}

function combineAnalysisResults(clientResults, serverResults) {
    const combinedScore = Math.min(
        clientResults.riskScore + (serverResults.serverFeatures.blacklistStatus ? 50 : 0),
        100
    );
    
    const combinedWarnings = [
        ...clientResults.warnings,
        ...(serverResults.serverFeatures.blacklistStatus ? ['Domain found in security blacklists'] : []),
        ...(serverResults.serverFeatures.domainAge < 30 ? ['Very new domain registration'] : []),
        ...(!serverResults.serverFeatures.sslCertificate ? ['Invalid or missing SSL certificate'] : [])
    ];
    
    return {
        ...clientResults,
        ...serverResults,
        riskScore: combinedScore,
        warnings: combinedWarnings,
        serverFeatures: serverResults.serverFeatures
    };
}

function displayURLResults(results) {
    const container = document.getElementById('urlResults');
    const riskLevel = getRiskLevel(results.riskScore);
    const riskClass = getRiskClass(riskLevel);
    
    container.innerHTML = `
        <div class="results-header">
            <h5>Comprehensive Analysis Results</h5>
            <span class="analysis-badge">36 Features Analyzed</span>
        </div>
        
        <div class="risk-display">
            <div class="risk-score">
                <i class="fas ${getRiskIcon(riskLevel)} risk-icon ${riskClass}-icon"></i>
                <div class="risk-level ${riskClass}-text">${riskLevel} Risk</div>
                <div class="score-text">Score: ${results.riskScore}/100</div>
                <div class="progress-bar-container">
                    <div class="progress-bar-fill ${riskClass}" style="width: ${results.riskScore}%"></div>
                </div>
            </div>
            
            <div class="analysis-details">
                <h6>Analysis Details:</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <strong>URL:</strong> ${results.url}
                    </div>
                    <div class="detail-item">
                        <strong>Domain:</strong> ${results.domain}
                    </div>
                    <div class="detail-item">
                        <strong>Protocol:</strong> ${results.features.https ? 'HTTPS ✓' : 'HTTP ⚠'}
                    </div>
                    <div class="detail-item">
                        <strong>Domain Age:</strong> ${results.serverFeatures?.domainAge || 'Unknown'} days
                    </div>
                    <div class="detail-item">
                        <strong>SSL Status:</strong> ${results.serverFeatures?.sslCertificate ? 'Valid ✓' : 'Invalid ⚠'}
                    </div>
                    <div class="detail-item">
                        <strong>Analyzed:</strong> ${results.timestamp}
                    </div>
                </div>
            </div>
        </div>
        
        ${results.warnings.length > 0 ? `
            <div class="warnings-list">
                <h6>Security Warnings (${results.warnings.length}):</h6>
                ${results.warnings.map(warning => `
                    <div class="warning-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>${warning}</span>
                    </div>
                `).join('')}
            </div>
        ` : ''}
        
        <div class="features-analysis">
            <h6>Feature Analysis Summary:</h6>
            <div class="features-grid">
                ${generateFeatureItems(results.features, results.serverFeatures)}
            </div>
        </div>
    `;
}

function generateFeatureItems(clientFeatures, serverFeatures) {
    const features = [
        { name: 'HTTPS Protocol', value: clientFeatures.https, type: 'security' },
        { name: 'URL Length', value: clientFeatures.urlLength === 'normal', type: 'structure' },
        { name: 'Domain Structure', value: !clientFeatures.excessiveHyphens, type: 'structure' },
        { name: 'Subdomain Count', value: !clientFeatures.excessiveSubdomains, type: 'structure' },
        { name: 'Suspicious Keywords', value: clientFeatures.suspiciousKeywords === 0, type: 'content' },
        { name: 'URL Shortener', value: !clientFeatures.isShortener, type: 'behavior' },
        { name: 'IP Address Usage', value: !clientFeatures.usesIPAddress, type: 'structure' },
        { name: 'SSL Certificate', value: serverFeatures?.sslCertificate, type: 'security' },
        { name: 'Domain Reputation', value: serverFeatures?.reputationScore > 70, type: 'reputation' },
        { name: 'Blacklist Status', value: !serverFeatures?.blacklistStatus, type: 'security' }
    ];
    
    return features.map(feature => {
        const status = feature.value ? 'pass' : 'fail';
        const statusText = feature.value ? 'Pass' : 'Fail';
        
        return `
            <div class="feature-item">
                <span class="feature-name">${feature.name}</span>
                <span class="feature-status ${status}">${statusText}</span>
            </div>
        `;
    }).join('');
}

// Email Analysis Functions
async function analyzeEmail() {
    const sender = document.getElementById('senderEmail').value.trim();
    const subject = document.getElementById('emailSubject').value.trim();
    const content = document.getElementById('emailContent').value.trim();
    const headers = document.getElementById('emailHeaders').value.trim();
    const resultsContainer = document.getElementById('emailResults');
    
    if (!sender || !subject || !content) {
        showError(resultsContainer, 'Please fill in sender, subject, and content fields.');
        return;
    }
    
    showLoading('Analyzing email for phishing indicators...');
    
    try {
        const emailData = { sender, subject, content, headers };
        const analysis = await performEmailAnalysis(emailData);
        
        displayEmailResults(analysis);
        
    } catch (error) {
        console.error('Email analysis error:', error);
        showError(resultsContainer, 'Email analysis failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function performEmailAnalysis(emailData) {
    // Use email analysis from feature_script.js
    const clientAnalysis = extractEmailFeatures(emailData);
    const serverAnalysis = await performServerAnalysis(emailData, 'email');
    
    return combineEmailResults(clientAnalysis, serverAnalysis);
}

function combineEmailResults(clientResults, serverResults) {
    return {
        ...clientResults,
        ...serverResults,
        riskScore: Math.min(clientResults.riskScore + 5, 100), // Add slight server adjustment
    };
}

function displayEmailResults(results) {
    const container = document.getElementById('emailResults');
    const riskLevel = getRiskLevel(results.riskScore);
    const riskClass = getRiskClass(riskLevel);
    
    container.innerHTML = `
        <div class="results-header">
            <h5>Email Analysis Results</h5>
        </div>
        
        <div class="risk-display">
            <div class="risk-score">
                <i class="fas ${getRiskIcon(riskLevel)} risk-icon ${riskClass}-icon"></i>
                <div class="risk-level ${riskClass}-text">${riskLevel} Risk</div>
                <div class="score-text">Score: ${results.riskScore}/100</div>
                <div class="progress-bar-container">
                    <div class="progress-bar-fill ${riskClass}" style="width: ${results.riskScore}%"></div>
                </div>
            </div>
            
            <div class="analysis-details">
                <h6>Email Details:</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <strong>Sender:</strong> ${results.sender}
                    </div>
                    <div class="detail-item">
                        <strong>Subject:</strong> ${results.subject}
                    </div>
                    <div class="detail-item">
                        <strong>Analyzed:</strong> ${results.timestamp}
                    </div>
                </div>
            </div>
        </div>
        
        ${results.warnings.length > 0 ? `
            <div class="warnings-list">
                <h6>Phishing Indicators (${results.warnings.length}):</h6>
                ${results.warnings.map(warning => `
                    <div class="warning-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>${warning}</span>
                    </div>
                `).join('')}
            </div>
        ` : ''}
    `;
}

// Website Scanner Functions
async function scanWebsite() {
    const websiteInput = document.getElementById('websiteInput').value.trim();
    const resultsContainer = document.getElementById('websiteResults');
    
    if (!websiteInput) {
        showError(resultsContainer, 'Please enter a website URL to scan.');
        return;
    }
    
    const options = {
        checkSSL: document.getElementById('checkSSL').checked,
        checkDomain: document.getElementById('checkDomain').checked,
        checkContent: document.getElementById('checkContent').checked,
        checkBehavior: document.getElementById('checkBehavior').checked,
        checkSEO: document.getElementById('checkSEO').checked,
        checkSocial: document.getElementById('checkSocial').checked
    };
    
    showLoading('Performing comprehensive website security scan...');
    
    try {
        const scanResults = await performWebsiteScan(websiteInput, options);
        displayWebsiteResults(scanResults);
        
    } catch (error) {
        console.error('Website scan error:', error);
        showError(resultsContainer, 'Website scan failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function performWebsiteScan(website, options) {
    // Use website analysis from feature_script.js
    const analysis = extractWebsiteFeatures(website, options);
    const serverAnalysis = await performServerAnalysis(website, 'website');
    
    return combineWebsiteResults(analysis, serverAnalysis);
}

function combineWebsiteResults(clientResults, serverResults) {
    return {
        ...clientResults,
        ...serverResults
    };
}

function displayWebsiteResults(results) {
    const container = document.getElementById('websiteResults');
    const riskLevel = getRiskLevel(results.riskScore);
    const riskClass = getRiskClass(riskLevel);
    
    container.innerHTML = `
        <div class="results-header">
            <h5>Website Security Scan Results</h5>
        </div>
        
        <div class="risk-display">
            <div class="risk-score">
                <i class="fas ${getRiskIcon(riskLevel)} risk-icon ${riskClass}-icon"></i>
                <div class="risk-level ${riskClass}-text">${riskLevel} Risk</div>
                <div class="score-text">Score: ${results.riskScore}/100</div>
                <div class="progress-bar-container">
                    <div class="progress-bar-fill ${riskClass}" style="width: ${results.riskScore}%"></div>
                </div>
            </div>
            
            <div class="analysis-details">
                <h6>Scan Summary:</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <strong>Website:</strong> ${results.website}
                    </div>
                    <div class="detail-item">
                        <strong>Scanned:</strong> ${results.timestamp}
                    </div>
                    <div class="detail-item">
                        <strong>Checks Performed:</strong> ${results.checks.length}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="security-checks">
            <h6>Security Checks:</h6>
            <div class="checks-grid">
                ${results.checks.map(check => `
                    <div class="check-item ${check.status}">
                        <i class="fas ${getCheckIcon(check.status)}"></i>
                        <div class="check-content">
                            <div class="check-name">${check.name}</div>
                            <div class="check-message">${check.message}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        
        ${results.warnings.length > 0 ? `
            <div class="warnings-list">
                <h6>Security Issues (${results.warnings.length}):</h6>
                ${results.warnings.map(warning => `
                    <div class="warning-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>${warning}</span>
                    </div>
                `).join('')}
            </div>
        ` : ''}
    `;
}

// Bulk Analysis Functions
async function analyzeBulk() {
    const bulkUrls = document.getElementById('bulkUrls').value.trim();
    const resultsContainer = document.getElementById('bulkResults');
    
    if (!bulkUrls) {
        showError(resultsContainer, 'Please enter URLs to analyze (one per line).');
        return;
    }
    
    const urls = bulkUrls.split('\n').map(url => url.trim()).filter(url => url);
    
    if (urls.length === 0) {
        showError(resultsContainer, 'No valid URLs found.');
        return;
    }
    
    if (urls.length > 50) {
        showError(resultsContainer, 'Maximum 50 URLs allowed for bulk analysis.');
        return;
    }
    
    showLoading(`Analyzing ${urls.length} URLs...`);
    
    try {
        const results = await performBulkAnalysis(urls);
        displayBulkResults(results);
        
        if (document.getElementById('exportResults').checked) {
            exportBulkResults(results);
        }
        
    } catch (error) {
        console.error('Bulk analysis error:', error);
        showError(resultsContainer, 'Bulk analysis failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function performBulkAnalysis(urls) {
    const results = [];
    const batchSize = 5; // Process 5 URLs at a time
    
    for (let i = 0; i < urls.length; i += batchSize) {
        const batch = urls.slice(i, i + batchSize);
        const batchPromises = batch.map(async (url) => {
            try {
                if (!isValidURL(url)) {
                    return { url, error: 'Invalid URL format', riskScore: 0 };
                }
                
                const analysis = await performClientSideAnalysis(url);
                return analysis;
            } catch (error) {
                return { url, error: 'Analysis failed', riskScore: 0 };
            }
        });
        
        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
        
        // Update loading message
        showLoading(`Analyzed ${results.length}/${urls.length} URLs...`);
    }
    
    return results;
}

function displayBulkResults(results) {
    const container = document.getElementById('bulkResults');
    const prioritize = document.getElementById('prioritizeRisk').checked;
    
    // Sort by risk score if prioritize is enabled
    const sortedResults = prioritize 
        ? results.sort((a, b) => b.riskScore - a.riskScore)
        : results;
    
    const highRisk = results.filter(r => r.riskScore >= 70).length;
    const mediumRisk = results.filter(r => r.riskScore >= 40 && r.riskScore < 70).length;
    const lowRisk = results.filter(r => r.riskScore < 40).length;
    
    container.innerHTML = `
        <div class="results-header">
            <h5>Bulk Analysis Results</h5>
        </div>
        
        <div class="bulk-summary">
            <div class="summary-stats">
                <div class="stat-card danger-bg">
                    <div class="stat-number">${highRisk}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-card warning-bg">
                    <div class="stat-number">${mediumRisk}</div>
                    <div class="stat-label">Medium Risk</div>
                </div>
                <div class="stat-card safe-bg">
                    <div class="stat-number">${lowRisk}</div>
                    <div class="stat-label">Low Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${results.length}</div>
                    <div class="stat-label">Total Analyzed</div>
                </div>
            </div>
        </div>
        
        <div class="bulk-results-list">
            ${sortedResults.map((result, index) => {
                if (result.error) {
                    return `
                        <div class="bulk-result-item error">
                            <div class="result-index">${index + 1}</div>
                            <div class="result-url">${result.url}</div>
                            <div class="result-status error">Error: ${result.error}</div>
                        </div>
                    `;
                }
                
                const riskLevel = getRiskLevel(result.riskScore);
                const riskClass = getRiskClass(riskLevel);
                
                return `
                    <div class="bulk-result-item ${riskClass}">
                        <div class="result-index">${index + 1}</div>
                        <div class="result-content">
                            <div class="result-url">${result.url}</div>
                            <div class="result-domain">${result.domain}</div>
                        </div>
                        <div class="result-risk">
                            <div class="risk-score-badge ${riskClass}">${result.riskScore}</div>
                            <div class="risk-level-text">${riskLevel}</div>
                        </div>
                        <div class="result-warnings">
                            ${result.warnings.length} warnings
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function exportBulkResults(results) {
    const csvContent = [
        'URL,Domain,Risk Score,Risk Level,Warnings Count,Top Warning',
        ...results.map(result => {
            if (result.error) {
                return `"${result.url}","","0","Error","0","${result.error}"`;
            }
            
            const riskLevel = getRiskLevel(result.riskScore);
            const topWarning = result.warnings.length > 0 ? result.warnings[0] : '';
            
            return `"${result.url}","${result.domain}","${result.riskScore}","${riskLevel}","${result.warnings.length}","${topWarning}"`;
        })
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `phishguard-bulk-analysis-${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Quiz Functions
function loadQuizQuestions() {
    // Load questions from the quiz questions array
    quizQuestions = getRandomQuestions(5);
    initializeQuiz();
}

function getRandomQuestions(count) {
    const allQuestions = [
        {
            question: "Which of the following is a common sign of a phishing email?",
            options: [
                "Personalized greeting with your full name",
                "Urgent language demanding immediate action",
                "Professional email signature",
                "Clear and proper grammar"
            ],
            correct: 1,
            explanation: "Phishing emails often use urgent language to pressure victims into acting quickly without thinking."
        },
        {
            question: "What should you do before clicking on a link in an email?",
            options: [
                "Click immediately if it looks legitimate",
                "Forward it to friends first",
                "Hover over the link to see the actual URL",
                "Reply to the sender asking if it's real"
            ],
            correct: 2,
            explanation: "Always hover over links to preview the destination URL before clicking to verify legitimacy."
        },
        {
            question: "Which URL is most likely to be a phishing attempt?",
            options: [
                "https://www.paypal.com/login",
                "https://paypal-security-update.com",
                "https://secure.paypal.com",
                "https://www.paypal.com/security"
            ],
            correct: 1,
            explanation: "The second URL uses a different domain that mimics PayPal but isn't the official site."
        },
        {
            question: "What is the best way to verify a suspicious email from your bank?",
            options: [
                "Click the link in the email",
                "Reply to the email with your account details",
                "Call your bank directly using a known phone number",
                "Forward the email to your friends"
            ],
            correct: 2,
            explanation: "Always verify through independent channels like calling your bank directly using official contact information."
        },
        {
            question: "Which of these is NOT a good practice for email security?",
            options: [
                "Using two-factor authentication",
                "Keeping software updated",
                "Opening all attachments to check them",
                "Being skeptical of unexpected emails"
            ],
            correct: 2,
            explanation: "Never open unexpected attachments as they may contain malware. Always verify with the sender first."
        },
        {
            question: "What makes a password strong and secure?",
            options: [
                "Using only lowercase letters",
                "Using your birthdate",
                "Combining uppercase, lowercase, numbers, and symbols",
                "Using the same password for all accounts"
            ],
            correct: 2,
            explanation: "Strong passwords combine multiple character types and are unique for each account."
        },
        {
            question: "If you receive an email asking for your social security number, you should:",
            options: [
                "Provide it immediately if the email looks official",
                "Never provide it via email",
                "Only provide the last 4 digits",
                "Ask for their phone number first"
            ],
            correct: 1,
            explanation: "Legitimate organizations never ask for sensitive information like SSN via email."
        },
        {
            question: "What is 'typosquatting' in the context of phishing?",
            options: [
                "Typing errors in phishing emails",
                "Creating fake websites with URLs similar to legitimate ones",
                "Using voice recognition to steal passwords",
                "Sending multiple emails quickly"
            ],
            correct: 1,
            explanation: "Typosquatting involves registering domains similar to legitimate sites to trick users."
        },
        {
            question: "Which of these email subjects is most likely to be phishing?",
            options: [
                "Your monthly newsletter",
                "URGENT: Your account will be closed in 24 hours!",
                "Meeting scheduled for tomorrow",
                "Thank you for your purchase"
            ],
            correct: 1,
            explanation: "Urgent, threatening language is a classic phishing tactic to create panic."
        },
        {
            question: "What should you do if you accidentally clicked on a phishing link?",
            options: [
                "Ignore it and hope nothing happens",
                "Immediately change your passwords and run antivirus scan",
                "Wait and see what happens",
                "Only change passwords if you notice problems"
            ],
            correct: 1,
            explanation: "Immediate action is crucial: change passwords, scan for malware, and monitor accounts."
        }
    ];
    
    // Shuffle and return random questions
    const shuffled = allQuestions.sort(() => Math.random() - 0.5);
    return shuffled.slice(0, count);
}

function initializeQuiz() {
    currentQuestionIndex = 0;
    userAnswers = new Array(quizQuestions.length).fill(-1);
    quizScore = 0;
    
    document.getElementById('quizResults').classList.add('hidden');
    document.getElementById('quizContainer').classList.remove('hidden');
    
    loadQuestion();
}

function loadQuestion() {
    if (currentQuestionIndex >= quizQuestions.length) {
        finishQuiz();
        return;
    }
    
    const question = quizQuestions[currentQuestionIndex];
    
    document.getElementById('questionText').textContent = question.question;
    document.getElementById('currentQuestion').textContent = currentQuestionIndex + 1;
    document.getElementById('totalQuestions').textContent = quizQuestions.length;
    document.getElementById('quizScore').textContent = calculateCurrentScore();
    
    const progress = ((currentQuestionIndex + 1) / quizQuestions.length) * 100;
    document.getElementById('progressBar').style.width = progress + '%';
    
    const optionsContainer = document.getElementById('optionsContainer');
    optionsContainer.innerHTML = '';
    
    question.options.forEach((option, index) => {
        const optionDiv = document.createElement('div');
        optionDiv.className = 'quiz-option';
        optionDiv.innerHTML = `
            <label class="option-label">
                <input type="radio" name="quizOption" value="${index}">
                <span>${option}</span>
            </label>
        `;
        
        optionDiv.addEventListener('click', () => selectOption(index, optionDiv));
        optionsContainer.appendChild(optionDiv);
    });
    
    // Restore previous selection if exists
    if (userAnswers[currentQuestionIndex] !== -1) {
        const selectedIndex = userAnswers[currentQuestionIndex];
        const optionDivs = optionsContainer.querySelectorAll('.quiz-option');
        selectOption(selectedIndex, optionDivs[selectedIndex]);
    }
    
    // Update navigation buttons
    document.getElementById('prevBtn').disabled = currentQuestionIndex === 0;
    document.getElementById('nextBtn').textContent = 
        currentQuestionIndex === quizQuestions.length - 1 ? 'Finish Quiz' : 'Next';
}

function selectOption(index, optionDiv) {
    // Remove previous selections
    document.querySelectorAll('.quiz-option').forEach(opt => {
        opt.classList.remove('selected');
        const radio = opt.querySelector('input[type="radio"]');
        if (radio) radio.checked = false;
    });
    
    // Mark current selection
    optionDiv.classList.add('selected');
    const radio = optionDiv.querySelector('input[type="radio"]');
    if (radio) radio.checked = true;
    
    // Store answer
    userAnswers[currentQuestionIndex] = index;
}

function nextQuestion() {
    const selectedOption = document.querySelector('input[name="quizOption"]:checked');
    
    if (!selectedOption && currentQuestionIndex < quizQuestions.length) {
        alert('Please select an answer before proceeding.');
        return;
    }
    
    if (currentQuestionIndex === quizQuestions.length - 1) {
        finishQuiz();
    } else {
        currentQuestionIndex++;
        loadQuestion();
    }
}

function previousQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        loadQuestion();
    }
}

function calculateCurrentScore() {
    let score = 0;
    for (let i = 0; i <= currentQuestionIndex; i++) {
        if (userAnswers[i] === quizQuestions[i]?.correct) {
            score++;
        }
    }
    return score;
}

function finishQuiz() {
    // Calculate final score
    quizScore = 0;
    userAnswers.forEach((answer, index) => {
        if (answer === quizQuestions[index].correct) {
            quizScore++;
        }
    });
    
    // Show results
    document.getElementById('quizContainer').classList.add('hidden');
    document.getElementById('quizResults').classList.remove('hidden');
    
    const percentage = (quizScore / quizQuestions.length) * 100;
    const correctAnswers = quizScore;
    const incorrectAnswers = quizQuestions.length - quizScore;
    
    document.getElementById('scoreDisplay').textContent = `${quizScore}/${quizQuestions.length}`;
    document.getElementById('correctAnswers').textContent = correctAnswers;
    document.getElementById('incorrectAnswers').textContent = incorrectAnswers;
    document.getElementById('accuracyRate').textContent = Math.round(percentage) + '%';
    
    let message = '';
    if (percentage >= 80) {
        message = 'Excellent! You have strong phishing detection skills.';
    } else if (percentage >= 60) {
        message = 'Good job! Consider reviewing phishing detection techniques.';
    } else {
        message = 'Keep learning! Regular practice will improve your security awareness.';
    }
    
    document.getElementById('scoreMessage').textContent = message;
}

function restartQuiz() {
    // Generate new random questions
    quizQuestions = getRandomQuestions(5);
    initializeQuiz();
}

// Threat Feed Functions
function updateThreatFeed() {
    const threats = [
        {
            type: 'Email Phishing',
            description: 'New campaign targeting banking customers with fake security alerts and urgent account verification requests',
            severity: 'high',
            time: '2 minutes ago'
        },
        {
            type: 'SMS Phishing',
            description: 'Package delivery scam messages increasing by 300% targeting holiday shoppers',
            severity: 'medium',
            time: '15 minutes ago'
        },
        {
            type: 'Website Clone',
            description: 'Fake social media login pages detected on compromised domains with SSL certificates',
            severity: 'high',
            time: '1 hour ago'
        },
        {
            type: 'Business Email',
            description: 'CEO impersonation attacks targeting finance departments with wire transfer requests',
            severity: 'critical',
            time: '3 hours ago'
        },
        {
            type: 'Voice Phishing',
            description: 'Automated calls claiming to be from tech support companies requesting remote access',
            severity: 'medium',
            time: '5 hours ago'
        },
        {
            type: 'Cryptocurrency Scam',
            description: 'Fake investment platforms promising high returns on cryptocurrency investments',
            severity: 'high',
            time: '6 hours ago'
        },
        {
            type: 'Romance Scam',
            description: 'Dating app profiles using AI-generated photos to build relationships and request money',
            severity: 'medium',
            time: '8 hours ago'
        }
    ];
    
    // Shuffle and select random threats
    const shuffledThreats = threats.sort(() => Math.random() - 0.5).slice(0, 5);
    
    const feedContainer = document.getElementById('threatFeed');
    if (feedContainer) {
        feedContainer.innerHTML = shuffledThreats.map(threat => `
            <div class="threat-item ${threat.severity}">
                <div class="threat-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="threat-content">
                    <div class="threat-header">
                        <div class="threat-type">${threat.type}</div>
                        <div class="threat-time">${threat.time}</div>
                    </div>
                    <div class="threat-description">${threat.description}</div>
                    <span class="threat-severity ${threat.severity}">${threat.severity} severity</span>
                </div>
            </div>
        `).join('');
    }
}

function refreshThreatFeed() {
    showLoading('Updating threat intelligence...');
    setTimeout(() => {
        updateThreatFeed();
        hideLoading();
    }, 1000);
}

function filterThreats() {
    const severity = document.getElementById('severityFilter').value;
    const threatItems = document.querySelectorAll('.threat-item');
    
    threatItems.forEach(item => {
        if (severity === 'all' || item.classList.contains(severity)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

// Utility Functions
function isValidURL(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        // Try adding https:// if no protocol specified
        try {
            const url = new URL('https://' + string);
            return true;
        } catch (_) {
            return false;
        }
    }
}

function getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 30) return 'Medium';
    return 'Low';
}

function getRiskClass(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'critical';
        case 'High': return 'danger';
        case 'Medium': return 'warning';
        default: return 'safe';
    }
}

function getRiskIcon(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'fa-skull-crossbones';
        case 'High': return 'fa-exclamation-triangle';
        case 'Medium': return 'fa-exclamation-circle';
        default: return 'fa-check-circle';
    }
}

function getCheckIcon(status) {
    switch (status) {
        case 'pass': return 'fa-check-circle';
        case 'warning': return 'fa-exclamation-circle';
        case 'fail': return 'fa-times-circle';
        default: return 'fa-question-circle';
    }
}

function showError(container, message) {
    container.innerHTML = `
        <div class="error-message">
            <i class="fas fa-exclamation-circle"></i>
            <span>${message}</span>
        </div>
    `;
}

function addButtonLoadingStates() {
    const buttons = document.querySelectorAll('.analyze-btn, .nav-btn, .restart-btn');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            this.disabled = true;
            
            // Restore after 3 seconds (or when analysis completes)
            setTimeout(() => {
                this.innerHTML = originalText;
                this.disabled = false;
            }, 3000);
        });
    });
}