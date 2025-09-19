// PhishGuard - Advanced Phishing Detection System
// Enhanced with real-time threat intelligence and comprehensive security analysis

// Global Variables
let mobileMenuOpen = false;
let quizQuestions = [];
let currentQuestionIndex = 0;
let userAnswers = [];
let quizScore = 0;
let loadingTimeout = null;
let isAnalyzing = false;
let urlHistory = [];

// Comprehensive Quiz Questions Database (30+ questions)
const allQuizQuestions = [
    {
        question: "What is the most reliable way to identify a phishing email?",
        options: [
            "Check the sender's email address carefully",
            "Look for urgent language and threats",
            "Verify links by hovering over them",
            "All of the above"
        ],
        correct: 3,
        explanation: "All these methods are important for identifying phishing emails. Always verify sender addresses, be suspicious of urgent language, and check links before clicking."
    },
    {
        question: "Which URL is most likely to be legitimate?",
        options: [
            "https://paypaI.com/login",
            "https://www.paypal.com/login",
            "http://paypal-security.net/verify",
            "https://paypal.secure-login.org"
        ],
        correct: 1,
        explanation: "The second option uses the correct spelling and official domain. The first uses a capital 'I' instead of 'l', and the others use suspicious subdomains."
    },
    {
        question: "What should you do if you receive an unexpected email asking for personal information?",
        options: [
            "Reply with the requested information",
            "Click the link to verify your account",
            "Contact the company directly through official channels",
            "Forward it to friends to ask their opinion"
        ],
        correct: 2,
        explanation: "Always contact the company directly through their official website or phone number to verify if the request is legitimate."
    },
    {
        question: "Which of these is a red flag in a URL?",
        options: [
            "HTTPS protocol",
            "Multiple subdomains",
            "Short domain name",
            "Common TLD like .com"
        ],
        correct: 1,
        explanation: "Multiple subdomains can be used to create confusing URLs that appear legitimate but redirect to malicious sites."
    },
    {
        question: "What is typosquatting?",
        options: [
            "A type of malware",
            "Creating domains with slight misspellings of popular sites",
            "A secure browsing technique",
            "A password protection method"
        ],
        correct: 1,
        explanation: "Typosquatting involves registering domains that are slight misspellings of popular websites to trick users into visiting malicious sites."
    },
    {
        question: "Which email characteristic is most suspicious?",
        options: [
            "Personalized greeting",
            "Company logo present",
            "Generic greeting like 'Dear Customer'",
            "Professional formatting"
        ],
        correct: 2,
        explanation: "Generic greetings are often used in phishing emails because attackers don't have personal information about their targets."
    },
    {
        question: "What does a padlock icon in the browser address bar indicate?",
        options: [
            "The website is definitely safe",
            "The connection is encrypted",
            "The website is verified by authorities",
            "The website cannot be hacked"
        ],
        correct: 1,
        explanation: "The padlock indicates an encrypted connection (HTTPS), but it doesn't guarantee the website is legitimate or safe."
    },
    {
        question: "Which action should you take before entering sensitive information on a website?",
        options: [
            "Check if the URL starts with HTTPS",
            "Verify the website's identity",
            "Look for trust indicators",
            "All of the above"
        ],
        correct: 3,
        explanation: "Before entering sensitive information, you should verify HTTPS, check the website's identity, and look for trust indicators like certificates."
    },
    {
        question: "What is the safest way to access your bank's website?",
        options: [
            "Click links in emails from your bank",
            "Type the URL directly into your browser",
            "Use a search engine to find the bank",
            "Use bookmarks you've saved"
        ],
        correct: 3,
        explanation: "Using saved bookmarks is safest because you know they point to the legitimate website. Typing URLs directly is also safe if you're careful."
    },
    {
        question: "Which of these is NOT a common phishing technique?",
        options: [
            "Creating urgency",
            "Impersonating trusted organizations",
            "Using strong encryption",
            "Requesting personal information"
        ],
        correct: 2,
        explanation: "Strong encryption is a security feature, not a phishing technique. Phishers typically use urgency, impersonation, and requests for personal information."
    },
    {
        question: "What should you do if you accidentally clicked a suspicious link?",
        options: [
            "Ignore it and continue browsing",
            "Close the browser immediately",
            "Run antivirus software and change passwords",
            "Restart your computer"
        ],
        correct: 2,
        explanation: "If you clicked a suspicious link, run antivirus software, change relevant passwords, and monitor your accounts for suspicious activity."
    },
    {
        question: "Which domain extension is most commonly abused by phishers?",
        options: [
            ".com",
            ".org",
            ".tk (free domains)",
            ".edu"
        ],
        correct: 2,
        explanation: "Free domain extensions like .tk are often abused by phishers because they're easy to obtain and don't require verification."
    },
    {
        question: "What is spear phishing?",
        options: [
            "Phishing using fake spear imagery",
            "Targeted phishing attacks on specific individuals",
            "Phishing through social media only",
            "A type of malware"
        ],
        correct: 1,
        explanation: "Spear phishing involves targeted attacks on specific individuals or organizations, often using personal information to appear more credible."
    },
    {
        question: "Which browser feature helps protect against phishing?",
        options: [
            "Pop-up blocker",
            "Safe browsing warnings",
            "Password manager",
            "All of the above"
        ],
        correct: 3,
        explanation: "All these features help protect against phishing: safe browsing warnings alert you to dangerous sites, pop-up blockers prevent malicious pop-ups, and password managers can detect fake sites."
    },
    {
        question: "What is the best practice for handling suspicious emails?",
        options: [
            "Delete them immediately",
            "Report them as spam/phishing",
            "Forward them to IT security",
            "Both B and C"
        ],
        correct: 3,
        explanation: "You should both report suspicious emails as spam/phishing to your email provider and forward them to your IT security team if applicable."
    },
    {
        question: "Which URL parameter is often used in phishing attacks?",
        options: [
            "?redirect=",
            "?secure=true",
            "?version=1.0",
            "?lang=en"
        ],
        correct: 0,
        explanation: "Redirect parameters can be used to send users to malicious sites after they visit what appears to be a legitimate URL."
    },
    {
        question: "What is pharming?",
        options: [
            "A type of agriculture",
            "Redirecting users from legitimate sites to fake ones",
            "A secure browsing method",
            "A password storage technique"
        ],
        correct: 1,
        explanation: "Pharming involves redirecting users from legitimate websites to fake ones, often by compromising DNS servers or local host files."
    },
    {
        question: "Which of these is a sign of a secure website?",
        options: [
            "Professional design",
            "Valid SSL certificate",
            "Contact information provided",
            "All of the above"
        ],
        correct: 3,
        explanation: "While professional design and contact information are good signs, a valid SSL certificate is the most important technical indicator of a secure connection."
    },
    {
        question: "What should you do before downloading software from the internet?",
        options: [
            "Check the publisher's reputation",
            "Verify digital signatures",
            "Use official download sources",
            "All of the above"
        ],
        correct: 3,
        explanation: "Before downloading software, always check the publisher's reputation, verify digital signatures, and use official download sources to avoid malware."
    },
    {
        question: "Which social engineering technique creates false urgency?",
        options: [
            "Pretexting",
            "Scareware",
            "Baiting",
            "Tailgating"
        ],
        correct: 1,
        explanation: "Scareware creates false urgency by claiming your computer is infected or at risk, pressuring you to take immediate action."
    },
    {
        question: "What is the most effective way to verify a suspicious website?",
        options: [
            "Check online reviews",
            "Look up the domain registration",
            "Contact the supposed organization directly",
            "All of the above"
        ],
        correct: 3,
        explanation: "All these methods are effective: online reviews show others' experiences, domain registration reveals ownership details, and direct contact confirms legitimacy."
    },
    {
        question: "Which email header can help identify phishing attempts?",
        options: [
            "From address",
            "Reply-to address",
            "Return-path",
            "All of the above"
        ],
        correct: 3,
        explanation: "All email headers can provide clues about phishing: mismatched from/reply-to addresses and suspicious return paths are common indicators."
    },
    {
        question: "What is the primary goal of most phishing attacks?",
        options: [
            "Installing malware",
            "Stealing personal information",
            "Damaging computers",
            "Creating botnets"
        ],
        correct: 1,
        explanation: "While phishing can lead to malware installation, the primary goal is usually to steal personal information like passwords, credit card numbers, or identity details."
    },
    {
        question: "Which of these is a characteristic of a phishing URL?",
        options: [
            "Uses HTTPS protocol",
            "Contains the brand name",
            "Has suspicious subdomains",
            "Ends with .com"
        ],
        correct: 2,
        explanation: "Suspicious subdomains are often used in phishing URLs to make them appear legitimate while actually redirecting to malicious sites."
    },
    {
        question: "What should you do if your organization experiences a phishing attack?",
        options: [
            "Keep it secret to avoid embarrassment",
            "Report it to authorities and stakeholders",
            "Only tell the IT department",
            "Wait to see if any damage occurs"
        ],
        correct: 1,
        explanation: "Phishing attacks should be reported to relevant authorities and stakeholders to prevent further damage and help others avoid similar attacks."
    },
    {
        question: "Which two-factor authentication method is most secure against phishing?",
        options: [
            "SMS codes",
            "Email codes",
            "Authenticator apps",
            "Security questions"
        ],
        correct: 2,
        explanation: "Authenticator apps are most secure because they generate time-based codes that can't be intercepted like SMS or email codes."
    },
    {
        question: "What is vishing?",
        options: [
            "Visual phishing through images",
            "Voice phishing through phone calls",
            "Video phishing through streaming",
            "Virtual phishing in games"
        ],
        correct: 1,
        explanation: "Vishing (voice phishing) involves phone calls where attackers impersonate legitimate organizations to steal personal information."
    },
    {
        question: "Which browser setting helps prevent phishing?",
        options: [
            "Blocking third-party cookies",
            "Enabling safe browsing",
            "Disabling JavaScript",
            "Using private browsing mode"
        ],
        correct: 1,
        explanation: "Safe browsing features in browsers actively check websites against databases of known phishing and malware sites."
    },
    {
        question: "What is the best way to handle a phishing email in your inbox?",
        options: [
            "Delete it immediately",
            "Mark as spam and report",
            "Reply asking if it's legitimate",
            "Forward it to colleagues as a warning"
        ],
        correct: 1,
        explanation: "Mark phishing emails as spam and report them to help email providers improve their filters and protect other users."
    },
    {
        question: "Which of these makes a phishing email more convincing?",
        options: [
            "Personal information about the target",
            "Official-looking logos and formatting",
            "Urgent or threatening language",
            "All of the above"
        ],
        correct: 3,
        explanation: "Sophisticated phishing emails combine personal information, official branding, and psychological pressure to appear more legitimate and urgent."
    }
];

// DOM Content Loaded Event
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
});

// Initialize Application
function initializeApp() {
    console.log('PhishGuard initialized successfully');
    
    // Add smooth scrolling
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // Add loading states to buttons
    addButtonLoadingStates();
    
    // Initialize clipboard functionality
    initializeClipboard();
    
    // Load history
    loadHistory();
}

// Setup Event Listeners
function setupEventListeners() {
    // Initialize quiz immediately
    initializeQuiz();

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);

    // Add scroll effects
    window.addEventListener('scroll', handleScrollEffects);
}

// URL Analysis Function (called from HTML button)
async function analyzeURL() {
    if (isAnalyzing) {
        showToast('Analysis already in progress', 'warning');
        return;
    }

    const urlInput = document.getElementById('urlInput').value.trim();
    const resultsContainer = document.getElementById('urlResults');
    const loadingOverlay = document.getElementById('loadingOverlay');

    if (!urlInput) {
        showToast('Please enter a URL to analyze', 'error');
        return;
    }

    if (!isValidURL(urlInput)) {
        showToast('Please enter a valid URL', 'error');
        return;
    }

    try {
        isAnalyzing = true;
        
        // Show loading state
        loadingOverlay.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        
        // Update button state
        const analyzeBtn = document.querySelector('.analyze-btn');
        const originalText = analyzeBtn.innerHTML;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
        analyzeBtn.disabled = true;

        // Set timeout for loading indicator
        loadingTimeout = setTimeout(() => {
            if (isAnalyzing) {
                updateLoadingMessage('Performing deep analysis...');
            }
        }, 3000);

        // Perform comprehensive analysis
        const [clientResults, serverResults] = await Promise.all([
            performClientSideAnalysis(urlInput),
            performServerAnalysis(urlInput)
        ]);

        // Combine results
        const combinedResults = combineAnalysisResults(clientResults, serverResults);

        // Clear loading timeout
        if (loadingTimeout) {
            clearTimeout(loadingTimeout);
            loadingTimeout = null;
        }

        // Hide loading and show results
        loadingOverlay.classList.add('hidden');
        displayURLResults(combinedResults, urlInput);
        resultsContainer.classList.remove('hidden');
        
        // Add to history
        addToHistory(urlInput, combinedResults);
        
        // Smooth scroll to results
        setTimeout(() => {
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);

        // Restore button state
        analyzeBtn.textContent = originalText;
        analyzeBtn.disabled = false;

    } catch (error) {
        console.error('Analysis error:', error);
        showToast('Analysis failed. Please try again.', 'error');
        
        // Hide loading indicator
        loadingIndicator.classList.add('hidden');
        
        // Restore button state
        const analyzeBtn = document.querySelector('button[type="submit"]');
        analyzeBtn.textContent = 'Analyze URL';
        analyzeBtn.disabled = false;
    } finally {
        isAnalyzing = false;
    }
}

// Server-side Analysis
async function performServerAnalysis(url) {
    // Call real backend API
    try {
        const response = await fetch('/api/analyze-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error('Server analysis failed');
        }
    } catch (error) {
        console.error('Server analysis error:', error);
        return {
            timestamp: new Date().toLocaleString(),
            serverFeatures: {},
            threats: ['Server analysis unavailable'],
            error: true
        };
    }
}

// Client-side Analysis
async function performClientSideAnalysis(url) {
    return new Promise((resolve) => {
        setTimeout(() => {
            const analysis = analyzeURLFeatures(url);
            resolve({
                timestamp: new Date().toLocaleString(),
                clientFeatures: analysis.features,
                riskScore: analysis.riskScore,
                warnings: analysis.warnings,
                riskLevel: getRiskLevel(analysis.riskScore)
            });
        }, 1000);
    });
}

// Combine Analysis Results
function combineAnalysisResults(clientResults, serverResults) {
    const combinedScore = Math.min(
        (clientResults.riskScore + (serverResults.risk_score || 0)) / 2,
        100
    );

    return {
        timestamp: new Date().toLocaleString(),
        riskScore: Math.round(combinedScore),
        riskLevel: getRiskLevel(combinedScore),
        warnings: [
            ...clientResults.warnings,
            ...(serverResults.warnings || [])
        ],
        features: {
            client: clientResults.clientFeatures,
            server: serverResults.serverFeatures || {}
        },
        threats: serverResults.threats || [],
        analysis: {
            client: clientResults,
            server: serverResults
        }
    };
}

// Display URL Analysis Results
function displayURLResults(results) {
    const resultsContainer = document.getElementById('results');
    
    const riskColor = getRiskColor(results.riskLevel);
    const riskIcon = getRiskIcon(results.riskLevel);
    
    resultsContainer.innerHTML = `
        <div class="analysis-results">
            <div class="result-header">
                <div class="risk-indicator ${riskColor}">
                    <i class="${riskIcon}"></i>
                    <div>
                        <h3>${results.riskLevel} Risk</h3>
                        <p>Risk Score: ${results.riskScore}/100</p>
                    </div>
                </div>
                <div class="timestamp">
                    <i class="fas fa-clock"></i>
                    <span>Analyzed: ${results.timestamp}</span>
                </div>
            </div>

            ${results.warnings.length > 0 ? `
                <div class="warnings-section">
                    <h4><i class="fas fa-exclamation-triangle"></i> Security Warnings</h4>
                    <ul class="warnings-list">
                        ${results.warnings.map(warning => `<li>${warning}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${results.threats.length > 0 ? `
                <div class="threats-section">
                    <h4><i class="fas fa-shield-alt"></i> Threat Intelligence</h4>
                    <ul class="threats-list">
                        ${results.threats.map(threat => `<li>${threat}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            <div class="features-section">
                <h4><i class="fas fa-cog"></i> Analysis Details</h4>
                <div class="features-grid">
                    ${generateFeatureCards(results.features)}
                </div>
            </div>

            <div class="recommendations-section">
                <h4><i class="fas fa-lightbulb"></i> Recommendations</h4>
                <div class="recommendations">
                    ${generateRecommendations(results.riskLevel, results.warnings)}
                </div>
            </div>
        </div>
    `;
}

// Generate Feature Cards
function generateFeatureCards(features) {
    const cards = [];
    
    if (features.client) {
        cards.push(`
            <div class="feature-card">
                <h5>URL Structure</h5>
                <div class="feature-details">
                    <p>Length: ${features.client.urlLength || 'N/A'}</p>
                    <p>HTTPS: ${features.client.hasHTTPS ? 'Yes' : 'No'}</p>
                    <p>Suspicious chars: ${features.client.suspiciousChars || 0}</p>
                </div>
            </div>
        `);
    }
    
    if (features.server) {
        cards.push(`
            <div class="feature-card">
                <h5>Server Analysis</h5>
                <div class="feature-details">
                    <p>SSL Certificate: ${features.server.sslCertificate ? 'Valid' : 'Invalid'}</p>
                    <p>Domain Age: ${features.server.domainAge || 'Unknown'} days</p>
                    <p>Reputation: ${features.server.reputationScore || 'N/A'}/100</p>
                </div>
            </div>
        `);
    }
    
    return cards.join('');
}

// Generate Recommendations
function generateRecommendations(riskLevel, warnings) {
    const recommendations = [];
    
    switch (riskLevel) {
        case 'Critical':
            recommendations.push('🚫 Do not visit this website');
            recommendations.push('🛡️ Run a security scan on your device');
            recommendations.push('📞 Report this URL to security authorities');
            break;
        case 'High':
            recommendations.push('⚠️ Exercise extreme caution');
            recommendations.push('🔍 Verify the website through official channels');
            recommendations.push('🚫 Do not enter personal information');
            break;
        case 'Medium':
            recommendations.push('🔍 Verify the website legitimacy');
            recommendations.push('🛡️ Use additional security measures');
            recommendations.push('📱 Consider using mobile browser security');
            break;
        default:
            recommendations.push('✅ Website appears relatively safe');
            recommendations.push('🔒 Still verify HTTPS and certificates');
            recommendations.push('🛡️ Keep security software updated');
    }
    
    return recommendations.map(rec => `<p>${rec}</p>`).join('');
}

// Quiz Functions
function startQuiz() {
    // Select 5 random questions
    quizQuestions = getRandomQuestions(5);
    currentQuestionIndex = 0;
    userAnswers = [];
    quizScore = 0;
    
    displayQuestion();
    
    // Show quiz container and hide start button
    document.getElementById('quizContainer').classList.remove('hidden');
    document.getElementById('startQuiz').style.display = 'none';
}

function getRandomQuestions(count) {
    const shuffled = [...allQuizQuestions].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, count);
}

function displayQuestion() {
    const question = quizQuestions[currentQuestionIndex];
    const quizContainer = document.getElementById('quizContainer');
    
    quizContainer.innerHTML = `
        <div class="quiz-question">
            <div class="question-header">
                <h3>Question ${currentQuestionIndex + 1} of ${quizQuestions.length}</h3>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${((currentQuestionIndex + 1) / quizQuestions.length) * 100}%"></div>
                </div>
            </div>
            
            <div class="question-content">
                <h4>${question.question}</h4>
                <div class="options">
                    ${question.options.map((option, index) => `
                        <button class="option-btn" onclick="selectAnswer(${index})">
                            ${option}
                        </button>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function selectAnswer(selectedIndex) {
    const question = quizQuestions[currentQuestionIndex];
    const isCorrect = selectedIndex === question.correct;
    
    userAnswers.push({
        question: question.question,
        selected: selectedIndex,
        correct: question.correct,
        isCorrect: isCorrect,
        explanation: question.explanation
    });
    
    if (isCorrect) {
        quizScore++;
    }
    
    // Show feedback
    showAnswerFeedback(selectedIndex, question);
    
    // Move to next question after delay
    setTimeout(() => {
        currentQuestionIndex++;
        if (currentQuestionIndex < quizQuestions.length) {
            displayQuestion();
        } else {
            showQuizResults();
        }
    }, 2000);
}

function showAnswerFeedback(selectedIndex, question) {
    const options = document.querySelectorAll('.option-btn');
    
    options.forEach((btn, index) => {
        btn.disabled = true;
        if (index === question.correct) {
            btn.classList.add('correct');
        } else if (index === selectedIndex && index !== question.correct) {
            btn.classList.add('incorrect');
        }
    });
    
    // Show explanation
    const questionContent = document.querySelector('.question-content');
    questionContent.innerHTML += `
        <div class="explanation">
            <h5>Explanation:</h5>
            <p>${question.explanation}</p>
        </div>
    `;
}

function showQuizResults() {
    const percentage = Math.round((quizScore / quizQuestions.length) * 100);
    const quizContainer = document.getElementById('quizContainer');
    
    let performanceLevel = '';
    let performanceColor = '';
    
    if (percentage >= 80) {
        performanceLevel = 'Excellent';
        performanceColor = 'text-green-400';
    } else if (percentage >= 60) {
        performanceLevel = 'Good';
        performanceColor = 'text-blue-400';
    } else if (percentage >= 40) {
        performanceLevel = 'Fair';
        performanceColor = 'text-yellow-400';
    } else {
        performanceLevel = 'Needs Improvement';
        performanceColor = 'text-red-400';
    }
    
    quizContainer.innerHTML = `
        <div class="quiz-results">
            <div class="results-header">
                <h3>Quiz Complete!</h3>
                <div class="score-display">
                    <div class="score-circle">
                        <span class="score-number">${percentage}%</span>
                        <span class="score-label">${performanceLevel}</span>
                    </div>
                </div>
                <p class="${performanceColor}">You scored ${quizScore} out of ${quizQuestions.length} questions correctly.</p>
            </div>
            
            <div class="detailed-results">
                <h4>Review Your Answers:</h4>
                ${userAnswers.map((answer, index) => `
                    <div class="answer-review ${answer.isCorrect ? 'correct' : 'incorrect'}">
                        <h5>Question ${index + 1}: ${answer.isCorrect ? '✓' : '✗'}</h5>
                        <p class="question-text">${answer.question}</p>
                        <p class="answer-text">Your answer: ${quizQuestions[index].options[answer.selected]}</p>
                        ${!answer.isCorrect ? `<p class="correct-answer">Correct answer: ${quizQuestions[index].options[answer.correct]}</p>` : ''}
                        <p class="explanation">${answer.explanation}</p>
                    </div>
                `).join('')}
            </div>
            
            <div class="quiz-actions">
                <button onclick="restartQuiz()" class="btn-primary">Take Quiz Again</button>
                <button onclick="closeQuiz()" class="btn-secondary">Close Quiz</button>
            </div>
        </div>
    `;
}

function restartQuiz() {
    document.getElementById('startQuiz').style.display = 'block';
    document.getElementById('quizContainer').classList.add('hidden');
}

function closeQuiz() {
    document.getElementById('startQuiz').style.display = 'block';
    document.getElementById('quizContainer').classList.add('hidden');
}

// History Management Functions
function addToHistory(url, results) {
    const historyEntry = {
        url: url,
        riskScore: results.riskScore || 0,
        riskLevel: results.riskLevel || 'Low',
        timestamp: new Date().toLocaleString(),
        warnings: results.warnings ? results.warnings.length : 0
    };
    
    // Add to beginning of history
    urlHistory.unshift(historyEntry);
    
    // Keep only 5 most recent
    if (urlHistory.length > 5) {
        urlHistory.pop();
    }
    
    // Update UI
    updateHistoryDisplay();
    
    // Save to localStorage
    localStorage.setItem('phishguard_history', JSON.stringify(urlHistory));
}

function loadHistory() {
    try {
        const saved = localStorage.getItem('phishguard_history');
        if (saved) {
            urlHistory = JSON.parse(saved);
            updateHistoryDisplay();
        }
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

function updateHistoryDisplay() {
    const historyContainer = document.getElementById('historyContainer');
    if (!historyContainer) return;
    
    if (urlHistory.length === 0) {
        historyContainer.innerHTML = '<p class="text-gray-400">No recent analyses</p>';
        return;
    }
    
    const historyHTML = urlHistory.map(entry => `
        <div class="history-item p-3 border-l-4 ${getRiskBorderColor(entry.riskLevel)} bg-gray-800 rounded-r-lg mb-2">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <p class="text-white font-medium truncate" title="${entry.url}">${entry.url}</p>
                    <div class="flex items-center gap-4 mt-1">
                        <span class="text-sm ${getRiskTextColor(entry.riskLevel)}">${entry.riskLevel} Risk</span>
                        <span class="text-sm text-gray-400">${entry.warnings} warnings</span>
                        <span class="text-sm text-gray-500">${entry.timestamp}</span>
                    </div>
                </div>
                <div class="risk-score ${getRiskScoreClass(entry.riskScore)} ml-4">
                    ${entry.riskScore}
                </div>
            </div>
        </div>
    `).join('');
    
    historyContainer.innerHTML = historyHTML;
}

function getRiskBorderColor(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'border-red-500';
        case 'High': return 'border-orange-500';
        case 'Medium': return 'border-yellow-500';
        default: return 'border-green-500';
    }
}

function getRiskTextColor(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'text-red-400';
        case 'High': return 'text-orange-400';
        case 'Medium': return 'text-yellow-400';
        default: return 'text-green-400';
    }
}

function getRiskScoreClass(score) {
    if (score >= 80) return 'text-red-400 font-bold';
    if (score >= 60) return 'text-orange-400 font-bold';
    if (score >= 30) return 'text-yellow-400 font-bold';
    return 'text-green-400 font-bold';
}

function clearHistory() {
    urlHistory = [];
    localStorage.removeItem('phishguard_history');
    updateHistoryDisplay();
    showToast('History cleared successfully', 'success');
}

// Utility Functions
function isValidURL(string) {
    try {
        new URL(string.startsWith('http') ? string : 'https://' + string);
        return true;
    } catch (_) {
        return false;
    }
}

function getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 30) return 'Medium';
    return 'Low';
}

function getRiskColor(level) {
    switch (level) {
        case 'Critical': return 'risk-critical';
        case 'High': return 'risk-high';
        case 'Medium': return 'risk-medium';
        default: return 'risk-low';
    }
}

function getRiskIcon(level) {
    switch (level) {
        case 'Critical': return 'fas fa-exclamation-triangle';
        case 'High': return 'fas fa-exclamation-circle';
        case 'Medium': return 'fas fa-exclamation';
        default: return 'fas fa-check-circle';
    }
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

function updateLoadingMessage(message) {
    const loadingText = document.querySelector('#loadingIndicator .loading-text');
    if (loadingText) {
        loadingText.textContent = message;
    }
}

function addButtonLoadingStates() {
    const buttons = document.querySelectorAll('button[type="submit"]');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.disabled) {
                this.classList.add('loading');
            }
        });
    });
}

function initializeClipboard() {
    // Add copy functionality to results
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('copy-btn')) {
            const textToCopy = e.target.dataset.copy;
            navigator.clipboard.writeText(textToCopy).then(() => {
                showToast('Copied to clipboard!', 'success');
            });
        }
    });
}

function toggleMobileMenu() {
    mobileMenuOpen = !mobileMenuOpen;
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileMenu) {
        mobileMenu.classList.toggle('hidden', !mobileMenuOpen);
    }
}

function handleKeyboardShortcuts(e) {
    // Ctrl/Cmd + Enter to analyze URL
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const urlForm = document.getElementById('urlForm');
        if (urlForm && !isAnalyzing) {
            urlForm.dispatchEvent(new Event('submit'));
        }
    }
    
    // Escape to close mobile menu
    if (e.key === 'Escape' && mobileMenuOpen) {
        toggleMobileMenu();
    }
}

function handleScrollEffects() {
    const header = document.querySelector('header');
    if (header) {
        if (window.scrollY > 100) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    }
}

// Additional functions for URL analysis and history
async function performServerAnalysis(url) {
    try {
        const response = await fetch('/api/analyze-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error(`Server analysis failed: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Server analysis error:', error);
        return {
            risk_score: 0,
            warnings: ['Server analysis unavailable'],
            features: {}
        };
    }
}

function combineAnalysisResults(clientResults, serverResults) {
    return {
        url: serverResults.url || clientResults.url,
        risk_score: Math.max(clientResults.risk_score || 0, serverResults.risk_score || 0),
        risk_level: serverResults.risk_level || 'Low',
        warnings: [...(clientResults.warnings || []), ...(serverResults.warnings || [])],
        features: { ...(clientResults.features || {}), ...(serverResults.features || {}) },
        timestamp: new Date().toISOString()
    };
}

function displayURLResults(results, url) {
    const resultsContainer = document.getElementById('urlResults');
    if (!resultsContainer) return;

    const riskColor = getRiskColor(results.risk_level);
    const riskIcon = getRiskIcon(results.risk_level);
    
    resultsContainer.innerHTML = `
        <div class="analysis-results">
            <div class="result-header">
                <div class="result-icon ${riskColor}">
                    <i class="fas ${riskIcon}"></i>
                </div>
                <div class="result-info">
                    <h4>Analysis Complete</h4>
                    <p class="analyzed-url">${url}</p>
                </div>
                <div class="risk-score">
                    <span class="score-label">Risk Score</span>
                    <span class="score-value ${riskColor}">${results.risk_score}/100</span>
                </div>
            </div>
            
            <div class="risk-level-indicator ${riskColor}">
                <i class="fas ${riskIcon}"></i>
                <span>Risk Level: ${results.risk_level}</span>
            </div>
            
            ${results.warnings && results.warnings.length > 0 ? `
                <div class="warnings-section">
                    <h5><i class="fas fa-exclamation-triangle"></i> Security Warnings</h5>
                    <ul class="warnings-list">
                        ${results.warnings.map(warning => `<li>${warning}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            <div class="analysis-details">
                <h5><i class="fas fa-chart-bar"></i> Analysis Details</h5>
                <div class="details-grid">
                    <div class="detail-item">
                        <span class="detail-label">Analysis Time</span>
                        <span class="detail-value">${new Date().toLocaleString()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Features Analyzed</span>
                        <span class="detail-value">${Object.keys(results.features || {}).length}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Update history display
    updateHistoryDisplay();
}

function updateHistoryDisplay() {
    const historyContainer = document.getElementById('historyContainer');
    if (!historyContainer) return;
    
    if (urlHistory.length === 0) {
        historyContainer.innerHTML = '<p class="no-history">No analysis history yet. Analyze a URL to get started!</p>';
        return;
    }
    
    const historyHTML = urlHistory.map((item, index) => `
        <div class="history-item">
            <div class="history-info">
                <div class="url-preview">${item.url}</div>
                <div class="history-meta">
                    <span class="timestamp">${new Date(item.timestamp).toLocaleString()}</span>
                    <span class="risk-badge ${getRiskColor(item.risk_level)}">${item.risk_level}</span>
                </div>
            </div>
            <div class="risk-score-mini">${item.risk_score}/100</div>
        </div>
    `).join('');
    
    historyContainer.innerHTML = historyHTML;
}

function getRiskIcon(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'fa-skull-crossbones';
        case 'High': return 'fa-exclamation-triangle';  
        case 'Medium': return 'fa-exclamation-circle';
        default: return 'fa-shield-alt';
    }
}

function getRiskColor(riskLevel) {
    switch (riskLevel) {
        case 'Critical': return 'critical';
        case 'High': return 'high';
        case 'Medium': return 'medium';
        default: return 'low';
    }
}

function loadHistory() {
    // Load history from localStorage
    const saved = localStorage.getItem('phishguard_history');
    if (saved) {
        try {
            urlHistory = JSON.parse(saved).slice(0, 5); // Keep only 5 most recent
            updateHistoryDisplay();
        } catch (e) {
            console.error('Error loading history:', e);
            urlHistory = [];
        }
    }
}

function saveHistory() {
    try {
        localStorage.setItem('phishguard_history', JSON.stringify(urlHistory));
    } catch (e) {
        console.error('Error saving history:', e);
    }
}

function addToHistory(url, results) {
    const historyItem = {
        url: url,
        risk_score: results.risk_score || 0,
        risk_level: results.risk_level || 'Low',
        timestamp: new Date().toISOString(),
        warnings_count: (results.warnings || []).length
    };
    
    // Add to beginning of array
    urlHistory.unshift(historyItem);
    
    // Keep only 5 most recent
    urlHistory = urlHistory.slice(0, 5);
    
    // Save to localStorage
    saveHistory();
    
    // Update display
    updateHistoryDisplay();
}

// Toast notification system
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        // Create toast container if it doesn't exist
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = getToastIcon(type);
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas ${icon}"></i>
            <span>${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add to container
    const container = document.getElementById('toastContainer');
    container.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

function getToastIcon(type) {
    switch (type) {
        case 'success': return 'fa-check-circle';
        case 'error': return 'fa-exclamation-circle';
        case 'warning': return 'fa-exclamation-triangle';
        default: return 'fa-info-circle';
    }
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        isValidURL,
        getRiskLevel,
        getRiskColor,
        getRiskIcon
    };
}
