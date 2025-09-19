// PhishGuard Advanced Client-Side Feature Extraction - 36+ Security Features

// Enhanced URL Feature Extraction with Machine Learning-inspired Logic
function extractAdvancedURLFeatures(url) {
    let riskScore = 0;
    let warnings = [];
    let features = {};
    let domain = '';
    let confidenceFactors = [];
    
    try {
        // Normalize URL - add protocol if missing
        let normalizedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            normalizedUrl = 'https://' + url;
        }
        
        const urlObj = new URL(normalizedUrl);
        domain = urlObj.hostname.toLowerCase();
        
        // Feature 1: Advanced Protocol Security Analysis
        const protocolAnalysis = analyzeProtocol(urlObj, normalizedUrl);
        riskScore += protocolAnalysis.risk;
        features = { ...features, ...protocolAnalysis.features };
        warnings.push(...protocolAnalysis.warnings);
        
        // Feature 2-5: Comprehensive URL Structure Analysis
        const structureAnalysis = analyzeURLStructure(normalizedUrl, urlObj);
        riskScore += structureAnalysis.risk;
        features = { ...features, ...structureAnalysis.features };
        warnings.push(...structureAnalysis.warnings);
        
        // Feature 6-10: Advanced Domain Analysis
        const domainAnalysis = analyzeDomainFeatures(domain, urlObj);
        riskScore += domainAnalysis.risk;
        features = { ...features, ...domainAnalysis.features };
        warnings.push(...domainAnalysis.warnings);
        
        // Feature 11-15: Content and Parameter Analysis
        const contentAnalysis = analyzeURLContent(urlObj, normalizedUrl);
        riskScore += contentAnalysis.risk;
        features = { ...features, ...contentAnalysis.features };
        warnings.push(...contentAnalysis.warnings);
        
        // Feature 16-20: Security Pattern Recognition
        const securityAnalysis = analyzeSecurityPatterns(normalizedUrl, domain);
        riskScore += securityAnalysis.risk;
        features = { ...features, ...securityAnalysis.features };
        warnings.push(...securityAnalysis.warnings);
        
        // Feature 21-25: Behavioral Analysis
        const behaviorAnalysis = analyzeBehavioralPatterns(normalizedUrl, domain, urlObj);
        riskScore += behaviorAnalysis.risk;
        features = { ...features, ...behaviorAnalysis.features };
        warnings.push(...behaviorAnalysis.warnings);
        
        // Feature 26-30: Advanced Threat Intelligence
        const threatAnalysis = analyzeThreatIntelligence(normalizedUrl, domain);
        riskScore += threatAnalysis.risk;
        features = { ...features, ...threatAnalysis.features };
        warnings.push(...threatAnalysis.warnings);
        
        // Feature 31-36: Advanced Security Analysis
        const securityAnalysis = performAdvancedSecurityAnalysis(normalizedUrl, domain, features);
        riskScore += securityAnalysis.risk;
        features = { ...features, ...securityAnalysis.features };
        warnings.push(...securityAnalysis.warnings);
        
        // Calculate confidence score
        const confidenceScore = calculateConfidenceScore(features, warnings.length);
        features.confidenceScore = confidenceScore;
        
    } catch (error) {
        riskScore = 95;
        warnings.push('Critical: Invalid URL format or parsing error');
        features.invalidURL = true;
        features.parseError = error.message;
    }
    
    // Final risk assessment with weighted scoring
    const finalScore = Math.min(applyWeightedScoring(riskScore, features), 100);
    
    return {
        url: url,
        domain: domain,
        riskScore: finalScore,
        warnings: warnings.filter(w => w), // Remove empty warnings
        features: features,
        timestamp: new Date().toLocaleString(),
        riskLevel: determineRiskLevel(finalScore)
    };
}

// Feature 1: Advanced Protocol Security Analysis
function analyzeProtocol(urlObj, normalizedUrl) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // HTTPS Analysis
    if (urlObj.protocol !== 'https:') {
        risk += 30;
        warnings.push('Website does not use secure HTTPS protocol - data transmission is not encrypted');
        features.httpsProtocol = false;
        features.protocolSecurity = 'insecure';
    } else {
        features.httpsProtocol = true;
        features.protocolSecurity = 'secure';
    }
    
    // Mixed Content Detection
    if (normalizedUrl.includes('http://') && normalizedUrl.includes('https://')) {
        risk += 25;
        warnings.push('Mixed content detected - combination of secure and insecure protocols');
        features.mixedContent = true;
    }
    
    // Protocol Downgrade Attack Detection
    if (normalizedUrl.match(/https?:\/\/.*https?:\/\//)) {
        risk += 35;
        warnings.push('Potential protocol downgrade attack detected');
        features.protocolDowngrade = true;
    }
    
    return { risk, warnings, features };
}

// Features 2-5: Comprehensive URL Structure Analysis
function analyzeURLStructure(normalizedUrl, urlObj) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Advanced URL Length Analysis
    const urlLength = normalizedUrl.length;
    if (urlLength > 200) {
        risk += 30;
        warnings.push('Extremely long URL detected (>200 chars) - possible obfuscation attempt');
        features.urlLength = 'extreme';
    } else if (urlLength > 150) {
        risk += 20;
        warnings.push('Very long URL detected - potential hiding of malicious intent');
        features.urlLength = 'very_long';
    } else if (urlLength > 100) {
        risk += 10;
        features.urlLength = 'long';
    } else {
        features.urlLength = 'normal';
    }
    
    // @ Symbol Analysis (URL Redirection)
    if (normalizedUrl.includes('@')) {
        risk += 40;
        warnings.push('Contains @ symbol - commonly used in phishing for URL redirection attacks');
        features.hasAtSymbol = true;
    }
    
    // Double Slash Pattern Detection
    const doubleSlashCount = (normalizedUrl.match(/\/\//g) || []).length;
    if (doubleSlashCount > 1) {
        risk += 35;
        warnings.push('Multiple // sequences detected - advanced redirection technique');
        features.multipleSlashes = true;
        features.doubleSlashCount = doubleSlashCount;
    }
    
    // Path Depth Analysis
    const pathSegments = urlObj.pathname.split('/').filter(segment => segment.length > 0);
    if (pathSegments.length > 10) {
        risk += 20;
        warnings.push('Excessive path depth detected - possible directory traversal or obfuscation');
        features.excessivePathDepth = true;
    }
    features.pathDepth = pathSegments.length;
    
    // File Extension Analysis
    const pathExtension = urlObj.pathname.split('.').pop().toLowerCase();
    const suspiciousExtensions = ['exe', 'scr', 'bat', 'com', 'pif', 'zip', 'rar'];
    if (suspiciousExtensions.includes(pathExtension)) {
        risk += 30;
        warnings.push(`Suspicious file extension detected: .${pathExtension}`);
        features.suspiciousExtension = pathExtension;
    }
    
    return { risk, warnings, features };
}

// Features 6-10: Advanced Domain Analysis
function analyzeDomainFeatures(domain, urlObj) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Subdomain Analysis
    const subdomains = domain.split('.');
    const subdomainCount = subdomains.length - 2; // Subtract main domain and TLD
    
    if (subdomainCount > 4) {
        risk += 30;
        warnings.push('Excessive subdomain levels detected - possible subdomain abuse');
        features.excessiveSubdomains = true;
    } else if (subdomainCount > 2) {
        risk += 15;
        features.excessiveSubdomains = false;
    }
    features.subdomainCount = Math.max(0, subdomainCount);
    
    // Advanced Hyphen Analysis
    const hyphenCount = (domain.match(/-/g) || []).length;
    const domainLength = domain.length;
    const hyphenRatio = hyphenCount / domainLength;
    
    if (hyphenCount > 5 || hyphenRatio > 0.3) {
        risk += 25;
        warnings.push('Excessive hyphens in domain - characteristic of phishing domains');
        features.excessiveHyphens = true;
    }
    features.hyphenCount = hyphenCount;
    features.hyphenRatio = hyphenRatio;
    
    // Domain Composition Analysis
    const numericChars = (domain.match(/\d/g) || []).length;
    const numericRatio = numericChars / domainLength;
    
    if (numericRatio > 0.4) {
        risk += 20;
        warnings.push('High numeric content in domain name - suspicious pattern');
        features.highNumericContent = true;
    }
    features.numericRatio = numericRatio;
    
    // Character Repetition Analysis
    const charFrequency = {};
    for (const char of domain) {
        charFrequency[char] = (charFrequency[char] || 0) + 1;
    }
    
    const maxRepetition = Math.max(...Object.values(charFrequency));
    if (maxRepetition > domainLength * 0.3) {
        risk += 15;
        warnings.push('Excessive character repetition in domain');
        features.excessiveRepetition = true;
    }
    
    // TLD Analysis
    const tld = domain.split('.').pop();
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'zip', 'top', 'bid', 'loan'];
    if (suspiciousTLDs.includes(tld)) {
        risk += 25;
        warnings.push(`Suspicious top-level domain: .${tld}`);
        features.suspiciousTLD = tld;
    }
    
    return { risk, warnings, features };
}

// Features 11-15: Content and Parameter Analysis
function analyzeURLContent(urlObj, normalizedUrl) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Advanced Parameter Analysis
    const paramCount = Array.from(urlObj.searchParams).length;
    if (paramCount > 15) {
        risk += 25;
        warnings.push('Excessive URL parameters detected - possible parameter pollution');
        features.excessiveParams = true;
    } else if (paramCount > 8) {
        risk += 10;
        features.excessiveParams = false;
    }
    features.parameterCount = paramCount;
    
    // Suspicious Parameter Names
    const suspiciousParamNames = ['token', 'auth', 'login', 'pass', 'user', 'account', 'verify', 'confirm'];
    let suspiciousParamCount = 0;
    
    for (const [paramName] of urlObj.searchParams) {
        if (suspiciousParamNames.some(suspicious => paramName.toLowerCase().includes(suspicious))) {
            suspiciousParamCount++;
            risk += 15;
            warnings.push(`Suspicious parameter detected: ${paramName}`);
        }
    }
    features.suspiciousParamCount = suspiciousParamCount;
    
    // URL Encoding Analysis
    const encodingPattern = /%[0-9A-Fa-f]{2}/g;
    const encodingCount = (normalizedUrl.match(encodingPattern) || []).length;
    const encodingRatio = encodingCount / normalizedUrl.length;
    
    if (encodingCount > 10 || encodingRatio > 0.1) {
        risk += 20;
        warnings.push('Excessive URL encoding detected - possible obfuscation technique');
        features.excessiveEncoding = true;
    }
    features.encodingCount = encodingCount;
    features.encodingRatio = encodingRatio;
    
    // Base64 Detection in Parameters
    for (const [paramName, paramValue] of urlObj.searchParams) {
        if (isBase64Encoded(paramValue) && paramValue.length > 20) {
            risk += 18;
            warnings.push(`Base64 encoded parameter detected: ${paramName}`);
            features.base64InParams = true;
        }
    }
    
    // Fragment Analysis
    if (urlObj.hash && urlObj.hash.length > 50) {
        risk += 12;
        warnings.push('Long URL fragment detected - possible data hiding');
        features.longFragment = true;
    }
    
    return { risk, warnings, features };
}

// Features 16-20: Security Pattern Recognition
function analyzeSecurityPatterns(normalizedUrl, domain) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Advanced Keyword Analysis
    const suspiciousKeywords = [
        'secure', 'verify', 'urgent', 'suspended', 'limited', 'confirm',
        'login', 'signin', 'account', 'bank', 'paypal', 'amazon', 'update',
        'billing', 'payment', 'security', 'alert', 'warning', 'locked',
        'expired', 'validation', 'authentication', 'credential', 'identity'
    ];
    
    let keywordCount = 0;
    const detectedKeywords = [];
    
    suspiciousKeywords.forEach(keyword => {
        if (normalizedUrl.toLowerCase().includes(keyword)) {
            keywordCount++;
            detectedKeywords.push(keyword);
            risk += 12;
        }
    });
    
    if (keywordCount > 3) {
        warnings.push(`Multiple suspicious keywords detected: ${detectedKeywords.slice(0, 3).join(', ')}${detectedKeywords.length > 3 ? '...' : ''}`);
    } else if (keywordCount > 0) {
        warnings.push(...detectedKeywords.map(kw => `Suspicious keyword detected: "${kw}"`));
    }
    
    features.suspiciousKeywords = keywordCount;
    features.detectedKeywords = detectedKeywords;
    
    // IP Address Detection (Enhanced)
    const ipv4Pattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    const ipv6Pattern = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/;
    
    if (ipv4Pattern.test(domain) || ipv6Pattern.test(domain)) {
        risk += 40;
        warnings.push('IP address used instead of domain name - highly suspicious');
        features.usesIPAddress = true;
    }
    
    // Port Analysis
    if (normalizedUrl.includes(':') && !normalizedUrl.match(/:\/\//) && !normalizedUrl.match(/:443/) && !normalizedUrl.match(/:80/)) {
        const portMatch = normalizedUrl.match(/:(\d+)/);
        if (portMatch) {
            const port = portMatch[1];
            risk += 20;
            warnings.push(`Non-standard port detected: ${port}`);
            features.nonStandardPort = port;
        }
    }
    
    // Homograph Attack Detection
    const homographPatterns = [
        /[а-яё]/gi, // Cyrillic
        /[αβγδεζηθικλμνξοπρστυφχψω]/gi, // Greek
        /[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]/gi // Extended Latin
    ];
    
    homographPatterns.forEach((pattern, index) => {
        if (pattern.test(domain)) {
            risk += 35;
            warnings.push('Domain contains potential homograph characters (lookalike attack)');
            features.homographDetected = true;
            return;
        }
    });
    
    // URL Shortener Detection (Enhanced)
    const urlShorteners = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'short.link', 'tiny.cc', 'is.gd', 'v.gd', 'cutt.ly', 'rebrand.ly',
        'clickmeter.com', 'clicky.me', 'bc.vc'
    ];
    
    const isShortener = urlShorteners.some(shortener => domain.includes(shortener));
    if (isShortener) {
        risk += 30;
        warnings.push('URL shortening service detected - destination hidden');
        features.isShortener = true;
    }
    
    return { risk, warnings, features };
}

// Features 21-25: Behavioral Analysis
function analyzeBehavioralPatterns(normalizedUrl, domain, urlObj) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Typosquatting Detection (Enhanced)
    const legitimateDomains = [
        'google.com', 'microsoft.com', 'apple.com', 'facebook.com', 'meta.com',
        'twitter.com', 'x.com', 'github.com', 'amazon.com', 'paypal.com',
        'ebay.com', 'linkedin.com', 'netflix.com', 'spotify.com', 'instagram.com',
        'youtube.com', 'gmail.com', 'outlook.com', 'yahoo.com', 'dropbox.com'
    ];
    
    legitimateDomains.forEach(legitDomain => {
        const similarity = calculateStringSimilarity(domain, legitDomain);
        if (similarity > 0.7 && similarity < 0.95 && domain !== legitDomain) {
            risk += 45;
            warnings.push(`Possible typosquatting of ${legitDomain} (${Math.round(similarity * 100)}% similar)`);
            features.possibleTyposquatting = {
                target: legitDomain,
                similarity: similarity
            };
        }
    });
    
    // Brand Impersonation Detection
    const brandKeywords = [
        'microsoft', 'google', 'apple', 'amazon', 'paypal', 'ebay', 'facebook',
        'bank', 'secure', 'login', 'account', 'verify', 'update', 'office365',
        'gmail', 'outlook', 'netflix', 'spotify', 'instagram', 'youtube'
    ];
    
    brandKeywords.forEach(brand => {
        if (domain.includes(brand) && !domain.startsWith(brand + '.') && !domain.endsWith('.' + brand + '.com')) {
            risk += 35;
            warnings.push(`Potential brand impersonation detected: ${brand}`);
            features.brandImpersonation = brand;
        }
    });
    
    // Suspicious Pattern Combinations
    const suspiciousPatterns = [
        /secure.*login/i,
        /verify.*account/i,
        /update.*payment/i,
        /confirm.*identity/i,
        /suspended.*account/i
    ];
    
    suspiciousPatterns.forEach(pattern => {
        if (pattern.test(normalizedUrl)) {
            risk += 25;
            warnings.push('Suspicious phrase pattern detected in URL');
            features.suspiciousPattern = true;
        }
    });
    
    // Domain Age Simulation (Client-side heuristics)
    const domainAgeHeuristic = analyzeDomainAgeHeuristics(domain);
    if (domainAgeHeuristic.suspicious) {
        risk += domainAgeHeuristic.risk;
        warnings.push(...domainAgeHeuristic.warnings);
        features.domainAgeHeuristic = domainAgeHeuristic;
    }
    
    // Consonant-Vowel Ratio Analysis
    const vowels = (domain.match(/[aeiou]/gi) || []).length;
    const consonants = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    const cvRatio = consonants / (vowels || 1);
    
    if (cvRatio > 5) {
        risk += 15;
        warnings.push('Unusual consonant-vowel ratio in domain (possible generated domain)');
        features.unusualCVRatio = true;
    }
    features.consonantVowelRatio = cvRatio;
    
    return { risk, warnings, features };
}

// Features 26-30: Advanced Threat Intelligence
function analyzeThreatIntelligence(normalizedUrl, domain) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Known Malicious Pattern Detection
    const maliciousPatterns = [
        /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/,  // IP addresses
        /bit\.ly|tinyurl|t\.co/,            // URL shorteners
        /[a-z0-9]{20,}/,                    // Long random strings
        /[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/, // UUID patterns
        /data:image|javascript:|vbscript:/   // Dangerous protocols
    ];
    
    maliciousPatterns.forEach((pattern, index) => {
        if (pattern.test(normalizedUrl)) {
            risk += [40, 30, 15, 20, 50][index];
            warnings.push(`Malicious pattern detected in URL structure`);
            features.maliciousPattern = true;
        }
    });
    
    // Phishing Database Simulation
    const knownPhishingDomains = [
        'phishing-example.com', 'fake-bank.net', 'scam-site.org',
        'malicious-site.tk', 'phish-test.ml', 'dangerous-link.ga'
    ];
    
    if (knownPhishingDomains.some(phishDomain => domain.includes(phishDomain))) {
        risk = 100;
        warnings.push('CRITICAL: Domain found in known phishing database');
        features.knownPhishingDomain = true;
    }
    
    // Suspicious TLD Combinations
    const suspiciousTLDCombos = ['.tk', '.ml', '.ga', '.cf'];
    const tld = '.' + domain.split('.').pop();
    
    if (suspiciousTLDCombos.includes(tld) && domain.split('.').length > 2) {
        risk += 20;
        warnings.push(`Suspicious TLD with subdomain structure: ${tld}`);
        features.suspiciousTLDPattern = true;
    }
    
    // Dynamic DNS Detection
    const dynamicDNSProviders = ['dyndns', 'no-ip', 'freedns', 'changeip'];
    if (dynamicDNSProviders.some(provider => domain.includes(provider))) {
        risk += 25;
        warnings.push('Dynamic DNS provider detected - commonly used by attackers');
        features.dynamicDNS = true;
    }
    
    // Suspicious Character Sequences
    const suspiciousSequences = [
        /(.)\1{3,}/,  // Character repetition (aaaa, bbbb, etc.)
        /[0O]{2,}/,   // Zeros and O's together
        /[Il1]{2,}/,  // I, l, and 1 together
        /[a-z][A-Z][a-z][A-Z]/ // Alternating case
    ];
    
    suspiciousSequences.forEach(sequence => {
        if (sequence.test(domain)) {
            risk += 10;
            warnings.push('Suspicious character sequence in domain');
            features.suspiciousCharSequence = true;
        }
    });
    
    return { risk, warnings, features };
}

// Features 31-36: Machine Learning Inspired Analysis
function performMLInspiredAnalysis(normalizedUrl, domain, existingFeatures) {
    let risk = 0;
    let warnings = [];
    let features = {};
    
    // Entropy Analysis
    const urlEntropy = calculateEntropy(normalizedUrl);
    const domainEntropy = calculateEntropy(domain);
    
    if (urlEntropy > 4.5 || domainEntropy > 3.5) {
        risk += 20;
        warnings.push('High entropy detected - possible randomly generated URL');
        features.highEntropy = true;
        features.urlEntropy = urlEntropy;
        features.domainEntropy = domainEntropy;
    }
    
    // Feature Correlation Analysis
    const correlationRisk = analyzeFeatureCorrelations(existingFeatures);
    risk += correlationRisk.risk;
    warnings.push(...correlationRisk.warnings);
    features.correlationAnalysis = correlationRisk.analysis;
    
    // Lexical Analysis
    const lexicalScore = performLexicalAnalysis(domain);
    if (lexicalScore.suspicious) {
        risk += lexicalScore.risk;
        warnings.push(...lexicalScore.warnings);
        features.lexicalAnalysis = lexicalScore;
    }
    
    // Behavioral Clustering
    const clusterAnalysis = performBehavioralClustering(normalizedUrl, domain, existingFeatures);
    if (clusterAnalysis.suspicious) {
        risk += clusterAnalysis.risk;
        warnings.push(...clusterAnalysis.warnings);
        features.behavioralCluster = clusterAnalysis.cluster;
    }
    
    // Advanced Pattern Recognition
    const patternAnalysis = performAdvancedPatternRecognition(normalizedUrl);
    risk += patternAnalysis.risk;
    warnings.push(...patternAnalysis.warnings);
    features.advancedPatterns = patternAnalysis.patterns;
    
    // Anomaly Detection
    const anomalyScore = detectAnomalies(normalizedUrl, domain, existingFeatures);
    if (anomalyScore.anomalous) {
        risk += anomalyScore.risk;
        warnings.push('Anomalous URL characteristics detected');
        features.anomalyDetection = anomalyScore;
    }
    
    return { risk, warnings, features };
}

// Helper Functions

function calculateStringSimilarity(str1, str2) {
    const len1 = str1.length;
    const len2 = str2.length;
    const matrix = Array(len2 + 1).fill(null).map(() => Array(len1 + 1).fill(null));
    
    for (let i = 0; i <= len1; i++) matrix[0][i] = i;
    for (let j = 0; j <= len2; j++) matrix[j][0] = j;
    
    for (let j = 1; j <= len2; j++) {
        for (let i = 1; i <= len1; i++) {
            const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[j][i] = Math.min(
                matrix[j][i - 1] + 1,
                matrix[j - 1][i] + 1,
                matrix[j - 1][i - 1] + indicator
            );
        }
    }
    
    const distance = matrix[len2][len1];
    return 1 - distance / Math.max(len1, len2);
}

function calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    
    for (let i = 0; i < len; i++) {
        frequencies[str[i]] = (frequencies[str[i]] || 0) + 1;
    }
    
    let entropy = 0;
    for (const frequency of Object.values(frequencies)) {
        const p = frequency / len;
        entropy -= p * Math.log2(p);
    }
    
    return entropy;
}

function isBase64Encoded(str) {
    try {
        return btoa(atob(str)) === str;
    } catch (err) {
        return false;
    }
}

function analyzeDomainAgeHeuristics(domain) {
    // Simple heuristics to guess domain age based on patterns
    let suspicious = false;
    let risk = 0;
    let warnings = [];
    
    // Very short domains (less than 4 chars) are often newer
    if (domain.split('.')[0].length < 4) {
        suspicious = true;
        risk += 15;
        warnings.push('Very short domain name - often indicates recent registration');
    }
    
    // Domains with numbers at the end might be variants of existing domains
    if (/\d+$/.test(domain.split('.')[0])) {
        suspicious = true;
        risk += 10;
        warnings.push('Domain ends with numbers - possible variant of existing domain');
    }
    
    return { suspicious, risk, warnings };
}

function analyzeFeatureCorrelations(features) {
    let risk = 0;
    let warnings = [];
    let analysis = {};
    
    // Check for dangerous feature combinations
    const dangerousCombos = [
        { features: ['usesIPAddress', 'nonStandardPort'], risk: 30, warning: 'IP address with non-standard port - highly suspicious' },
        { features: ['isShortener', 'suspiciousKeywords'], risk: 25, warning: 'URL shortener with suspicious keywords' },
        { features: ['excessiveHyphens', 'suspiciousTLD'], risk: 20, warning: 'Excessive hyphens with suspicious TLD' },
        { features: ['homographDetected', 'brandImpersonation'], risk: 35, warning: 'Homograph attack combined with brand impersonation' }
    ];
    
    dangerousCombos.forEach(combo => {
        if (combo.features.every(feature => features[feature])) {
            risk += combo.risk;
            warnings.push(combo.warning);
            analysis[combo.features.join('_')] = true;
        }
    });
    
    return { risk, warnings, analysis };
}

function performLexicalAnalysis(domain) {
    let suspicious = false;
    let risk = 0;
    let warnings = [];
    
    // Dictionary word analysis
    const commonWords = ['secure', 'login', 'bank', 'pay', 'account', 'verify', 'update'];
    const domainWords = domain.split(/[.-]/).filter(part => part.length > 2);
    
    let suspiciousWordCount = 0;
    domainWords.forEach(word => {
        if (commonWords.includes(word.toLowerCase())) {
            suspiciousWordCount++;
        }
    });
    
    if (suspiciousWordCount > 1) {
        suspicious = true;
        risk += 20;
        warnings.push('Multiple suspicious words in domain structure');
    }
    
    // Random character analysis
    const randomnessScore = calculateRandomnessScore(domain);
    if (randomnessScore > 0.7) {
        suspicious = true;
        risk += 15;
        warnings.push('Domain appears to contain random character sequences');
    }
    
    return { suspicious, risk, warnings, randomnessScore };
}

function calculateRandomnessScore(str) {
    // Simple randomness heuristic based on character transitions
    let transitions = 0;
    let totalTransitions = 0;
    
    for (let i = 0; i < str.length - 1; i++) {
        const char1 = str[i];
        const char2 = str[i + 1];
        
        totalTransitions++;
        
        // Check for unusual transitions
        if (/[a-z]/.test(char1) && /[0-9]/.test(char2)) transitions++;
        if (/[0-9]/.test(char1) && /[a-z]/.test(char2)) transitions++;
        if (Math.abs(char1.charCodeAt(0) - char2.charCodeAt(0)) > 10) transitions++;
    }
    
    return totalTransitions > 0 ? transitions / totalTransitions : 0;
}

function performBehavioralClustering(url, domain, features) {
    // Simulate clustering based on behavioral patterns
    let suspicious = false;
    let risk = 0;
    let warnings = [];
    let cluster = 'normal';
    
    // Phishing cluster indicators
    const phishingIndicators = [
        features.suspiciousKeywords > 2,
        features.excessiveHyphens,
        features.usesIPAddress,
        features.brandImpersonation,
        features.homographDetected
    ];
    
    const phishingScore = phishingIndicators.filter(Boolean).length;
    
    if (phishingScore >= 3) {
        suspicious = true;
        risk = 30;
        warnings.push('URL matches phishing behavior cluster');
        cluster = 'phishing';
    } else if (phishingScore >= 2) {
        risk = 15;
        cluster = 'suspicious';
    }
    
    return { suspicious, risk, warnings, cluster };
}

function performAdvancedPatternRecognition(url) {
    let risk = 0;
    let warnings = [];
    let patterns = [];
    
    // Advanced regex patterns for sophisticated attacks
    const advancedPatterns = [
        { pattern: /[a-z]+[0-9]+[a-z]+\.(tk|ml|ga|cf)/, risk: 25, name: 'suspicious_alternating_pattern' },
        { pattern: /[a-z]+-[a-z]+-[a-z]+\./, risk: 20, name: 'triple_hyphen_pattern' },
        { pattern: /[a-z]{1,3}[0-9]{1,3}[a-z]{1,3}/, risk: 15, name: 'char_num_alternation' },
        { pattern: /www\d+\./, risk: 18, name: 'www_with_numbers' },
        { pattern: /secure[^a-z]|[^a-z]secure/, risk: 22, name: 'secure_keyword_misuse' }
    ];
    
    advancedPatterns.forEach(({ pattern, risk: patternRisk, name }) => {
        if (pattern.test(url.toLowerCase())) {
            risk += patternRisk;
            patterns.push(name);
            warnings.push(`Advanced suspicious pattern detected: ${name.replace(/_/g, ' ')}`);
        }
    });
    
    return { risk, warnings, patterns };
}

function detectAnomalies(url, domain, features) {
    let anomalous = false;
    let risk = 0;
    let anomalies = [];
    
    // Statistical anomaly detection based on feature combinations
    const featureVector = [
        features.urlLength === 'extreme' ? 1 : 0,
        features.suspiciousKeywords || 0,
        features.hyphenCount || 0,
        features.subdomainCount || 0,
        features.parameterCount || 0
    ];
    
    const anomalyScore = featureVector.reduce((sum, val) => sum + val, 0);
    
    if (anomalyScore > 5) {
        anomalous = true;
        risk = 25;
        anomalies.push('multiple_suspicious_features');
    }
    
    // Domain length anomaly
    if (domain.length > 50 || domain.length < 4) {
        anomalous = true;
        risk += 10;
        anomalies.push('unusual_domain_length');
    }
    
    return { anomalous, risk, anomalies, score: anomalyScore };
}

function calculateConfidenceScore(features, warningCount) {
    // Calculate confidence based on feature completeness and consistency
    let confidence = 100;
    
    // Reduce confidence for missing or incomplete analysis
    if (!features.httpsProtocol) confidence -= 10;
    if (warningCount === 0 && Object.keys(features).length < 10) confidence -= 15;
    if (features.parseError) confidence -= 30;
    
    // Increase confidence for comprehensive analysis
    if (Object.keys(features).length > 20) confidence += 5;
    if (features.correlationAnalysis) confidence += 5;
    
    return Math.max(0, Math.min(100, confidence));
}

function applyWeightedScoring(baseScore, features) {
    let weightedScore = baseScore;
    
    // Apply weights based on feature criticality
    if (features.knownPhishingDomain) return 100;
    if (features.usesIPAddress) weightedScore *= 1.2;
    if (features.homographDetected) weightedScore *= 1.15;
    if (features.brandImpersonation) weightedScore *= 1.1;
    
    // Reduce score for positive indicators
    if (features.httpsProtocol && !features.suspiciousKeywords) {
        weightedScore *= 0.9;
    }
    
    return Math.min(100, weightedScore);
}

function determineRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 30) return 'Medium';
    return 'Low';
}

// Legacy function for backward compatibility
function extractURLFeatures(url) {
    return extractAdvancedURLFeatures(url);
}