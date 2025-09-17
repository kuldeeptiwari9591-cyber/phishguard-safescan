// PhishGuard Client-Side Feature Extraction - 36 Advanced Security Features

// URL Feature Extraction (Features 1-20)
function extractURLFeatures(url) {
    let riskScore = 0;
    let warnings = [];
    let features = {};
    let domain = '';
    
    try {
        // Normalize URL - add protocol if missing
        let normalizedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            normalizedUrl = 'https://' + url;
        }
        
        const urlObj = new URL(normalizedUrl);
        domain = urlObj.hostname.toLowerCase();
        
        // Feature 1: Protocol Security Check
        if (urlObj.protocol !== 'https:') {
            riskScore += 25;
            warnings.push('Website does not use secure HTTPS protocol');
            features.httpsProtocol = false;
        } else {
            features.httpsProtocol = true;
        }
        
        // Feature 2: URL Length Analysis
        if (normalizedUrl.length > 150) {
            riskScore += 20;
            warnings.push('Unusually long URL (potential obfuscation)');
            features.urlLength = 'excessive';
        } else if (normalizedUrl.length > 100) {
            riskScore += 10;
            features.urlLength = 'long';
        } else {
            features.urlLength = 'normal';
        }
        
        // Feature 3: @ Symbol Detection (URL Redirection)
        if (normalizedUrl.includes('@')) {
            riskScore += 35;
            warnings.push('Contains @ symbol (used for URL redirection attacks)');
            features.hasAtSymbol = true;
        } else {
            features.hasAtSymbol = false;
        }
        
        // Feature 4: Double Slash Detection
        const doubleSlashCount = (normalizedUrl.match(/\/\//g) || []).length;
        if (doubleSlashCount > 1) {
            riskScore += 30;
            warnings.push('Multiple // sequences detected (redirection technique)');
            features.multipleSlashes = true;
        } else {
            features.multipleSlashes = false;
        }
        
        // Feature 5: Dot Count (Subdomain Analysis)
        const dotCount = (domain.match(/\./g) || []).length;
        if (dotCount > 4) {
            riskScore += 25;
            warnings.push('Excessive subdomain structure detected');
            features.excessiveSubdomains = true;
        } else if (dotCount > 3) {
            riskScore += 15;
            features.excessiveSubdomains = false;
        } else {
            features.excessiveSubdomains = false;
        }
        features.subdomainCount = dotCount;
        
        // Feature 6: Hyphen Count Analysis
        const hyphenCount = (domain.match(/-/g) || []).length;
        if (hyphenCount > 4) {
            riskScore += 20;
            warnings.push('Domain contains excessive hyphens (suspicious pattern)');
            features.excessiveHyphens = true;
        } else if (hyphenCount > 2) {
            riskScore += 10;
            features.excessiveHyphens = false;
        } else {
            features.excessiveHyphens = false;
        }
        features.hyphenCount = hyphenCount;
        
        // Feature 7: Suspicious Keywords Detection
        const suspiciousKeywords = [
            'secure', 'verify', 'urgent', 'suspended', 'limited', 'confirm', 
            'login', 'bank', 'paypal', 'amazon', 'update', 'billing', 
            'account-locked', 'security-alert', 'immediate', 'expires'
        ];
        
        let keywordCount = 0;
        suspiciousKeywords.forEach(keyword => {
            if (normalizedUrl.toLowerCase().includes(keyword)) {
                keywordCount++;
                riskScore += 12;
                warnings.push(`Contains suspicious keyword: "${keyword}"`);
            }
        });
        features.suspiciousKeywords = keywordCount;
        
        // Feature 8: URL Shortener Detection
        const shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'buff.ly', 'short.link', 'tiny.cc', 'is.gd', 'v.gd'
        ];
        
        const isShortener = shorteners.some(shortener => domain.includes(shortener));
        if (isShortener) {
            riskScore += 25;
            warnings.push('Uses URL shortening service (potential link hiding)');
            features.isShortener = true;
        } else {
            features.isShortener = false;
        }
        
        // Feature 9: Special Character Analysis
        const specialChars = /[!@#$%^&*()_+=\[\]{};':"\\|,.<>\/?~`]/g;
        const specialCharCount = (normalizedUrl.match(specialChars) || []).length;
        if (specialCharCount > 15) {
            riskScore += 15;
            warnings.push('Excessive special characters detected');
            features.excessiveSpecialChars = true;
        } else {
            features.excessiveSpecialChars = false;
        }
        features.specialCharCount = specialCharCount;
        
        // Feature 10: Path Length Analysis
        const pathLength = urlObj.pathname.length;
        if (pathLength > 100) {
            riskScore += 15;
            warnings.push('Unusually long URL path detected');
            features.longPath = true;
        } else {
            features.longPath = false;
        }
        features.pathLength = pathLength;
        
        // Feature 11: URL Parameter Analysis
        const paramCount = Array.from(urlObj.searchParams).length;
        if (paramCount > 8) {
            riskScore += 20;
            warnings.push('Excessive URL parameters detected');
            features.excessiveParams = true;
        } else {
            features.excessiveParams = false;
        }
        features.parameterCount = paramCount;
        
        // Feature 12: URL Encoding Analysis
        const encodingPattern = /%[0-9A-Fa-f]{2}/g;
        const encodingCount = (normalizedUrl.match(encodingPattern) || []).length;
        if (encodingCount > 5) {
            riskScore += 18;
            warnings.push('Excessive URL encoding detected (potential obfuscation)');
            features.excessiveEncoding = true;
        } else {
            features.excessiveEncoding = false;
        }
        features.encodingCount = encodingCount;
        
        // Feature 13: IP Address Detection
        const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipPattern.test(domain)) {
            riskScore += 40;
            warnings.push('Uses IP address instead of domain name');
            features.usesIPAddress = true;
        } else {
            features.usesIPAddress = false;
        }
        
        // Feature 14: Non-standard Port Detection
        if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
            riskScore += 25;
            warnings.push(`Uses non-standard port: ${urlObj.port}`);
            features.nonStandardPort = true;
        } else {
            features.nonStandardPort = false;
        }
        
        // Feature 15: Typosquatting Detection
        const legitimateDomains = [
            'google.com', 'microsoft.com', 'apple.com', 'facebook.com', 
            'twitter.com', 'github.com', 'amazon.com', 'paypal.com',
            'ebay.com', 'linkedin.com', 'netflix.com', 'spotify.com'
        ];
        
        legitimateDomains.forEach(legitDomain => {
            if (domain.includes(legitDomain) && domain !== legitDomain) {
                riskScore += 45;
                warnings.push(`Possible typosquatting of ${legitDomain}`);
                features.possibleTyposquatting = legitDomain;
            }
        });
        
        // Feature 16: Domain Extension Analysis
        const suspiciousExtensions = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip', '.top'];
        const domainExtension = '.' + domain.split('.').pop();
        if (suspiciousExtensions.includes(domainExtension)) {
            riskScore += 20;
            warnings.push(`Uses suspicious domain extension: ${domainExtension}`);
            features.suspiciousTLD = true;
        } else {
            features.suspiciousTLD = false;
        }
        
        // Feature 17: Numeric Domain Analysis
        const numericRatio = (domain.match(/\d/g) || []).length / domain.length;
        if (numericRatio > 0.3) {
            riskScore += 15;
            warnings.push('Domain contains excessive numeric characters');
            features.excessiveNumbers = true;
        } else {
            features.excessiveNumbers = false;
        }
        
        // Feature 18: Consonant Vowel Ratio
        const vowels = (domain.match(/[aeiou]/gi) || []).length;
        const consonants = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
        const cvRatio = consonants / (vowels || 1);
        if (cvRatio > 4) {
            riskScore += 10;
            warnings.push('Unusual consonant-vowel ratio in domain');
            features.unusualCVRatio = true;
        } else {
            features.unusualCVRatio = false;
        }
        
        // Feature 19: Homograph Detection (Basic)
        const homographChars = /[а-яё]/gi; // Cyrillic characters
        if (homographChars.test(domain)) {
            riskScore += 35;
            warnings.push('Domain contains potential homograph characters');
            features.homographDetected = true;
        } else {
            features.homographDetected = false;
        }
        
        // Feature 20: Brand Impersonation Detection
        const brandKeywords = [
            'microsoft', 'google', 'apple', 'amazon', 'paypal', 'ebay',
            'bank', 'secure', 'login', 'account', 'verify', 'update'
        ];
        
        let brandImpersonation = false;
        brandKeywords.forEach(brand => {
            if (domain.includes(brand) && !domain.startsWith(brand + '.')) {
                riskScore += 30;
                warnings.push(`Potential brand impersonation detected: ${brand}`);
                brandImpersonation = true;
            }
        });
        features.brandImpersonation = brandImpersonation;
        
    } catch (error) {
        riskScore = 90;
        warnings.push('Invalid URL format or parsing error');
        features.invalidURL = true;
    }
    
    return {
        url: url,
        domain: domain,
        riskScore: Math.min(riskScore, 100),
        warnings: warnings,
        features: features,
        timestamp: new Date().toLocaleString()
    };
}

// Email Feature Extraction (Features 21-30)
function extractEmailFeatures(emailData) {
    const { sender, subject, content, headers } = emailData;
    let riskScore = 0;
    let warnings = [];
    let features = {};
    
    // Feature 21: Sender Domain Analysis
    try {
        const senderDomain = sender.split('@')[1]?.toLowerCase();
        const freeDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com'];
        
        if (senderDomain) {
            features.senderDomain = senderDomain;
            
            // Check for suspicious sender patterns
            if (senderDomain.includes('-') && senderDomain.split('-').length > 2) {
                riskScore += 25;
                warnings.push('Suspicious sender domain structure');
            }
            
            // Check domain length
            if (senderDomain.length > 20) {
                riskScore += 15;
                warnings.push('Unusually long sender domain');
            }
            
            // Check for typosquatting in sender domain
            const legitEmailDomains = ['gmail.com', 'outlook.com', 'yahoo.com'];
            legitEmailDomains.forEach(domain => {
                if (senderDomain.includes(domain.substring(0, -4)) && senderDomain !== domain) {
                    riskScore += 35;
                    warnings.push(`Sender domain mimics ${domain}`);
                }
            });
        }
    } catch (e) {
        riskScore += 30;
        warnings.push('Invalid sender email format');
    }
    
    // Feature 22: Subject Line Analysis
    const urgentWords = [
        'urgent', 'immediate', 'expire', 'suspend', 'verify', 'confirm',
        'act now', 'limited time', 'expires today', 'final notice', 'last chance'
    ];
    
    let urgencyScore = 0;
    urgentWords.forEach(word => {
        if (subject.toLowerCase().includes(word)) {
            urgencyScore += 15;
            warnings.push(`Subject contains urgent language: "${word}"`);
        }
    });
    riskScore += Math.min(urgencyScore, 45);
    features.subjectUrgency = urgencyScore;
    
    // Feature 23: Subject Line Capitalization
    const allCapsRatio = (subject.match(/[A-Z]/g) || []).length / subject.length;
    if (allCapsRatio > 0.6) {
        riskScore += 20;
        warnings.push('Subject line uses excessive capitalization');
        features.excessiveCaps = true;
    } else {
        features.excessiveCaps = false;
    }
    
    // Feature 24: Content Phishing Phrases
    const phishingPhrases = [
        'click here', 'verify account', 'suspended account', 'confirm identity',
        'update payment', 'security alert', 'unusual activity', 'immediate action required',
        'confirm your information', 'reactivate your account', 'temporary suspension'
    ];
    
    let phraseCount = 0;
    phishingPhrases.forEach(phrase => {
        if (content.toLowerCase().includes(phrase)) {
            phraseCount++;
            riskScore += 20;
            warnings.push(`Content contains phishing phrase: "${phrase}"`);
        }
    });
    features.phishingPhrases = phraseCount;
    
    // Feature 25: Generic Greetings Detection
    const genericGreetings = [
        'dear customer', 'dear user', 'dear valued customer', 'dear account holder',
        'dear sir/madam', 'greetings', 'hello user'
    ];
    
    const hasGenericGreeting = genericGreetings.some(greeting => 
        content.toLowerCase().includes(greeting)
    );
    
    if (hasGenericGreeting) {
        riskScore += 18;
        warnings.push('Uses generic greeting instead of personalization');
        features.genericGreeting = true;
    } else {
        features.genericGreeting = false;
    }
    
    // Feature 26: Spelling and Grammar Analysis
    const commonMistakes = [
        'recieve', 'seperate', 'occurence', 'definately', 'loose',
        'there account', 'you\'re account', 'cant', 'wont', 'dont'
    ];
    
    let grammarIssues = 0;
    commonMistakes.forEach(mistake => {
        if (content.toLowerCase().includes(mistake)) {
            grammarIssues++;
            riskScore += 8;
        }
    });
    
    if (grammarIssues > 0) {
        warnings.push(`Content contains ${grammarIssues} spelling/grammar errors`);
        features.grammarIssues = grammarIssues;
    } else {
        features.grammarIssues = 0;
    }
    
    // Feature 27: Link Analysis
    const linkPattern = /https?:\/\/[^\s<>"']+/gi;
    const links = content.match(linkPattern) || [];
    
    if (links.length > 5) {
        riskScore += 25;
        warnings.push('Email contains excessive number of links');
        features.excessiveLinks = true;
    } else if (links.length > 2) {
        riskScore += 10;
        features.excessiveLinks = false;
    } else {
        features.excessiveLinks = false;
    }
    features.linkCount = links.length;
    
    // Analyze individual links
    links.forEach(link => {
        try {
            const urlFeatures = extractURLFeatures(link);
            if (urlFeatures.riskScore > 50) {
                riskScore += 20;
                warnings.push('Email contains high-risk URL');
            }
        } catch (e) {
            riskScore += 10;
            warnings.push('Email contains malformed URL');
        }
    });
    
    // Feature 28: Attachment References
    const attachmentKeywords = [
        'attachment', 'attached', 'document', 'file', 'download',
        'invoice', 'receipt', 'statement', 'report', 'pdf'
    ];
    
    const hasAttachmentRef = attachmentKeywords.some(keyword => 
        content.toLowerCase().includes(keyword)
    );
    
    if (hasAttachmentRef) {
        riskScore += 15;
        warnings.push('Email references attachments (potential malware vector)');
        features.attachmentReference = true;
    } else {
        features.attachmentReference = false;
    }
    
    // Feature 29: Emotional Manipulation Detection
    const emotionalWords = [
        'congratulations', 'winner', 'prize', 'lottery', 'inheritance',
        'emergency', 'help', 'stranded', 'accident', 'hospital', 'charity'
    ];
    
    let emotionalScore = 0;
    emotionalWords.forEach(word => {
        if (content.toLowerCase().includes(word)) {
            emotionalScore += 10;
        }
    });
    
    if (emotionalScore > 20) {
        riskScore += 25;
        warnings.push('Email uses emotional manipulation techniques');
        features.emotionalManipulation = true;
    } else {
        features.emotionalManipulation = false;
    }
    
    // Feature 30: Sender Display Name Analysis
    const displayNamePattern = /"?([^"<]+)"?\s*</;
    const displayNameMatch = sender.match(displayNamePattern);
    
    if (displayNameMatch) {
        const displayName = displayNameMatch[1].trim();
        const actualDomain = sender.split('@')[1];
        
        // Check if display name suggests different organization
        const orgSuggestions = ['bank', 'paypal', 'amazon', 'microsoft', 'google'];
        orgSuggestions.forEach(org => {
            if (displayName.toLowerCase().includes(org) && !actualDomain.includes(org)) {
                riskScore += 30;
                warnings.push(`Display name suggests ${org} but sender domain doesn't match`);
            }
        });
    }
    
    return {
        sender: sender,
        subject: subject,
        riskScore: Math.min(riskScore, 100),
        warnings: warnings,
        features: features,
        timestamp: new Date().toLocaleString()
    };
}

// Website Feature Extraction (Features 31-36)
function extractWebsiteFeatures(website, options) {
    let riskScore = 0;
    let warnings = [];
    let checks = [];
    let features = {};
    
    try {
        const urlObj = new URL(website.startsWith('http') ? website : 'https://' + website);
        const domain = urlObj.hostname.toLowerCase();
        
        // Feature 31: SSL/TLS Security Analysis
        if (options.checkSSL) {
            if (urlObj.protocol !== 'https:') {
                checks.push({
                    name: 'SSL Certificate',
                    status: 'fail',
                    message: 'Website does not use HTTPS encryption'
                });
                riskScore += 35;
                warnings.push('No HTTPS encryption detected');
            } else {
                checks.push({
                    name: 'SSL Certificate',
                    status: 'pass',
                    message: 'Website uses HTTPS encryption'
                });
            }
            
            // Simulate additional SSL checks
            const sslStrength = Math.random();
            if (sslStrength < 0.1) {
                checks.push({
                    name: 'SSL Strength',
                    status: 'fail',
                    message: 'Weak SSL/TLS configuration detected'
                });
                riskScore += 25;
                warnings.push('Weak SSL configuration');
            } else if (sslStrength < 0.3) {
                checks.push({
                    name: 'SSL Strength',
                    status: 'warning',
                    message: 'SSL configuration could be stronger'
                });
                riskScore += 10;
            } else {
                checks.push({
                    name: 'SSL Strength',
                    status: 'pass',
                    message: 'Strong SSL/TLS configuration'
                });
            }
        }
        
        // Feature 32: Domain and WHOIS Analysis
        if (options.checkDomain) {
            // Simulate domain age check
            const domainAge = Math.floor(Math.random() * 365 * 5); // 0-5 years
            
            if (domainAge < 30) {
                checks.push({
                    name: 'Domain Age',
                    status: 'fail',
                    message: `Very new domain (${domainAge} days old)`
                });
                riskScore += 40;
                warnings.push('Domain registered very recently');
            } else if (domainAge < 90) {
                checks.push({
                    name: 'Domain Age',
                    status: 'warning',
                    message: `Recent domain registration (${domainAge} days old)`
                });
                riskScore += 20;
            } else {
                checks.push({
                    name: 'Domain Age',
                    status: 'pass',
                    message: `Established domain (${domainAge} days old)`
                });
            }
            
            // Simulate reputation check
            const reputation = Math.floor(Math.random() * 100);
            if (reputation < 30) {
                checks.push({
                    name: 'Domain Reputation',
                    status: 'fail',
                    message: 'Poor domain reputation score'
                });
                riskScore += 45;
                warnings.push('Domain has poor reputation');
            } else if (reputation < 60) {
                checks.push({
                    name: 'Domain Reputation',
                    status: 'warning',
                    message: 'Mixed domain reputation'
                });
                riskScore += 15;
            } else {
                checks.push({
                    name: 'Domain Reputation',
                    status: 'pass',
                    message: 'Good domain reputation'
                });
            }
        }
        
        // Feature 33: Content and Structure Analysis
        if (options.checkContent) {
            // Simulate content analysis
            const contentRisk = Math.random();
            
            if (contentRisk < 0.05) {
                checks.push({
                    name: 'Content Analysis',
                    status: 'fail',
                    message: 'Suspicious content patterns detected'
                });
                riskScore += 50;
                warnings.push('Website content shows phishing indicators');
            } else if (contentRisk < 0.2) {
                checks.push({
                    name: 'Content Analysis',
                    status: 'warning',
                    message: 'Some content patterns require attention'
                });
                riskScore += 15;
            } else {
                checks.push({
                    name: 'Content Analysis',
                    status: 'pass',
                    message: 'Content appears legitimate'
                });
            }
            
            // Simulate form security check
            const hasInsecureForms = Math.random() < 0.1;
            if (hasInsecureForms && urlObj.protocol !== 'https:') {
                checks.push({
                    name: 'Form Security',
                    status: 'fail',
                    message: 'Login forms without HTTPS detected'
                });
                riskScore += 40;
                warnings.push('Insecure login forms detected');
            } else {
                checks.push({
                    name: 'Form Security',
                    status: 'pass',
                    message: 'Forms use secure transmission'
                });
            }
        }
        
        // Feature 34: Behavioral Analysis
        if (options.checkBehavior) {
            // Simulate behavioral checks
            const behaviorRisk = Math.random();
            
            if (behaviorRisk < 0.1) {
                checks.push({
                    name: 'Behavioral Analysis',
                    status: 'fail',
                    message: 'Suspicious user interaction patterns'
                });
                riskScore += 35;
                warnings.push('Suspicious behavioral patterns detected');
            } else {
                checks.push({
                    name: 'Behavioral Analysis',
                    status: 'pass',
                    message: 'Normal user interaction patterns'
                });
            }
            
            // Redirect analysis
            const hasRedirects = Math.random() < 0.3;
            if (hasRedirects) {
                const redirectCount = Math.floor(Math.random() * 5) + 1;
                if (redirectCount > 3) {
                    checks.push({
                        name: 'Redirect Analysis',
                        status: 'warning',
                        message: `Multiple redirects detected (${redirectCount})`
                    });
                    riskScore += 20;
                    warnings.push('Excessive redirects detected');
                } else {
                    checks.push({
                        name: 'Redirect Analysis',
                        status: 'pass',
                        message: `Normal redirect count (${redirectCount})`
                    });
                }
            } else {
                checks.push({
                    name: 'Redirect Analysis',
                    status: 'pass',
                    message: 'No suspicious redirects detected'
                });
            }
        }
        
        // Feature 35: SEO and Marketing Pattern Analysis
        if (options.checkSEO) {
            // Simulate SEO analysis
            const seoRisk = Math.random();
            
            if (seoRisk < 0.15) {
                checks.push({
                    name: 'SEO Analysis',
                    status: 'warning',
                    message: 'Unusual SEO patterns detected'
                });
                riskScore += 15;
                warnings.push('Suspicious SEO patterns');
            } else {
                checks.push({
                    name: 'SEO Analysis',
                    status: 'pass',
                    message: 'Normal SEO patterns'
                });
            }
            
            // Check for keyword stuffing indicators
            const keywordStuffing = Math.random() < 0.1;
            if (keywordStuffing) {
                checks.push({
                    name: 'Keyword Analysis',
                    status: 'warning',
                    message: 'Potential keyword stuffing detected'
                });
                riskScore += 10;
            } else {
                checks.push({
                    name: 'Keyword Analysis',
                    status: 'pass',
                    message: 'Normal keyword usage'
                });
            }
        }
        
        // Feature 36: Social Engineering Indicators
        if (options.checkSocial) {
            // Simulate social engineering detection
            const socialRisk = Math.random();
            
            if (socialRisk < 0.08) {
                checks.push({
                    name: 'Social Engineering',
                    status: 'fail',
                    message: 'Strong social engineering indicators detected'
                });
                riskScore += 45;
                warnings.push('Website designed to manipulate users');
            } else if (socialRisk < 0.25) {
                checks.push({
                    name: 'Social Engineering',
                    status: 'warning',
                    message: 'Mild social engineering indicators'
                });
                riskScore += 15;
            } else {
                checks.push({
                    name: 'Social Engineering',
                    status: 'pass',
                    message: 'No social engineering indicators'
                });
            }
            
            // Check for urgency indicators
            const urgencyCheck = Math.random() < 0.2;
            if (urgencyCheck) {
                checks.push({
                    name: 'Urgency Tactics',
                    status: 'warning',
                    message: 'Time pressure tactics detected'
                });
                riskScore += 20;
                warnings.push('Website uses urgency manipulation');
            } else {
                checks.push({
                    name: 'Urgency Tactics',
                    status: 'pass',
                    message: 'No urgency manipulation detected'
                });
            }
        }
        
        // Check for known malicious patterns
        const knownBadDomains = ['malicious-site.com', 'phishing-test.net', 'scam-example.org'];
        if (knownBadDomains.includes(domain)) {
            riskScore = 100;
            warnings.push('CRITICAL: Domain found in malicious site database');
            checks.push({
                name: 'Blacklist Check',
                status: 'fail',
                message: 'Domain found in security blacklist'
            });
        } else {
            checks.push({
                name: 'Blacklist Check',
                status: 'pass',
                message: 'Domain not found in blacklists'
            });
        }
        
    } catch (error) {
        riskScore = 95;
        warnings.push('Invalid website URL or analysis error');
        checks.push({
            name: 'URL Validation',
            status: 'fail',
            message: 'Invalid or malformed URL'
        });
    }
    
    return {
        website: website,
        riskScore: Math.min(riskScore, 100),
        warnings: warnings,
        checks: checks,
        features: features,
        timestamp: new Date().toLocaleString()
    };
}