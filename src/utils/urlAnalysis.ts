// URL Analysis Features for PhishGuard
export interface AnalysisResult {
  url: string
  domain: string
  riskScore: number
  warnings: string[]
  timestamp: string
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'
  features: Record<string, any>
}

export interface EmailAnalysisResult {
  sender: string
  subject: string
  riskScore: number
  warnings: string[]
  timestamp: string
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'
}

export interface WebsiteAnalysisResult {
  website: string
  riskScore: number
  warnings: string[]
  checks: Array<{
    name: string
    status: 'passed' | 'failed' | 'warning'
    message: string
  }>
  timestamp: string
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'
}

export function performURLAnalysis(url: string): AnalysisResult {
  const suspiciousKeywords = ['secure', 'verify', 'urgent', 'suspended', 'limited', 'confirm', 'login', 'bank', 'paypal', 'amazon', 'update', 'billing', 'account-locked']
  const legitimateDomains = ['google.com', 'microsoft.com', 'apple.com', 'facebook.com', 'twitter.com', 'github.com', 'amazon.com', 'paypal.com']
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly']
  
  let riskScore = 0
  let warnings: string[] = []
  let domain = ''
  let features: Record<string, any> = {}

  try {
    const urlObj = new URL(url)
    domain = urlObj.hostname.toLowerCase()

    // Feature: HTTPS Check
    if (urlObj.protocol !== 'https:') {
      riskScore += 30
      warnings.push('Website does not use HTTPS encryption')
      features.https = false
    } else {
      features.https = true
    }

    // Feature: URL Length
    if (url.length > 100) {
      riskScore += 15
      warnings.push('Unusually long URL (potential obfuscation)')
      features.urlLength = 'suspicious'
    } else {
      features.urlLength = 'normal'
    }

    // Feature: @ Symbol (redirection)
    if (url.includes('@')) {
      riskScore += 40
      warnings.push('Contains @ symbol (used for redirection attacks)')
      features.hasAtSymbol = true
    }

    // Feature: // after protocol
    const doubleSlashCount = (url.match(/\/\//g) || []).length
    if (doubleSlashCount > 1) {
      riskScore += 25
      warnings.push('Multiple // sequences detected (redirection trick)')
      features.multipleSlashes = true
    }

    // Feature: Suspicious Keywords
    let keywordCount = 0
    suspiciousKeywords.forEach(keyword => {
      if (url.toLowerCase().includes(keyword)) {
        keywordCount++
        riskScore += 15
        warnings.push(`Contains suspicious keyword: "${keyword}"`)
      }
    })
    features.suspiciousKeywords = keywordCount

    // Feature: URL Shorteners
    if (shorteners.some(shortener => domain.includes(shortener))) {
      riskScore += 20
      warnings.push('Uses URL shortening service (potential hiding)')
      features.isShortener = true
    }

    // Feature: Hyphen Count
    const hyphenCount = (domain.match(/-/g) || []).length
    if (hyphenCount > 3) {
      riskScore += 25
      warnings.push('Domain contains excessive hyphens (suspicious pattern)')
      features.excessiveHyphens = true
    }
    features.hyphenCount = hyphenCount

    // Feature: Number of Dots (subdomains)
    const dotCount = (domain.match(/\./g) || []).length
    if (dotCount > 3) {
      riskScore += 20
      warnings.push('Unusually long subdomain structure')
      features.excessiveSubdomains = true
    }
    features.subdomainCount = dotCount

    // Feature: Typosquatting Detection
    legitimateDomains.forEach(legitDomain => {
      if (domain.includes(legitDomain) && domain !== legitDomain) {
        riskScore += 40
        warnings.push(`Possible typosquatting of ${legitDomain}`)
        features.possibleTyposquatting = legitDomain
      }
    })

    // Feature: IP Address in URL
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
    if (ipPattern.test(domain)) {
      riskScore += 35
      warnings.push('Uses IP address instead of domain name')
      features.usesIPAddress = true
    }

    // Feature: Non-standard Port
    if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
      riskScore += 20
      warnings.push(`Uses non-standard port: ${urlObj.port}`)
      features.nonStandardPort = urlObj.port
    }

    // Feature: Excessive URL Parameters
    const paramCount = Array.from(urlObj.searchParams).length
    if (paramCount > 5) {
      riskScore += 15
      warnings.push('Excessive URL parameters detected')
      features.excessiveParams = true
    }
    features.parameterCount = paramCount

    // Feature: URL Encoding Detection
    const encodingPattern = /%[0-9A-Fa-f]{2}/g
    const encodingCount = (url.match(encodingPattern) || []).length
    if (encodingCount > 3) {
      riskScore += 20
      warnings.push('Excessive URL encoding detected (obfuscation)')
      features.excessiveEncoding = true
    }

    // Feature: Special Characters
    const specialChars = /[!@#$%^&*()_+=\[\]{};':"\\|,.<>\/?~`]/g
    const specialCharCount = (url.match(specialChars) || []).length
    if (specialCharCount > 10) {
      riskScore += 10
      warnings.push('Unusual number of special characters')
      features.specialCharCount = specialCharCount
    }

  } catch (e) {
    riskScore = 100
    warnings.push('Invalid URL format')
    features.invalidURL = true
  }

  const finalScore = Math.min(riskScore, 100)
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low'
  
  if (finalScore >= 80) riskLevel = 'Critical'
  else if (finalScore >= 60) riskLevel = 'High'
  else if (finalScore >= 30) riskLevel = 'Medium'

  return {
    url,
    domain,
    riskScore: finalScore,
    warnings,
    timestamp: new Date().toLocaleString(),
    riskLevel,
    features
  }
}

export function performEmailAnalysis(sender: string, subject: string, content: string): EmailAnalysisResult {
  let riskScore = 0
  let warnings: string[] = []

  const urgentWords = ['urgent', 'immediate', 'expire', 'suspend', 'verify', 'confirm', 'act now', 'limited time', 'expires today']
  const phishingPhrases = ['click here', 'verify account', 'suspended account', 'confirm identity', 'update payment', 'security alert', 'unusual activity']
  const commonMistakes = ['recieve', 'seperate', 'occurence', 'definately', 'loose', 'there account']

  // Analyze sender domain
  try {
    const senderDomain = sender.split('@')[1]?.toLowerCase()
    const commonDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com']
    
    if (senderDomain && !commonDomains.includes(senderDomain)) {
      if (senderDomain.includes('-') || senderDomain.split('.').length > 2) {
        riskScore += 20
        warnings.push('Suspicious sender domain structure')
      }
    }
  } catch (e) {
    riskScore += 30
    warnings.push('Invalid sender email format')
  }

  // Analyze subject line
  urgentWords.forEach(word => {
    if (subject.toLowerCase().includes(word)) {
      riskScore += 15
      warnings.push(`Subject contains urgent language: "${word}"`)
    }
  })

  // Analyze content
  phishingPhrases.forEach(phrase => {
    if (content.toLowerCase().includes(phrase)) {
      riskScore += 25
      warnings.push(`Content contains phishing phrase: "${phrase}"`)
    }
  })

  // Check for excessive urgency
  const urgencyCount = urgentWords.filter(word => content.toLowerCase().includes(word)).length
  if (urgencyCount > 2) {
    riskScore += 30
    warnings.push('Excessive use of urgent language')
  }

  // Check for spelling/grammar issues
  commonMistakes.forEach(mistake => {
    if (content.toLowerCase().includes(mistake)) {
      riskScore += 10
      warnings.push('Contains common spelling errors')
    }
  })

  // Check for generic greetings
  if (content.toLowerCase().includes('dear customer') || content.toLowerCase().includes('dear user')) {
    riskScore += 15
    warnings.push('Uses generic greeting (not personalized)')
  }

  // Check for suspicious links
  const linkPattern = /https?:\/\/[^\s]+/g
  const links = content.match(linkPattern) || []
  if (links.length > 3) {
    riskScore += 20
    warnings.push('Contains multiple links')
  }

  const finalScore = Math.min(riskScore, 100)
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low'
  
  if (finalScore >= 80) riskLevel = 'Critical'
  else if (finalScore >= 60) riskLevel = 'High'
  else if (finalScore >= 30) riskLevel = 'Medium'

  return {
    sender,
    subject,
    riskScore: finalScore,
    warnings,
    timestamp: new Date().toLocaleString(),
    riskLevel
  }
}

export function performWebsiteAnalysis(website: string, options: {
  checkSSL: boolean
  checkDomain: boolean
  checkContent: boolean
}): WebsiteAnalysisResult {
  let riskScore = 0
  let warnings: string[] = []
  let checks: Array<{ name: string; status: 'passed' | 'failed' | 'warning'; message: string }> = []

  try {
    const urlObj = new URL(website)
    const domain = urlObj.hostname.toLowerCase()
    
    // Known phishing domains (simplified simulation)
    const knownPhishingDomains = ['phishing-example.com', 'fake-bank.net', 'scam-site.org']
    const isKnownPhishing = knownPhishingDomains.some(d => domain.includes(d))
    
    if (isKnownPhishing) {
      riskScore = 100
      warnings.push('CRITICAL: Known phishing website detected!')
      checks.push({ 
        name: 'Blacklist Check', 
        status: 'failed', 
        message: 'Website found in phishing blacklist' 
      })
    }

    if (options.checkSSL) {
      if (urlObj.protocol !== 'https:') {
        checks.push({ name: 'SSL Certificate', status: 'failed', message: 'Website does not use HTTPS' })
        riskScore += 30
        warnings.push('No SSL encryption detected')
      } else {
        checks.push({ name: 'SSL Certificate', status: 'passed', message: 'Valid HTTPS connection' })
      }
      
      // Simulate certificate checks
      const certValid = Math.random() > 0.1
      if (!certValid) {
        checks.push({ name: 'Certificate Validity', status: 'failed', message: 'Invalid or expired SSL certificate' })
        riskScore += 40
        warnings.push('Invalid SSL certificate')
      } else {
        checks.push({ name: 'Certificate Validity', status: 'passed', message: 'SSL certificate is valid' })
      }
    }

    if (options.checkDomain) {
      // Simulate domain age check
      const domainAge = Math.floor(Math.random() * 365)
      if (domainAge < 30) {
        checks.push({ name: 'Domain Age', status: 'warning', message: `Domain registered ${domainAge} days ago (very new)` })
        riskScore += 25
        warnings.push('Very new domain registration')
      } else if (domainAge < 90) {
        checks.push({ name: 'Domain Age', status: 'warning', message: `Domain registered ${domainAge} days ago (recent)` })
        riskScore += 15
      } else {
        checks.push({ name: 'Domain Age', status: 'passed', message: `Domain registered ${domainAge} days ago` })
      }

      // Simulate reputation check
      const reputation = Math.floor(Math.random() * 100)
      if (reputation < 30) {
        checks.push({ name: 'Domain Reputation', status: 'failed', message: 'Poor domain reputation' })
        riskScore += 40
        warnings.push('Domain has poor reputation')
      } else if (reputation < 60) {
        checks.push({ name: 'Domain Reputation', status: 'warning', message: 'Mixed domain reputation' })
        riskScore += 15
      } else {
        checks.push({ name: 'Domain Reputation', status: 'passed', message: 'Good domain reputation' })
      }
    }

    if (options.checkContent) {
      // Simulate content analysis
      const hasLogin = Math.random() > 0.7
      const hasPayment = Math.random() > 0.8

      if (hasLogin && urlObj.protocol !== 'https:') {
        checks.push({ name: 'Login Security', status: 'failed', message: 'Login forms without HTTPS detected' })
        riskScore += 35
        warnings.push('Insecure login forms detected')
      } else {
        checks.push({ name: 'Login Security', status: 'passed', message: 'No insecure login forms detected' })
      }

      if (hasPayment) {
        checks.push({ name: 'Payment Security', status: 'passed', message: 'Secure payment processing detected' })
      }

      // Additional phishing content checks
      if (isKnownPhishing) {
        checks.push({ 
          name: 'Content Analysis', 
          status: 'failed', 
          message: 'Site contains phishing content designed to steal information' 
        })
      } else {
        checks.push({ 
          name: 'Content Analysis', 
          status: 'passed', 
          message: 'No obvious phishing content detected' 
        })
      }
    }

  } catch (e) {
    riskScore = 100
    warnings.push('Invalid website URL')
    checks.push({ name: 'URL Validation', status: 'failed', message: 'Invalid URL format' })
  }

  const finalScore = Math.min(riskScore, 100)
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low'
  
  if (finalScore >= 80) riskLevel = 'Critical'
  else if (finalScore >= 60) riskLevel = 'High'
  else if (finalScore >= 30) riskLevel = 'Medium'

  return {
    website,
    riskScore: finalScore,
    warnings,
    checks,
    timestamp: new Date().toLocaleString(),
    riskLevel
  }
}