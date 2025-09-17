import { useState } from "react"
import { Search, Globe, Mail, Shield, AlertTriangle, CheckCircle, XCircle, Clock } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { GradientButton } from "./ui/gradient-button"
import { performURLAnalysis, performEmailAnalysis, performWebsiteAnalysis, type AnalysisResult, type EmailAnalysisResult, type WebsiteAnalysisResult } from "@/utils/urlAnalysis"
import { useToast } from "@/hooks/use-toast"

const DetectionCenter = () => {
  const [activeTab, setActiveTab] = useState<'url' | 'email' | 'website'>('url')
  const [loading, setLoading] = useState(false)
  
  // URL Analysis State
  const [urlInput, setUrlInput] = useState('')
  const [urlResults, setUrlResults] = useState<AnalysisResult | null>(null)
  
  // Email Analysis State
  const [emailSender, setEmailSender] = useState('')
  const [emailSubject, setEmailSubject] = useState('')
  const [emailContent, setEmailContent] = useState('')
  const [emailResults, setEmailResults] = useState<EmailAnalysisResult | null>(null)
  
  // Website Analysis State
  const [websiteInput, setWebsiteInput] = useState('')
  const [checkSSL, setCheckSSL] = useState(true)
  const [checkDomain, setCheckDomain] = useState(true)
  const [checkContent, setCheckContent] = useState(true)
  const [websiteResults, setWebsiteResults] = useState<WebsiteAnalysisResult | null>(null)

  const { toast } = useToast()

  const handleURLAnalysis = async () => {
    if (!urlInput.trim()) {
      toast({
        title: "Error",
        description: "Please enter a URL to analyze",
        variant: "destructive"
      })
      return
    }

    setLoading(true)
    setUrlResults(null)
    
    // Simulate API call delay
    setTimeout(() => {
      try {
        const results = performURLAnalysis(urlInput)
        setUrlResults(results)
        toast({
          title: "Analysis Complete",
          description: `Risk Level: ${results.riskLevel}`,
          variant: results.riskLevel === 'Low' ? "default" : "destructive"
        })
      } catch (error) {
        toast({
          title: "Analysis Failed",
          description: "Unable to analyze the provided URL",
          variant: "destructive"
        })
      }
      setLoading(false)
    }, 2000)
  }

  const handleEmailAnalysis = async () => {
    if (!emailSender || !emailSubject || !emailContent) {
      toast({
        title: "Error",
        description: "Please fill in all email fields",
        variant: "destructive"
      })
      return
    }

    setLoading(true)
    setEmailResults(null)
    
    setTimeout(() => {
      try {
        const results = performEmailAnalysis(emailSender, emailSubject, emailContent)
        setEmailResults(results)
        toast({
          title: "Email Analysis Complete",
          description: `Risk Level: ${results.riskLevel}`,
          variant: results.riskLevel === 'Low' ? "default" : "destructive"
        })
      } catch (error) {
        toast({
          title: "Analysis Failed",
          description: "Unable to analyze the email",
          variant: "destructive"
        })
      }
      setLoading(false)
    }, 2000)
  }

  const handleWebsiteAnalysis = async () => {
    if (!websiteInput.trim()) {
      toast({
        title: "Error",
        description: "Please enter a website URL to scan",
        variant: "destructive"
      })
      return
    }

    setLoading(true)
    setWebsiteResults(null)
    
    setTimeout(() => {
      try {
        const results = performWebsiteAnalysis(websiteInput, {
          checkSSL,
          checkDomain,
          checkContent
        })
        setWebsiteResults(results)
        toast({
          title: "Website Scan Complete",
          description: `Risk Level: ${results.riskLevel}`,
          variant: results.riskLevel === 'Low' ? "default" : "destructive"
        })
      } catch (error) {
        toast({
          title: "Scan Failed",
          description: "Unable to scan the website",
          variant: "destructive"
        })
      }
      setLoading(false)
    }, 3000)
  }

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'Low':
        return <CheckCircle className="h-8 w-8 text-safe" />
      case 'Medium':
        return <AlertTriangle className="h-8 w-8 text-warning" />
      case 'High':
      case 'Critical':
        return <XCircle className="h-8 w-8 text-danger" />
      default:
        return <Shield className="h-8 w-8 text-muted-foreground" />
    }
  }

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'Low':
        return 'text-safe'
      case 'Medium':
        return 'text-warning'
      case 'High':
      case 'Critical':
        return 'text-danger'
      default:
        return 'text-muted-foreground'
    }
  }

  const getProgressBarColor = (riskScore: number) => {
    if (riskScore >= 70) return 'bg-gradient-danger'
    if (riskScore >= 40) return 'bg-gradient-warning'
    return 'bg-gradient-safe'
  }

  return (
    <section id="detector" className="py-16 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12 animate-fade-in">
          <h3 className="text-4xl font-bold mb-4 bg-gradient-primary bg-clip-text text-transparent">
            Phishing Detection Center
          </h3>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Advanced AI-powered analysis to detect phishing attempts across URLs, emails, and websites
          </p>
        </div>
        
        {/* Tab Navigation */}
        <div className="flex justify-center mb-8">
          <div className="bg-card rounded-lg shadow-lg p-2 border">
            <GradientButton
              onClick={() => setActiveTab('url')}
              variant={activeTab === 'url' ? 'primary' : 'outline'}
              className="mr-2"
            >
              <Globe className="h-4 w-4 mr-2" />
              URL Scanner
            </GradientButton>
            <GradientButton
              onClick={() => setActiveTab('email')}
              variant={activeTab === 'email' ? 'primary' : 'outline'}
              className="mr-2"
            >
              <Mail className="h-4 w-4 mr-2" />
              Email Analyzer
            </GradientButton>
            <GradientButton
              onClick={() => setActiveTab('website')}
              variant={activeTab === 'website' ? 'primary' : 'outline'}
            >
              <Shield className="h-4 w-4 mr-2" />
              Website Scanner
            </GradientButton>
          </div>
        </div>

        <div className="max-w-6xl mx-auto">
          {/* URL Analysis Tab */}
          {activeTab === 'url' && (
            <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-fade-in">
              <CardHeader>
                <CardTitle className="flex items-center text-2xl">
                  <Globe className="h-6 w-6 mr-3 text-primary" />
                  URL Phishing Detection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold mb-2">Enter URL to analyze:</label>
                  <Input
                    type="url"
                    placeholder="https://example.com"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    className="text-lg"
                  />
                </div>
                <GradientButton
                  onClick={handleURLAnalysis}
                  disabled={loading}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <Clock className="h-5 w-5 mr-2 animate-spin" />
                      Analyzing URL...
                    </>
                  ) : (
                    <>
                      <Search className="h-5 w-5 mr-2" />
                      Analyze URL
                    </>
                  )}
                </GradientButton>

                {urlResults && (
                  <Card className="bg-gradient-card border-l-4 border-l-primary">
                    <CardHeader>
                      <CardTitle className="text-xl">Analysis Results</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="text-center space-y-4">
                          {getRiskIcon(urlResults.riskLevel)}
                          <div>
                            <div className={`text-2xl font-bold ${getRiskColor(urlResults.riskLevel)}`}>
                              {urlResults.riskLevel} Risk
                            </div>
                            <div className="text-lg text-muted-foreground">
                              Score: {urlResults.riskScore}/100
                            </div>
                          </div>
                          <div className="w-full bg-muted rounded-full h-3">
                            <div 
                              className={`h-3 rounded-full ${getProgressBarColor(urlResults.riskScore)}`}
                              style={{ width: `${urlResults.riskScore}%` }}
                            ></div>
                          </div>
                        </div>
                        <div>
                          <h6 className="font-bold mb-2">URL Details:</h6>
                          <div className="space-y-1 text-sm">
                            <p><strong>URL:</strong> {urlResults.url}</p>
                            <p><strong>Domain:</strong> {urlResults.domain}</p>
                            <p><strong>Analyzed:</strong> {urlResults.timestamp}</p>
                          </div>
                          {urlResults.warnings.length > 0 && (
                            <div className="mt-4">
                              <h5 className="font-bold text-danger mb-2">Security Warnings:</h5>
                              <ul className="space-y-1">
                                {urlResults.warnings.map((warning, index) => (
                                  <li key={index} className="flex items-start space-x-2 text-sm">
                                    <AlertTriangle className="h-4 w-4 text-danger mt-0.5 flex-shrink-0" />
                                    <span>{warning}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </CardContent>
            </Card>
          )}

          {/* Email Analysis Tab */}
          {activeTab === 'email' && (
            <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-fade-in">
              <CardHeader>
                <CardTitle className="flex items-center text-2xl">
                  <Mail className="h-6 w-6 mr-3 text-primary" />
                  Email Content Analysis
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold mb-2">Sender Email:</label>
                    <Input
                      type="email"
                      placeholder="sender@example.com"
                      value={emailSender}
                      onChange={(e) => setEmailSender(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold mb-2">Email Subject:</label>
                    <Input
                      type="text"
                      placeholder="Email subject line"
                      value={emailSubject}
                      onChange={(e) => setEmailSubject(e.target.value)}
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Email Content:</label>
                  <Textarea
                    rows={6}
                    placeholder="Paste email content here..."
                    value={emailContent}
                    onChange={(e) => setEmailContent(e.target.value)}
                  />
                </div>
                <GradientButton
                  onClick={handleEmailAnalysis}
                  disabled={loading}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <Clock className="h-5 w-5 mr-2 animate-spin" />
                      Analyzing Email...
                    </>
                  ) : (
                    <>
                      <Mail className="h-5 w-5 mr-2" />
                      Analyze Email
                    </>
                  )}
                </GradientButton>

                {emailResults && (
                  <Card className="bg-gradient-card border-l-4 border-l-primary">
                    <CardHeader>
                      <CardTitle className="text-xl">Email Analysis Results</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="text-center space-y-4">
                          {getRiskIcon(emailResults.riskLevel)}
                          <div>
                            <div className={`text-2xl font-bold ${getRiskColor(emailResults.riskLevel)}`}>
                              {emailResults.riskLevel} Risk
                            </div>
                            <div className="text-lg text-muted-foreground">
                              Score: {emailResults.riskScore}/100
                            </div>
                          </div>
                          <div className="w-full bg-muted rounded-full h-3">
                            <div 
                              className={`h-3 rounded-full ${getProgressBarColor(emailResults.riskScore)}`}
                              style={{ width: `${emailResults.riskScore}%` }}
                            ></div>
                          </div>
                        </div>
                        <div>
                          <h6 className="font-bold mb-2">Email Details:</h6>
                          <div className="space-y-1 text-sm">
                            <p><strong>Sender:</strong> {emailResults.sender}</p>
                            <p><strong>Subject:</strong> {emailResults.subject}</p>
                            <p><strong>Analyzed:</strong> {emailResults.timestamp}</p>
                          </div>
                          {emailResults.warnings.length > 0 && (
                            <div className="mt-4">
                              <h5 className="font-bold text-danger mb-2">Security Warnings:</h5>
                              <ul className="space-y-1">
                                {emailResults.warnings.map((warning, index) => (
                                  <li key={index} className="flex items-start space-x-2 text-sm">
                                    <AlertTriangle className="h-4 w-4 text-danger mt-0.5 flex-shrink-0" />
                                    <span>{warning}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </CardContent>
            </Card>
          )}

          {/* Website Scanner Tab */}
          {activeTab === 'website' && (
            <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-fade-in">
              <CardHeader>
                <CardTitle className="flex items-center text-2xl">
                  <Shield className="h-6 w-6 mr-3 text-primary" />
                  Website Security Scanner
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold mb-2">Website URL:</label>
                  <Input
                    type="url"
                    placeholder="https://website-to-scan.com"
                    value={websiteInput}
                    onChange={(e) => setWebsiteInput(e.target.value)}
                    className="text-lg"
                  />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="checkSSL"
                      checked={checkSSL}
                      onCheckedChange={(checked) => setCheckSSL(checked as boolean)}
                    />
                    <label htmlFor="checkSSL" className="text-sm font-medium">SSL Certificate</label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="checkDomain"
                      checked={checkDomain}
                      onCheckedChange={(checked) => setCheckDomain(checked as boolean)}
                    />
                    <label htmlFor="checkDomain" className="text-sm font-medium">Domain Reputation</label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="checkContent"
                      checked={checkContent}
                      onCheckedChange={(checked) => setCheckContent(checked as boolean)}
                    />
                    <label htmlFor="checkContent" className="text-sm font-medium">Content Analysis</label>
                  </div>
                </div>
                <GradientButton
                  onClick={handleWebsiteAnalysis}
                  disabled={loading}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <Clock className="h-5 w-5 mr-2 animate-spin" />
                      Scanning Website...
                    </>
                  ) : (
                    <>
                      <Shield className="h-5 w-5 mr-2" />
                      Scan Website
                    </>
                  )}
                </GradientButton>

                {websiteResults && (
                  <Card className="bg-gradient-card border-l-4 border-l-primary">
                    <CardHeader>
                      <CardTitle className="text-xl">Website Scan Results</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="space-y-4">
                          <div className="text-center">
                            {getRiskIcon(websiteResults.riskLevel)}
                            <div>
                              <div className={`text-2xl font-bold ${getRiskColor(websiteResults.riskLevel)}`}>
                                {websiteResults.riskLevel} Risk
                              </div>
                              <div className="text-lg text-muted-foreground">
                                Score: {websiteResults.riskScore}/100
                              </div>
                            </div>
                            <div className="w-full bg-muted rounded-full h-3">
                              <div 
                                className={`h-3 rounded-full ${getProgressBarColor(websiteResults.riskScore)}`}
                                style={{ width: `${websiteResults.riskScore}%` }}
                              ></div>
                            </div>
                          </div>
                          <div className="text-sm">
                            <p><strong>Website:</strong> {websiteResults.website}</p>
                            <p><strong>Scanned:</strong> {websiteResults.timestamp}</p>
                          </div>
                          {websiteResults.warnings.length > 0 && (
                            <div>
                              <h5 className="font-bold text-danger mb-2">Security Issues:</h5>
                              <ul className="space-y-1">
                                {websiteResults.warnings.map((warning, index) => (
                                  <li key={index} className="flex items-start space-x-2 text-sm">
                                    <AlertTriangle className="h-4 w-4 text-danger mt-0.5 flex-shrink-0" />
                                    <span>{warning}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                        <div>
                          <h6 className="font-bold mb-3">Security Checks:</h6>
                          <div className="space-y-2">
                            {websiteResults.checks.map((check, index) => {
                              const statusIcon = check.status === 'passed' ? (
                                <CheckCircle className="h-5 w-5 text-safe" />
                              ) : check.status === 'warning' ? (
                                <AlertTriangle className="h-5 w-5 text-warning" />
                              ) : (
                                <XCircle className="h-5 w-5 text-danger" />
                              )
                              
                              return (
                                <div key={index} className="flex items-start space-x-3 p-3 border rounded-lg bg-background/50">
                                  {statusIcon}
                                  <div className="flex-1">
                                    <div className="font-semibold text-sm">{check.name}</div>
                                    <div className="text-xs text-muted-foreground">{check.message}</div>
                                  </div>
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </section>
  )
}

export default DetectionCenter