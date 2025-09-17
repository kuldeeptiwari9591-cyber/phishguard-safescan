import { AlertTriangle, Shield, Link, Zap, UserX, Download, MousePointer, Lock, RotateCcw, GraduationCap, Clock } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import phishingWarningImage from "@/assets/phishing-warning-signs.jpg"
import securityBestPracticesImage from "@/assets/security-best-practices.jpg"
import { useEffect, useState } from "react"

interface ThreatItem {
  type: string
  description: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  time: string
}

const EducationSection = () => {
  const [threats, setThreats] = useState<ThreatItem[]>([])

  const mockThreats: ThreatItem[] = [
    {
      type: 'Email Phishing',
      description: 'New campaign targeting banking customers with fake security alerts',
      severity: 'High',
      time: '2 minutes ago'
    },
    {
      type: 'SMS Phishing',
      description: 'Package delivery scam messages increasing by 300%',
      severity: 'Medium',
      time: '15 minutes ago'
    },
    {
      type: 'Website Clone',
      description: 'Fake social media login pages detected on compromised domains',
      severity: 'High',
      time: '1 hour ago'
    },
    {
      type: 'Business Email',
      description: 'CEO impersonation attacks targeting finance departments',
      severity: 'Critical',
      time: '3 hours ago'
    },
    {
      type: 'Voice Phishing',
      description: 'Automated calls claiming to be from tech support companies',
      severity: 'Medium',
      time: '5 hours ago'
    }
  ]

  useEffect(() => {
    // Simulate real-time threat feed updates
    const updateThreats = () => {
      const shuffled = [...mockThreats].sort(() => Math.random() - 0.5)
      setThreats(shuffled.slice(0, 4))
    }

    updateThreats()
    const interval = setInterval(updateThreats, 30000) // Update every 30 seconds

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'text-danger bg-danger/10 border-danger/20'
      case 'High':
        return 'text-danger bg-danger/10 border-danger/20'
      case 'Medium':
        return 'text-warning bg-warning/10 border-warning/20'
      case 'Low':
        return 'text-safe bg-safe/10 border-safe/20'
      default:
        return 'text-muted-foreground bg-muted border-muted'
    }
  }

  const commonPhishingSigns = [
    {
      icon: <AlertTriangle className="h-5 w-5" />,
      text: "Urgent or threatening language demanding immediate action"
    },
    {
      icon: <Link className="h-5 w-5" />,
      text: "Suspicious URLs that don't match the claimed sender"
    },
    {
      icon: <Zap className="h-5 w-5" />,
      text: "Poor grammar and spelling mistakes"
    },
    {
      icon: <UserX className="h-5 w-5" />,
      text: "Requests for personal or financial information"
    },
    {
      icon: <Download className="h-5 w-5" />,
      text: "Unexpected attachments or downloads"
    }
  ]

  const protectionTips = [
    {
      icon: <Shield className="h-5 w-5" />,
      text: "Always verify sender identity through independent channels"
    },
    {
      icon: <MousePointer className="h-5 w-5" />,
      text: "Hover over links to preview URLs before clicking"
    },
    {
      icon: <Lock className="h-5 w-5" />,
      text: "Use two-factor authentication on all accounts"
    },
    {
      icon: <RotateCcw className="h-5 w-5" />,
      text: "Keep software and browsers updated"
    },
    {
      icon: <GraduationCap className="h-5 w-5" />,
      text: "Stay informed about latest phishing techniques"
    }
  ]

  return (
    <section id="education" className="py-16 bg-card">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12 animate-fade-in">
          <h3 className="text-4xl font-bold mb-4 bg-gradient-primary bg-clip-text text-transparent">
            Learn to Identify Phishing
          </h3>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Educate yourself about phishing techniques and learn how to protect against cyber threats
          </p>
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
          {/* Common Phishing Signs */}
          <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-slide-up">
            <CardHeader>
              <div className="mb-4">
                <img 
                  src={phishingWarningImage}
                  alt="Warning signs of phishing emails displayed on a computer screen with highlighted suspicious elements"
                  className="w-full rounded-lg"
                />
              </div>
              <CardTitle className="text-2xl text-danger">Common Phishing Signs</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-4">
                {commonPhishingSigns.map((sign, index) => (
                  <li key={index} className="flex items-start space-x-3 group">
                    <div className="text-danger mt-1 group-hover:scale-110 transition-transform">
                      {sign.icon}
                    </div>
                    <span className="text-muted-foreground group-hover:text-foreground transition-colors">
                      {sign.text}
                    </span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Protection Tips */}
          <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-slide-up delay-150">
            <CardHeader>
              <div className="mb-4">
                <img 
                  src={securityBestPracticesImage}
                  alt="Cybersecurity best practices infographic showing secure browsing habits and safety tips"
                  className="w-full rounded-lg"
                />
              </div>
              <CardTitle className="text-2xl text-safe">Protection Tips</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-4">
                {protectionTips.map((tip, index) => (
                  <li key={index} className="flex items-start space-x-3 group">
                    <div className="text-safe mt-1 group-hover:scale-110 transition-transform">
                      {tip.icon}
                    </div>
                    <span className="text-muted-foreground group-hover:text-foreground transition-colors">
                      {tip.text}
                    </span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Real-time Threat Feed */}
        <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-fade-in">
          <CardHeader>
            <CardTitle className="text-2xl flex items-center">
              <AlertTriangle className="h-6 w-6 mr-3 text-warning" />
              Latest Threat Intelligence
              <div className="ml-auto flex items-center text-sm text-muted-foreground">
                <Clock className="h-4 w-4 mr-1" />
                Live Feed
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {threats.map((threat, index) => (
                <div 
                  key={`${threat.type}-${index}`}
                  className="flex items-start space-x-4 p-4 border rounded-lg hover:shadow-md transition-all duration-300 bg-background/50"
                >
                  <AlertTriangle className={`mt-1 h-5 w-5 ${getSeverityColor(threat.severity).split(' ')[0]}`} />
                  <div className="flex-1">
                    <div className="flex justify-between items-start mb-1">
                      <h6 className="font-semibold text-foreground">{threat.type}</h6>
                      <span className="text-sm text-muted-foreground">{threat.time}</span>
                    </div>
                    <p className="text-muted-foreground text-sm mb-2">{threat.description}</p>
                    <span className={`inline-block px-2 py-1 text-xs font-semibold rounded border ${getSeverityColor(threat.severity)}`}>
                      {threat.severity} Severity
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  )
}

export default EducationSection