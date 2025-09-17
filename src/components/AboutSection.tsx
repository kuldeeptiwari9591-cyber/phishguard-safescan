import { Brain, Users, Clock, Shield } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"

const AboutSection = () => {
  const features = [
    {
      icon: <Brain className="h-12 w-12" />,
      title: "AI-Powered Detection",
      description: "Advanced machine learning algorithms analyze patterns and detect sophisticated phishing attempts in real-time."
    },
    {
      icon: <Users className="h-12 w-12" />,
      title: "Community Protection",
      description: "Crowdsourced threat intelligence helps protect millions of users worldwide from emerging phishing campaigns."
    },
    {
      icon: <Clock className="h-12 w-12" />,
      title: "Real-Time Updates",
      description: "Continuous monitoring and instant updates ensure protection against the latest phishing techniques and threats."
    }
  ]

  return (
    <section id="about" className="py-16 bg-card">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12 animate-fade-in">
          <h3 className="text-4xl font-bold mb-4 bg-gradient-primary bg-clip-text text-transparent">
            About PhishGuard
          </h3>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Advanced cybersecurity protection through intelligent detection and comprehensive education
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card 
              key={index}
              className="text-center shadow-card-hover hover:shadow-glow transition-all duration-300 animate-slide-up"
              style={{ animationDelay: `${index * 150}ms` }}
            >
              <CardContent className="pt-8 pb-8">
                <div className="text-primary mb-6 flex justify-center">
                  {feature.icon}
                </div>
                <h4 className="text-xl font-bold mb-4 text-foreground">
                  {feature.title}
                </h4>
                <p className="text-muted-foreground leading-relaxed">
                  {feature.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  )
}

export default AboutSection