import { ArrowRight } from "lucide-react"
import { GradientButton } from "./ui/gradient-button"
import heroCybersecurity from "@/assets/hero-cybersecurity.jpg"

const HeroSection = () => {
  const scrollToDetector = () => {
    const element = document.getElementById('detector')
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
  }

  return (
    <section className="bg-gradient-hero text-white py-20 relative overflow-hidden">
      <div className="absolute inset-0 bg-black/20"></div>
      <div className="container mx-auto px-4 text-center relative z-10">
        <div className="animate-fade-in">
          <img 
            src={heroCybersecurity}
            alt="Cybersecurity professional analyzing phishing threats on multiple computer monitors with security alerts and threat detection interfaces"
            className="mx-auto mb-8 rounded-lg shadow-2xl max-w-4xl w-full h-auto"
          />
        </div>
        <div className="animate-slide-up">
          <h2 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-white to-primary-glow bg-clip-text text-transparent">
            Protect Yourself from Phishing Attacks
          </h2>
          <p className="text-xl mb-8 max-w-3xl mx-auto leading-relaxed">
            Advanced AI-powered detection system to identify and analyze potential phishing threats in real-time. 
            Stay safe online with our comprehensive security tools and educational resources.
          </p>
          <GradientButton 
            onClick={scrollToDetector}
            variant="hero" 
            size="lg"
            className="animate-glow"
          >
            Start Detection
            <ArrowRight className="ml-2 h-5 w-5" />
          </GradientButton>
        </div>
      </div>
      
      {/* Decorative elements */}
      <div className="absolute top-20 left-10 w-20 h-20 bg-white/10 rounded-full blur-xl animate-pulse"></div>
      <div className="absolute bottom-20 right-10 w-32 h-32 bg-primary-glow/20 rounded-full blur-2xl animate-pulse"></div>
      <div className="absolute top-1/2 left-1/4 w-16 h-16 bg-accent/20 rounded-full blur-lg animate-pulse delay-500"></div>
    </section>
  )
}

export default HeroSection