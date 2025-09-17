import { Shield, Menu, X } from "lucide-react"
import { useState } from "react"
import { GradientButton } from "./ui/gradient-button"

const Header = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
    setIsMenuOpen(false)
  }

  return (
    <header className="bg-gradient-primary text-white shadow-elegant sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3 animate-fade-in">
            <Shield className="h-8 w-8 text-white" />
            <h1 className="text-2xl font-bold">PhishGuard</h1>
          </div>
          
          {/* Desktop Navigation */}
          <nav className="hidden md:flex space-x-8">
            <button 
              onClick={() => scrollToSection('detector')}
              className="hover:text-primary-glow transition-colors font-medium"
            >
              Detector
            </button>
            <button 
              onClick={() => scrollToSection('education')}
              className="hover:text-primary-glow transition-colors font-medium"
            >
              Education
            </button>
            <button 
              onClick={() => scrollToSection('quiz')}
              className="hover:text-primary-glow transition-colors font-medium"
            >
              Quiz
            </button>
            <button 
              onClick={() => scrollToSection('about')}
              className="hover:text-primary-glow transition-colors font-medium"
            >
              About
            </button>
          </nav>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="md:hidden p-2"
          >
            {isMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <nav className="md:hidden mt-4 pb-4 animate-fade-in">
            <div className="flex flex-col space-y-3">
              <button 
                onClick={() => scrollToSection('detector')}
                className="text-left hover:text-primary-glow transition-colors font-medium"
              >
                Detector
              </button>
              <button 
                onClick={() => scrollToSection('education')}
                className="text-left hover:text-primary-glow transition-colors font-medium"
              >
                Education
              </button>
              <button 
                onClick={() => scrollToSection('quiz')}
                className="text-left hover:text-primary-glow transition-colors font-medium"
              >
                Quiz
              </button>
              <button 
                onClick={() => scrollToSection('about')}
                className="text-left hover:text-primary-glow transition-colors font-medium"
              >
                About
              </button>
            </div>
          </nav>
        )}
      </div>
    </header>
  )
}

export default Header