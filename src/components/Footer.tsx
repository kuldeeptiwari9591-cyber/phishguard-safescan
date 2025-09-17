import { Shield } from "lucide-react"

const Footer = () => {
  return (
    <footer className="bg-gradient-primary text-white py-12">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center space-x-3 mb-4">
              <Shield className="h-6 w-6" />
              <h5 className="text-xl font-bold">PhishGuard</h5>
            </div>
            <p className="text-white/80 leading-relaxed">
              Protecting users from phishing attacks through advanced detection and comprehensive education.
            </p>
          </div>
          
          <div>
            <h6 className="font-bold mb-4 text-lg">Tools</h6>
            <ul className="space-y-2 text-white/80">
              <li><a href="#detector" className="hover:text-white transition-colors">URL Scanner</a></li>
              <li><a href="#detector" className="hover:text-white transition-colors">Email Analyzer</a></li>
              <li><a href="#detector" className="hover:text-white transition-colors">Website Scanner</a></li>
              <li><a href="#quiz" className="hover:text-white transition-colors">Security Quiz</a></li>
            </ul>
          </div>
          
          <div>
            <h6 className="font-bold mb-4 text-lg">Resources</h6>
            <ul className="space-y-2 text-white/80">
              <li><a href="#education" className="hover:text-white transition-colors">Security Education</a></li>
              <li><a href="#education" className="hover:text-white transition-colors">Threat Intelligence</a></li>
              <li><a href="#education" className="hover:text-white transition-colors">Best Practices</a></li>
              <li><a href="#about" className="hover:text-white transition-colors">About PhishGuard</a></li>
            </ul>
          </div>
          
          <div>
            <h6 className="font-bold mb-4 text-lg">Contact</h6>
            <ul className="space-y-2 text-white/80">
              <li><a href="#" className="hover:text-white transition-colors">Report Phishing</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Support</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Privacy Policy</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Terms of Service</a></li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-white/20 mt-8 pt-8 text-center text-white/80">
          <p>© 2024 PhishGuard. All rights reserved. Protecting users worldwide from cyber threats.</p>
        </div>
      </div>
    </footer>
  )
}

export default Footer