import Header from "../components/Header"
import HeroSection from "../components/HeroSection"
import DetectionCenter from "../components/DetectionCenter"
import EducationSection from "../components/EducationSection"
import QuizSection from "../components/QuizSection"
import AboutSection from "../components/AboutSection"
import Footer from "../components/Footer"

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <HeroSection />
      <DetectionCenter />
      <EducationSection />
      <QuizSection />
      <AboutSection />
      <Footer />
    </div>
  );
};

export default Index;
