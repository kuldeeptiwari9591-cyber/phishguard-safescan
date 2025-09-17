import { useState, useEffect } from "react"
import { ChevronLeft, ChevronRight, RefreshCw, Award, Brain } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { GradientButton } from "./ui/gradient-button"
import { Button } from "./ui/button"
import { Progress } from "./ui/progress"
import { getRandomQuestions, type QuizQuestion } from "@/data/quizQuestions"
import { useToast } from "@/hooks/use-toast"

const QuizSection = () => {
  const [questions, setQuestions] = useState<QuizQuestion[]>([])
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0)
  const [userAnswers, setUserAnswers] = useState<number[]>([])
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null)
  const [quizCompleted, setQuizCompleted] = useState(false)
  const [score, setScore] = useState(0)
  const [showExplanation, setShowExplanation] = useState(false)

  const { toast } = useToast()

  useEffect(() => {
    initializeQuiz()
  }, [])

  const initializeQuiz = () => {
    const randomQuestions = getRandomQuestions(5)
    setQuestions(randomQuestions)
    setCurrentQuestionIndex(0)
    setUserAnswers(new Array(5).fill(-1))
    setSelectedAnswer(null)
    setQuizCompleted(false)
    setScore(0)
    setShowExplanation(false)
  }

  const handleAnswerSelect = (answerIndex: number) => {
    setSelectedAnswer(answerIndex)
    const newAnswers = [...userAnswers]
    newAnswers[currentQuestionIndex] = answerIndex
    setUserAnswers(newAnswers)
  }

  const nextQuestion = () => {
    if (selectedAnswer === null) {
      toast({
        title: "Please select an answer",
        description: "Choose an option before proceeding",
        variant: "destructive"
      })
      return
    }

    if (showExplanation) {
      setShowExplanation(false)
      if (currentQuestionIndex === questions.length - 1) {
        finishQuiz()
      } else {
        setCurrentQuestionIndex(currentQuestionIndex + 1)
        setSelectedAnswer(userAnswers[currentQuestionIndex + 1] !== -1 ? userAnswers[currentQuestionIndex + 1] : null)
      }
    } else {
      setShowExplanation(true)
    }
  }

  const previousQuestion = () => {
    if (showExplanation) {
      setShowExplanation(false)
    } else if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(currentQuestionIndex - 1)
      setSelectedAnswer(userAnswers[currentQuestionIndex - 1] !== -1 ? userAnswers[currentQuestionIndex - 1] : null)
      setShowExplanation(false)
    }
  }

  const finishQuiz = () => {
    const finalScore = userAnswers.reduce((acc, answer, index) => {
      return acc + (answer === questions[index]?.correct ? 1 : 0)
    }, 0)
    
    setScore(finalScore)
    setQuizCompleted(true)
    
    toast({
      title: "Quiz Complete!",
      description: `You scored ${finalScore} out of ${questions.length}`,
      variant: finalScore >= 4 ? "default" : "destructive"
    })
  }

  const restartQuiz = () => {
    initializeQuiz()
  }

  const getScoreMessage = () => {
    const percentage = (score / questions.length) * 100
    if (percentage >= 80) {
      return 'Excellent! You have strong phishing detection skills.'
    } else if (percentage >= 60) {
      return 'Good job! Consider reviewing phishing detection techniques.'
    } else {
      return 'Keep learning! Regular practice will improve your security awareness.'
    }
  }

  const getAnswerClassName = (optionIndex: number) => {
    if (!showExplanation) {
      if (selectedAnswer === optionIndex) {
        return 'bg-primary/20 border-primary'
      }
      return 'hover:bg-muted/50 cursor-pointer'
    } else {
      if (optionIndex === questions[currentQuestionIndex]?.correct) {
        return 'bg-safe/20 border-safe text-safe-foreground'
      } else if (selectedAnswer === optionIndex && optionIndex !== questions[currentQuestionIndex]?.correct) {
        return 'bg-danger/20 border-danger text-danger-foreground'
      }
      return 'opacity-60'
    }
  }

  if (questions.length === 0) {
    return <div className="flex justify-center py-16"><RefreshCw className="h-8 w-8 animate-spin" /></div>
  }

  return (
    <section id="quiz" className="py-16 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12 animate-fade-in">
          <h3 className="text-4xl font-bold mb-4 bg-gradient-primary bg-clip-text text-transparent">
            Test Your Knowledge
          </h3>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Challenge yourself with our interactive phishing detection quiz. Questions change on each attempt!
          </p>
        </div>
        
        <div className="max-w-4xl mx-auto">
          <Card className="shadow-card-hover hover:shadow-glow transition-all duration-300 animate-fade-in">
            {!quizCompleted ? (
              <>
                <CardHeader>
                  <div className="flex justify-between items-center mb-4">
                    <span className="text-sm font-semibold text-muted-foreground">
                      Question {currentQuestionIndex + 1} of {questions.length}
                    </span>
                    <span className="text-sm font-semibold text-muted-foreground">
                      Score: {userAnswers.filter((answer, index) => answer === questions[index]?.correct).length}
                    </span>
                  </div>
                  <Progress 
                    value={((currentQuestionIndex + 1) / questions.length) * 100} 
                    className="mb-6"
                  />
                  <CardTitle className="text-xl">
                    <Brain className="h-6 w-6 mr-3 text-primary inline" />
                    {questions[currentQuestionIndex]?.question}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  {!showExplanation ? (
                    <div className="space-y-3">
                      {questions[currentQuestionIndex]?.options.map((option, index) => (
                        <div
                          key={index}
                          onClick={() => handleAnswerSelect(index)}
                          className={`p-4 border rounded-lg transition-all ${getAnswerClassName(index)}`}
                        >
                          <label className="flex items-center space-x-3 cursor-pointer w-full">
                            <input
                              type="radio"
                              name="quizOption"
                              value={index}
                              checked={selectedAnswer === index}
                              onChange={() => handleAnswerSelect(index)}
                              className="text-primary focus:ring-primary"
                            />
                            <span className="flex-1">{option}</span>
                          </label>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-6">
                      <div className="space-y-3">
                        {questions[currentQuestionIndex]?.options.map((option, index) => (
                          <div
                            key={index}
                            className={`p-4 border rounded-lg transition-all ${getAnswerClassName(index)}`}
                          >
                            <div className="flex items-center space-x-3">
                              <input
                                type="radio"
                                name="quizOption"
                                value={index}
                                checked={selectedAnswer === index}
                                readOnly
                                className="text-primary"
                              />
                              <span className="flex-1">{option}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                      
                      <Card className="bg-muted/50 border-l-4 border-l-primary">
                        <CardContent className="pt-6">
                          <h4 className="font-bold text-foreground mb-2">Explanation:</h4>
                          <p className="text-muted-foreground">{questions[currentQuestionIndex]?.explanation}</p>
                        </CardContent>
                      </Card>
                    </div>
                  )}
                  
                  <div className="flex justify-between">
                    <Button
                      onClick={previousQuestion}
                      disabled={currentQuestionIndex === 0 && !showExplanation}
                      variant="outline"
                    >
                      <ChevronLeft className="h-4 w-4 mr-2" />
                      Previous
                    </Button>
                    <GradientButton onClick={nextQuestion}>
                      {showExplanation ? (
                        currentQuestionIndex === questions.length - 1 ? 'Finish Quiz' : 'Next Question'
                      ) : 'Show Answer'}
                      <ChevronRight className="h-4 w-4 ml-2" />
                    </GradientButton>
                  </div>
                </CardContent>
              </>
            ) : (
              <CardContent className="text-center py-12">
                <div className="animate-fade-in">
                  <Award className="h-16 w-16 mx-auto mb-6 text-primary" />
                  <h4 className="text-3xl font-bold mb-4">Quiz Complete!</h4>
                  <div className="text-6xl font-bold mb-4 bg-gradient-primary bg-clip-text text-transparent">
                    {score}/{questions.length}
                  </div>
                  <p className="text-lg text-muted-foreground mb-8 max-w-md mx-auto">
                    {getScoreMessage()}
                  </p>
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                      <Card className="p-4">
                        <div className="text-2xl font-bold text-primary">{Math.round((score / questions.length) * 100)}%</div>
                        <div className="text-sm text-muted-foreground">Score</div>
                      </Card>
                      <Card className="p-4">
                        <div className="text-2xl font-bold text-safe">{score}</div>
                        <div className="text-sm text-muted-foreground">Correct</div>
                      </Card>
                      <Card className="p-4">
                        <div className="text-2xl font-bold text-danger">{questions.length - score}</div>
                        <div className="text-sm text-muted-foreground">Incorrect</div>
                      </Card>
                    </div>
                    <GradientButton onClick={restartQuiz} size="lg">
                      <RefreshCw className="h-5 w-5 mr-2" />
                      Take Quiz Again
                    </GradientButton>
                  </div>
                </div>
              </CardContent>
            )}
          </Card>
        </div>
      </div>
    </section>
  )
}

export default QuizSection