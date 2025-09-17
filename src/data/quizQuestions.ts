export interface QuizQuestion {
  question: string
  options: string[]
  correct: number
  explanation: string
}

export const allQuizQuestions: QuizQuestion[] = [
  {
    question: "Which of the following is a common sign of a phishing email?",
    options: [
      "Personalized greeting with your full name",
      "Urgent language demanding immediate action",
      "Professional email signature",
      "Clear and proper grammar"
    ],
    correct: 1,
    explanation: "Phishing emails often use urgent language to pressure victims into acting quickly without thinking."
  },
  {
    question: "What should you do before clicking on a link in an email?",
    options: [
      "Click immediately if it looks legitimate",
      "Forward it to friends first",
      "Hover over the link to see the actual URL",
      "Reply to the sender asking if it's real"
    ],
    correct: 2,
    explanation: "Always hover over links to preview the destination URL before clicking to verify legitimacy."
  },
  {
    question: "Which URL is most likely to be a phishing attempt?",
    options: [
      "https://www.paypal.com/login",
      "https://paypal-security-update.com",
      "https://secure.paypal.com",
      "https://www.paypal.com/security"
    ],
    correct: 1,
    explanation: "The second URL uses a different domain that mimics PayPal but isn't the official site."
  },
  {
    question: "What is the best way to verify a suspicious email from your bank?",
    options: [
      "Click the link in the email",
      "Reply to the email with your account details",
      "Call your bank directly using a known phone number",
      "Forward the email to your friends"
    ],
    correct: 2,
    explanation: "Always verify through independent channels like calling your bank directly using official contact information."
  },
  {
    question: "Which of these is NOT a good practice for email security?",
    options: [
      "Using two-factor authentication",
      "Keeping software updated",
      "Opening all attachments to check them",
      "Being skeptical of unexpected emails"
    ],
    correct: 2,
    explanation: "Never open unexpected attachments as they may contain malware. Always verify with the sender first."
  },
  {
    question: "What makes a password strong and secure?",
    options: [
      "Using only lowercase letters",
      "Using your birthdate",
      "Combining uppercase, lowercase, numbers, and symbols",
      "Using the same password for all accounts"
    ],
    correct: 2,
    explanation: "Strong passwords combine multiple character types and are unique for each account."
  },
  {
    question: "If you receive an email asking for your social security number, you should:",
    options: [
      "Provide it immediately if the email looks official",
      "Never provide it via email",
      "Only provide the last 4 digits",
      "Ask for their phone number first"
    ],
    correct: 1,
    explanation: "Legitimate organizations never ask for sensitive information like SSN via email."
  },
  {
    question: "What is 'typosquatting' in the context of phishing?",
    options: [
      "Typing errors in phishing emails",
      "Creating fake websites with URLs similar to legitimate ones",
      "Using voice recognition to steal passwords",
      "Sending multiple emails quickly"
    ],
    correct: 1,
    explanation: "Typosquatting involves registering domains similar to legitimate sites to trick users."
  },
  {
    question: "Which of these email subjects is most likely to be phishing?",
    options: [
      "Your monthly newsletter",
      "URGENT: Your account will be closed in 24 hours!",
      "Meeting scheduled for tomorrow",
      "Thank you for your purchase"
    ],
    correct: 1,
    explanation: "Urgent, threatening language is a classic phishing tactic to create panic."
  },
  {
    question: "What should you do if you accidentally clicked on a phishing link?",
    options: [
      "Ignore it and hope nothing happens",
      "Immediately change your passwords and run antivirus scan",
      "Wait and see what happens",
      "Only change passwords if you notice problems"
    ],
    correct: 1,
    explanation: "Immediate action is crucial: change passwords, scan for malware, and monitor accounts."
  },
  {
    question: "Which type of information should you NEVER share via email?",
    options: [
      "Your favorite color",
      "Meeting availability",
      "Credit card numbers",
      "Your job title"
    ],
    correct: 2,
    explanation: "Financial information like credit card numbers should never be shared via email."
  },
  {
    question: "What is 'vishing'?",
    options: [
      "Video phishing attacks",
      "Voice/phone phishing attacks",
      "Virtual reality phishing",
      "Visual phishing with images"
    ],
    correct: 1,
    explanation: "Vishing is voice phishing - fraudulent phone calls attempting to steal information."
  },
  {
    question: "How can you identify a legitimate website?",
    options: [
      "It has lots of colorful graphics",
      "It uses HTTPS and has proper spelling",
      "It asks for all your personal information",
      "It has pop-up advertisements"
    ],
    correct: 1,
    explanation: "Legitimate sites use HTTPS encryption and maintain professional standards."
  },
  {
    question: "What is two-factor authentication (2FA)?",
    options: [
      "Using two different passwords",
      "Logging in twice",
      "An extra security step beyond just a password",
      "Having two email accounts"
    ],
    correct: 2,
    explanation: "2FA adds an extra layer of security requiring something you know and something you have."
  },
  {
    question: "If an email claims to be from a company but comes from a Gmail address, you should:",
    options: [
      "Trust it because Gmail is secure",
      "Be suspicious as companies use their own email domains",
      "Reply immediately",
      "Forward it to others"
    ],
    correct: 1,
    explanation: "Legitimate companies use their own email domains, not free services like Gmail."
  },
  {
    question: "What is 'spear phishing'?",
    options: [
      "Phishing with fishing metaphors",
      "Highly targeted phishing attacks",
      "Phishing using spear-shaped graphics",
      "Phishing that happens very quickly"
    ],
    correct: 1,
    explanation: "Spear phishing involves highly targeted, personalized attacks on specific individuals."
  },
  {
    question: "Which browser security feature helps protect against phishing?",
    options: [
      "Auto-fill passwords",
      "Private browsing mode",
      "Phishing and malware protection",
      "Multiple tabs"
    ],
    correct: 2,
    explanation: "Modern browsers have built-in phishing and malware protection that warns about dangerous sites."
  },
  {
    question: "What should you do if you receive an unexpected prize notification email?",
    options: [
      "Claim the prize immediately",
      "Share it with friends",
      "Be extremely skeptical and verify independently",
      "Provide personal information to claim it"
    ],
    correct: 2,
    explanation: "Unexpected prize notifications are common phishing tactics. Always verify independently."
  },
  {
    question: "How often should you update your passwords?",
    options: [
      "Never, if they're strong",
      "Every few years",
      "Regularly, especially after security breaches",
      "Only when you forget them"
    ],
    correct: 2,
    explanation: "Regular password updates, especially after breaches, help maintain security."
  },
  {
    question: "What is 'pharming'?",
    options: [
      "Phishing on farms",
      "Redirecting users to fake websites without their knowledge",
      "Farming personal data",
      "Growing phishing attacks"
    ],
    correct: 1,
    explanation: "Pharming redirects users to fraudulent sites even when they type the correct URL."
  },
  {
    question: "If you're unsure about an email's legitimacy, you should:",
    options: [
      "Click all links to investigate",
      "Delete it immediately without reading",
      "Verify through official channels before taking action",
      "Forward it to see what others think"
    ],
    correct: 2,
    explanation: "When in doubt, always verify through official, independent channels before taking any action."
  },
  {
    question: "What makes public Wi-Fi dangerous for sensitive activities?",
    options: [
      "It's slower than private networks",
      "Data can be intercepted by attackers",
      "It costs money to use",
      "It has limited bandwidth"
    ],
    correct: 1,
    explanation: "Public Wi-Fi networks are unsecured, allowing attackers to intercept data transmissions."
  },
  {
    question: "Which of these is a sign of a secure website?",
    options: [
      "HTTP in the URL",
      "Pop-up advertisements",
      "HTTPS and a padlock icon",
      "Requests for passwords via email"
    ],
    correct: 2,
    explanation: "HTTPS and the padlock icon indicate encrypted, secure connections."
  },
  {
    question: "What should you do if your email account is compromised?",
    options: [
      "Wait and see what happens",
      "Change password, enable 2FA, and notify contacts",
      "Create a new email address",
      "Stop using email"
    ],
    correct: 1,
    explanation: "Immediate action includes changing passwords, enabling 2FA, and warning your contacts."
  },
  {
    question: "Why do phishers often create a sense of urgency?",
    options: [
      "To be helpful and save time",
      "To prevent victims from thinking carefully",
      "Because they're actually urgent situations",
      "To show they care about security"
    ],
    correct: 1,
    explanation: "Urgency prevents careful analysis and leads to hasty, poor decisions."
  }
]

// Function to get random questions for the quiz
export function getRandomQuestions(count: number = 5): QuizQuestion[] {
  const shuffled = [...allQuizQuestions].sort(() => Math.random() - 0.5)
  return shuffled.slice(0, count)
}