# PhishGuard - Advanced Phishing Detection Tool

PhishGuard is a comprehensive phishing detection web application that analyzes URLs using 36+ security features and real-time threat intelligence APIs.

## Features

- **36+ Security Features**: Comprehensive URL analysis including protocol security, domain analysis, suspicious patterns, and more
- **Real-time Threat Intelligence**: Integration with Google Safe Browsing and VirusTotal APIs
- **History Tracking**: Keeps track of the 5 most recent URL analyses
- **Interactive Quiz**: Educational phishing awareness quiz with 30+ questions
- **Modern UI**: Clean, responsive design with dark theme

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd phishguard
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:5000`

## Usage

### URL Analysis
1. Enter a URL in the input field on the main page
2. Click "Analyze URL" to perform comprehensive security analysis
3. View detailed results including risk score, warnings, and feature analysis
4. Check the history section to see your 5 most recent analyses

### Educational Quiz
1. Scroll down to the "Test Your Knowledge" section
2. Click "Start Quiz" to begin the phishing awareness quiz
3. Answer 5 randomly selected questions from a pool of 30+
4. Get your score and detailed explanations for each answer

## API Endpoints

- `POST /api/analyze-url` - Analyze a URL for phishing indicators
- `GET /api/history` - Get analysis history
- `GET /api/health` - Health check endpoint
- `GET /api/stats` - Get API statistics

## Security Features Analyzed

1. **Protocol Security**: HTTPS usage, mixed content detection
2. **URL Structure**: Length analysis, suspicious characters, encoding
3. **Domain Analysis**: Subdomains, TLD analysis, typosquatting detection
4. **Content Analysis**: Parameter analysis, Base64 detection
5. **Threat Intelligence**: Real-time API checks against known threats
6. **Pattern Recognition**: Suspicious keywords, brand impersonation
7. **And 30+ more advanced security checks**

## API Integration

The application integrates with the following threat intelligence APIs:

- **Google Safe Browsing API**: Real-time malicious URL detection
- **VirusTotal API**: Multi-engine malware and phishing detection
- **WHOIS API**: Domain registration information analysis

## File Structure

```
phishguard/
├── index.html          # Main HTML interface
├── style.css           # Styling and UI design
├── script.js           # Frontend logic and quiz system
├── feature_script.js   # Client-side URL feature analysis
├── app.py              # Flask backend server
├── feature_extractor.py# Advanced server-side analysis
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Technologies Used

- **Backend**: Python, Flask, Flask-CORS
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **APIs**: Google Safe Browsing, VirusTotal, WHOIS
- **Security**: Real-time threat intelligence, 36+ detection features

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Disclaimer

PhishGuard is an educational and security tool. While it provides comprehensive analysis using industry-standard techniques and APIs, no security tool is 100% accurate. Always exercise caution when clicking links or providing personal information online.

## Support

For issues, questions, or contributions, please create an issue in the repository or contact the development team.