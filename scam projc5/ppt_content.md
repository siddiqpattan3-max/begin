# PPT Content - Cyber Scam & Phishing Detector

## Slide 1: Title Slide
```
==================================
    CYBER SCAM & PHISHING
         DETECTOR
==================================
    
    A C Programming Project
    
    First Year Engineering
    
    [Your Name]
    [College Name]
```

## Slide 2: Problem Statement
```
==================================
       PROBLEM STATEMENT
==================================

• Rising cyber attacks globally
• 3.4 billion phishing emails sent daily
• 75% of organizations experienced
  phishing attacks in 2023
• Financial losses in billions of $
• Traditional users can't identify
  sophisticated phishing attempts

Need: Automated detection tool
```

## Slide 3: Project Objectives
```
==================================
        OBJECTIVES
==================================

✓ Detect phishing in SMS, WhatsApp, 
  emails, and texts
✓ Analyze using 50+ scam keywords
✓ Detect suspicious patterns
  - URLs, emails, phone numbers
  - ALL CAPS, excessive punctuation
  - Currency symbols
✓ Calculate risk score (0-100)
✓ Provide safety advice
✓ Save and view analysis reports
```

## Slide 4: Methodology
```
==================================
        METHODOLOGY
==================================

INPUT: User pastes a message
       │
       ▼
Convert to Lowercase
       │
       ▼
Search 50+ Keywords
  (OTP, Password, Bank, etc.)
       │
       ▼
Detect Patterns
  (URLs, Phones, Emails, etc.)
       │
       ▼
Calculate Risk Score (0-100)
       │
       ▼
Determine Risk Level
  (LOW / MEDIUM / HIGH)
       │
       ▼
Generate Safety Advice
       │
       ▼
Display Results + Save Report
```

## Slide 5: Technology Used
```
==================================
     TECHNOLOGY STACK
==================================

Language:
  • C Programming (C11 Standard)

Key Libraries:
  • stdio.h  - Input/Output
  • stdlib.h - Memory/Screen
  • string.h - String operations
  • ctype.h  - Character analysis
  • time.h   - Date/Time functions
  • conio.h  - Console I/O
  • windows.h - Color support

Tools:
  • GCC/Clang Compiler
  • VS Code / Dev-C++ IDE
  • Windows Terminal
```

## Slide 6: Key Features - Part 1
```
==================================
    KEY FEATURES (Part 1)
==================================

1. HOME MENU
   - Professional ASCII UI
   - 5 Menu Options
   - Color-coded output

2. MESSAGE ANALYSIS
   - Multi-line input support
   - Case-insensitive search
   - Real-time analysis

3. KEYWORD DETECTION (50+)
   - OTP, Password, Bank, UPI
   - Lottery, Winner, Free
   - Urgent, KYC, QR Code
   - Each with weighted risk score
```

## Slide 7: Key Features - Part 2
```
==================================
    KEY FEATURES (Part 2)
==================================

4. PATTERN DETECTION
   • http:// and https:// URLs
   • www. links
   • 3+ exclamation marks
   • ALL CAPS words
   • Currency symbols ($€£₹)
   • Phone numbers (10+ digits)
   • Email addresses
   • Phishing greetings

5. RISK CALCULATION
   0-30:  LOW RISK (Safe)
   31-60: MEDIUM RISK (Suspicious)
   61-100: HIGH RISK (Scam)
```

## Slide 8: Key Features - Part 3
```
==================================
    KEY FEATURES (Part 3)
==================================

6. FILE HANDLING
   - Automatic save to reports.txt
   - Append mode (no data loss)
   - Read and display past reports

7. SCAM STATISTICS
   - Total messages analyzed
   - Risk level distribution
   - Percentage calculations
   - Visual bar chart

8. HELP PAGE
   - What is Phishing?
   - Types of Scams
   - 15 Cybersecurity Tips
   - About this Detector
```

## Slide 9: C Concepts Used
```
==================================
     C CONCEPTS IMPLEMENTED
==================================

┌─────────────────────────────┐
│ 1. Functions (22 functions) │
│ 2. Arrays (keyword list)    │
│ 3. Strings (message)        │
│ 4. Structures (Message,     │
│    Statistics)              │
│ 5. File Handling (reports)  │
│ 6. Pointers (*msg)          │
│ 7. Loops (for, while)       │
│ 8. Switch-Case (menu)       │
│ 9. Searching (strstr)       │
│10. String Functions (strcpy,│
│    strcat, strncpy, etc.)   │
└─────────────────────────────┘
```

## Slide 10: Keyword Risk Scores
```
==================================
   KEYWORD RISK SCORES (Sample)
==================================

KEYWORD           SCORE
──────────────────────────
OTP                 30
Password            40
Account Blocked     30
Click Here          20
Lottery             25
Winner              25
Credit Card         25
Debit Card          25
QR Code             20
Refund              20
Security Alert      25
Suspicious Activity 25
URGENT              15
KYC                 20
Bank                10
Login               15
UPI                 15
Payment             15
Scan                20
Link                10
```

## Slide 11: Code Structure
```
==================================
     CODE STRUCTURE
==================================

main.c (500+ lines)
│
├── Structures
│   ├── Message
│   └── Statistics
│
├── Menu Functions (5)
│   ├── displayHomeMenu()
│   ├── analyzeMessage()
│   ├── viewPreviousReports()
│   ├── viewScamStatistics()
│   └── displayHelp()
│
├── Analysis Functions (7)
│   ├── convertToLowercase()
│   ├── searchSuspiciousKeywords()
│   ├── detectPatterns()
│   ├── calculateRiskScore()
│   ├── determineRiskLevel()
│   ├── generateSafetyAdvice()
│   └── displayResults()
│
├── File Handling (3)
│   ├── saveReport()
│   ├── loadReports()
│   └── isValidMessage()
│
└── Utility Functions (10+)
    └── clearInputBuffer(), etc.
```

## Slide 12: Sample Analysis - LOW RISK
```
==================================
   SAMPLE: LOW RISK MESSAGE
==================================

INPUT:
  "Hi, shall we meet at 5pm?"

OUTPUT:
  Risk Score: 0/100
  Risk Level: LOW RISK
  Keywords: None
  Advice: Message appears safe

RESULT: SAFE - No scam detected
```

## Slide 13: Sample Analysis - HIGH RISK
```
==================================
   SAMPLE: HIGH RISK MESSAGE
==================================

INPUT:
  "URGENT! Your bank account is 
  blocked! Click here to verify 
  KYC: http://fake-bank.com"

OUTPUT:
  Risk Score: 85/100
  Risk Level: HIGH RISK 🔴
  Keywords: bank, urgent, 
            account blocked, 
            click here, verify, 
            kyc, http:// link
  Advice: SCAM! Do not respond!

RESULT: DANGEROUS - Phishing scam!
```

## Slide 14: Advantages & Limitations
```
==================================
  ADVANTAGES & LIMITATIONS
==================================

ADVANTAGES:
✓ Real-time message analysis
✓ No internet required
✓ Comprehensive keyword list
✓ Pattern-based detection
✓ User-friendly interface
✓ Cross-platform (Windows)
✓ Educational tool

LIMITATIONS:
✗ Cannot analyze images
✗ No machine learning
✗ English only
✗ Static keyword list
✗ No URL verification
```

## Slide 15: Future Enhancements
```
==================================
    FUTURE ENHANCEMENTS
==================================

🔹 Machine Learning Integration
   - Train on real scam datasets
   - Adaptive scoring

🔹 API Integration
   - VirusTotal URL check
   - Real-time threat intelligence

🔹 Multi-Language Support
   - Hindi, Spanish, Arabic, etc.

🔹 GUI Version
   - Graphical User Interface
   - Cross-platform (Qt/Tkinter)

🔹 Browser Extension
   - Real-time email scanning
   - Website phishing detection

🔹 Mobile App
   - Android/iOS SMS scanner
```

## Slide 16: Conclusion
```
==================================
        CONCLUSION
==================================

✓ Successfully developed a C program
  to detect cyber scams & phishing

✓ 50+ keywords with weighted scores
✓ 10+ pattern detection techniques
✓ Risk-based classification
✓ File storage & statistics
✓ Professional UI with colors

IMPACT:
  Helps users identify scams before
  falling victim to cyber attacks

"Stay Safe, Stay Vigilant!"
```

## Slide 17: Thank You
```
==================================
        THANK YOU
==================================

    CYBER SCAM & PHISHING
         DETECTOR

    Questions & Answers

    [Your Name]
    [College Name]
    [Email]

==================================
```

