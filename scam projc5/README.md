# Cyber Scam & Phishing Detector

A professional C programming project designed to detect phishing attempts and cyber scams in SMS messages, WhatsApp messages, emails, and text messages using keyword and pattern matching techniques.

## 🚀 Features

### 1. Home Menu
- Professional ASCII-styled interface
- 5 menu options with color-coded output
- Input validation and error handling

### 2. Message Analysis
- Multi-line message input support
- Case-insensitive keyword search
- Real-time risk analysis
- Comprehensive result display

### 3. Keyword Detection (50+ Keywords)
- Weighted risk scores for each keyword
- Categories: Financial, Urgency, Prize/Scams, Security, Phishing
- Examples: OTP=30, Password=40, Lottery=25, Bank=10

### 4. Pattern Detection
| Pattern | Score |
|---------|-------|
| http:// URLs | +20 |
| https:// URLs | +15 |
| www. links | +10 |
| 3+ Exclamation Marks | +3 each |
| ALL CAPS Words | +5 each |
| Currency Symbols ($€£₹) | +8 each |
| Phone Numbers (10+ digits) | +15 |
| Email Addresses | +15 |
| Phishing Greetings | +10 |

### 5. Risk Classification
| Score Range | Risk Level | Color |
|-------------|------------|-------|
| 0-30 | LOW RISK | Green |
| 31-60 | MEDIUM RISK | Yellow |
| 61-100 | HIGH RISK | Red |

### 6. File Handling
- Automatic save to `reports.txt` (append mode)
- Load and display previous reports
- Persistent data storage

### 7. Scam Statistics
- Total messages analyzed
- Count and percentage by risk level
- Visual bar chart representation

### 8. Help & Information
- What is Phishing? (Educational content)
- Types of Cyber Scams
- 15 Cybersecurity Tips
- About the Detector tool

## 📋 Requirements

### Hardware
- Processor: Intel Pentium or higher
- RAM: 512 MB minimum
- Storage: 10 MB free space

### Software
- Operating System: Windows 7/8/10/11
- C Compiler: GCC (MinGW), Turbo C, or MSVC
- IDE: VS Code, Dev-C++, Code::Blocks (optional)

## 🔧 Installation & Compilation

### Using GCC (MinGW):
```bash
gcc main.c -o scam_detector.exe
```

### Using MSVC (Visual Studio):
```bash
cl main.c
```

### Using Turbo C++:
1. Open Turbo C
2. File → Open → main.c
3. Compile → Build
4. Run

## 🎮 Usage

1. **Compile** the program using any C compiler
2. **Run** the executable
3. The main menu will display with 5 options:
   - **1. Analyze Message** - Enter a message to analyze
   - **2. View Previous Reports** - View saved analysis reports
   - **3. View Scam Statistics** - View aggregate statistics
   - **4. Help** - Educational information about scams
   - **5. Exit** - Quit the program
4. Follow on-screen prompts

### Example Message Analysis
```
Enter message: "URGENT! Your bank account is blocked. 
Click here to verify KYC: http://fake-bank.com"

Result: HIGH RISK (Score: 85/100)
Keywords: bank, urgent, account blocked, click here, http://
Advice: This appears to be a SCAM. Do not respond!
```

## 📁 Project Structure

```
scam_projc5/
├── main.c                  # Complete C source code (500+ lines)
├── algorithm.md            # Detailed algorithm documentation
├── flowchart.md            # Program flowcharts
├── sample_output.md        # Sample output examples
├── function_explanations.md # All 22 functions explained
├── viva_questions.md       # 25+ viva questions with answers
├── ppt_content.md          # 17-slide presentation content
├── project_report.md       # Complete project report
├── README.md               # This file
├── TODO.md                 # Progress tracker
└── reports.txt             # Generated analysis reports
```

## 🛠️ C Concepts Used

| Concept | Implementation |
|---------|---------------|
| Functions | 22 modular functions |
| Arrays | Keyword list, string buffers |
| Strings | Message handling, analysis |
| Structures | Message, Statistics |
| File Handling | read/write reports.txt |
| Pointers | Function parameters |
| Loops | for, while iterations |
| Switch-Case | Menu navigation |
| Searching | strstr() keyword matching |
| String Functions | strcpy, strcat, strlen, strncpy, snprintf |

## 🧪 Test Cases

### Test 1: Phishing Email
```
Input: "Dear Customer, your account is blocked. Click here: http://bit.ly/verify"
Expected: HIGH RISK (85+)
```

### Test 2: Normal Message
```
Input: "Hey, how was your day?"
Expected: LOW RISK (0-10)
```

### Test 3: Lottery Scam
```
Input: "CONGRATULATIONS! You won $1,000,000! Claim now!"
Expected: HIGH RISK (70+)
```

## ⚠️ Limitations

- English language only
- No image/attachment analysis
- Static keyword list (no ML)
- Windows-specific color support
- No URL reputation checking

## 🚀 Future Enhancements

- [ ] Machine learning integration
- [ ] Multi-language support
- [ ] GUI interface
- [ ] Browser extension
- [ ] Mobile app version
- [ ] API-based URL verification
- [ ] Real-time email scanning

## 👨‍💻 Team CyberShield

| Name | Role |
|------|------|
| **Abubacker Siddik** | Team Lead & Developer |
| **Azim Sunderwal** | Developer & Tester |
| **Muhammed Yousuf** | Developer & Documentation |

**Course:** First Year Engineering  
**Project:** Cyber Scam & Phishing Detector (C Programming)

## 📄 License

This project is for educational purposes as a first-year engineering C programming project.

## 🙏 Acknowledgments

- C Programming Language (Kernighan & Ritchie)
- Cybersecurity standards and best practices
- Open source C compiler tools

---

**Stay Safe, Stay Vigilant!** 🔒

