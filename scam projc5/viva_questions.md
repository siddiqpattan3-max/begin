# Viva Questions & Answers - Cyber Scam & Phishing Detector

## Basic Level Questions

### Q1: What is the purpose of this project?
**Answer:** This project aims to develop a C program that analyzes SMS messages, WhatsApp messages, emails, and text messages to detect possible cyber scams and phishing attempts using keyword and pattern matching techniques.

### Q2: What programming language is used?
**Answer:** The entire project is written in the C programming language.

### Q3: What are the main features of this program?
**Answer:** 
1. Home menu with 5 options
2. Message analysis with keyword detection
3. Pattern detection (URLs, emails, phones, etc.)
4. Risk calculation (LOW/MEDIUM/HIGH)
5. File handling (save/load reports)
6. Scam statistics
7. Help page with cybersecurity information
8. Color-coded terminal output

### Q4: What C concepts are used in this project?
**Answer:**
- Functions (modular programming)
- Arrays (keyword list, strings)
- Strings (message handling)
- Structures (Message, Statistics)
- File Handling (fopen, fprintf, fgets)
- Pointers (function parameters)
- Loops (for, while)
- Switch-case (menu handling)
- Searching (strstr for keyword matching)
- String functions (strcpy, strcat, strlen, strncpy)

### Q5: How is the risk score calculated?
**Answer:** The risk score starts at 0 and increases based on:
1. Detected keywords (each has a predefined score: OTP=30, Password=40, etc.)
2. Detected patterns (URLs, emails, phones, etc.)
3. The final score is clamped between 0-100.

---

## Intermediate Level Questions

### Q6: Explain the Message structure.
**Answer:**
```c
typedef struct {
    char date[20];           // Analysis date
    char time[20];           // Analysis time
    char originalMsg[1000];  // Original user message
    char lowerMsg[1000];     // Lowercase version
    int riskScore;           // Calculated risk score (0-100)
    char riskLevel[15];       // LOW/MEDIUM/HIGH risk
    char detectedKeywords[20][50]; // Detected keywords
    int keywordCount;        // Number of keywords found
    char reasons[20][100];   // Reasons for risk score
    int reasonCount;         // Number of reasons
    char safetyAdvice[10][100]; // Safety tips
    int adviceCount;         // Number of advice items
} Message;
```

### Q7: How does the keyword detection work?
**Answer:** The program maintains an array of 50 predefined keywords with associated risk scores. It converts the user's message to lowercase and uses strstr() to search for each keyword. When found, the keyword is added to the detected list, its score is added to the total, and a reason string is generated.

### Q8: What patterns are detected and how?
**Answer:**
1. **http://** - String matching (+20)
2. **https://** - String matching (+15)
3. **www.** - String matching (+10)
4. **Excessive !!!** - Count consecutive exclamation marks (+3 each)
5. **ALL CAPS words** - Check if word is fully uppercase (+5 each)
6. **Currency symbols** - Search for $€£₹¥ (+8 each)
7. **Phone numbers** - Count 10+ consecutive digits (+15)
8. **Email addresses** - Check for @ with domain (.com/.in/.org/.net) (+15)
9. **Phishing greetings** - "dear customer", "dear user", etc. (+10)

### Q9: Explain the file handling mechanism.
**Answer:** The program uses:
- **saveReport()**: Opens "reports.txt" in append mode ("a") and writes all analysis data including date, time, score, level, message, keywords, reasons, and advice.
- **loadReports()**: Opens "reports.txt" in read mode ("r"), parses it line by line, identifies sections using header strings, and populates Message structures.

### Q10: How are statistics calculated?
**Answer:** The program loads all reports, categorizes each by risk level (HIGH/MEDIUM/LOW), counts them, calculates percentages, and displays a visual bar chart using '#' characters.

---

## Advanced Level Questions

### Q11: How does the program prevent buffer overflow?
**Answer:**
1. Using strncpy() instead of strcpy() with explicit length limits
2. Using strncat() instead of strcat()
3. Checking array bounds before adding elements (keywordCount < 20)
4. Using sizeof() in string operations
5. Limiting input message to MAX_MESSAGE_LENGTH (1000)
6. Using snprintf() for formatted strings with size limits

### Q12: How does the program handle invalid input?
**Answer:**
1. Checks if scanf() returns the expected number of items
2. clearInputBuffer() removes leftover characters from stdin
3. isValidMessage() checks if message contains non-space characters
4. Menu input validation shows error for non-numeric or out-of-range input
5. Message input validation rejects empty messages

### Q13: What is the time complexity of the keyword search?
**Answer:** O(n * k) where:
- n = length of the message
- k = number of keywords (50)

For each keyword, strstr() is called which runs in O(n) time in the worst case.

### Q14: How does the color output work?
**Answer:** The program uses Windows Console API functions:
- `SetConsoleTextAttribute(HANDLE, color)` to change text color
- Predefined color constants (COLOR_RED=12, COLOR_GREEN=10, etc.)
- Red for HIGH RISK, Yellow for MEDIUM RISK, Green for LOW RISK
- Cyan for headers, Yellow for safety advice

### Q15: How could you extend this project?
**Answer:**
1. Add more keywords with machine learning-based scoring
2. Implement URL reputation checking via API
3. Add support for image text analysis (OCR)
4. Create a GUI interface
5. Add network monitoring for real-time phishing detection
6. Implement email header analysis
7. Add multi-language support
8. Create a mobile app version

---

## Programming Concept Questions

### Q16: Why use `strncpy` instead of `strcpy`?
**Answer:** `strncpy` allows specifying the maximum number of characters to copy, preventing buffer overflow if the source string is longer than the destination buffer. `strcpy` does not check bounds and will overwrite memory.

### Q17: What is the difference between `fopen("r")` and `fopen("a")`?
**Answer:**
- **"r"** (read): Opens file for reading. File must exist. File pointer at beginning.
- **"a"** (append): Opens file for writing. Creates file if it doesn't exist. File pointer at end, so new data is appended.

### Q18: Explain the use of `typedef` in this project.
**Answer:** `typedef` creates aliases for data types:
```c
typedef struct { ... } Message;
// Allows using 'Message' instead of 'struct Message'
Message msg;  // No need to write 'struct Message msg;'
```

### Q19: How does `strstr()` work?
**Answer:** `strstr(str1, str2)` searches for the first occurrence of str2 in str1. It returns a pointer to the beginning of the first occurrence, or NULL if str2 is not found.

### Q20: Why is modular programming important in this project?
**Answer:** Modular programming:
1. Makes code more readable and maintainable
2. Allows testing individual functions
3. Enables code reuse
4. Makes debugging easier
5. Allows parallel development
6. Simplifies understanding of complex logic

---

## Practical Questions

### Q21: What would be the risk score for "URGENT! Your account is blocked. Click here: http://bit.ly/verify"?
**Answer:** 
- "urgent" detected → +15
- "account blocked" → +30
- "click here" → +20
- "http://" → +20
- "verify" - already counted in "click here" context
- ALL CAPS "URGENT" → +5
- Total: 70+ (HIGH RISK)

### Q22: What file is created when you save a report?
**Answer:** "reports.txt" is created in the same directory as the executable.

### Q23: What happens if reports.txt doesn't exist when viewing statistics?
**Answer:** The loadReports() function returns 0 (failure), and the program displays "No data available. Analyze messages first!"

### Q24: How does the program handle multi-line input?
**Answer:** It reads lines in a loop using fgets(). Each line is appended to the message until an empty line (just Enter) is detected, which signals the end of input.

### Q25: What is the maximum risk score possible?
**Answer:** The maximum is capped at 100, but theoretically, with all keywords and patterns detected, the raw score could be much higher before clamping.

