# Algorithm for Cyber Scam & Phishing Detector

## Main Algorithm Flow

### 1. Start Program
```
1. Include necessary header files (stdio.h, stdlib.h, string.h, ctype.h, time.h, conio.h, windows.h)
2. Define structures: Message, Statistics
3. Define global constants and color codes
4. Declare function prototypes
5. MAIN function:
   a. Check color support
   b. Loop:
      - Clear screen
      - Display home menu
      - Get user choice (1-5)
      - Switch case:
          1 → analyzeMessage()
          2 → viewPreviousReports()
          3 → viewScamStatistics()
          4 → displayHelp()
          5 → Exit program
```

### 2. Message Analysis Algorithm
```
analyzeMessage():
  1. Initialize Message structure (set all fields to zero)
  2. Get current date and time using getCurrentDateTime()
  3. Display "MESSAGE ANALYSIS TOOL" header
  4. Prompt user to enter/paste message
  5. Read multi-line input until empty line (Enter twice)
  6. Validate message (not empty) using isValidMessage()
  7. Convert message to lowercase using convertToLowercase()
  8. Search for suspicious keywords using searchSuspiciousKeywords()
  9. Detect patterns using detectPatterns()
  10. Calculate final risk score using calculateRiskScore()
  11. Determine risk level using determineRiskLevel()
  12. Generate safety advice using generateSafetyAdvice()
  13. Display results using displayResults()
  14. Save report to file using saveReport()
```

### 3. Keyword Search Algorithm
```
searchSuspiciousKeywords(Message *msg):
  1. Define keyword list with risk scores (50 keywords)
  2. For each keyword in list:
     - Check if keyword exists in lowercase message (case-insensitive)
     - If found:
       * Add keyword to detected list
       * Add risk score to total
       * Add reason string
  3. Return count of found keywords
```

### 4. Pattern Detection Algorithm
```
detectPatterns(Message *msg):
  Pattern 1: http:// → +20 risk, add reason
  Pattern 2: https:// → +15 risk, add reason
  Pattern 3: www. → +10 risk, add reason
  Pattern 4: Count consecutive '!' marks → if >=3, +score
  Pattern 5: Count ALL CAPS words (3+ letters) → if >=2, +score
  Pattern 6: Count currency symbols ($€£₹¥) → if >=1, +score
  Pattern 7: Detect phone numbers (10+ digits) → +15 risk
  Pattern 8: Detect email addresses (@ + .com/.in/.org/.net) → +15 risk
  Pattern 9: Detect multiple scam-related words → +score
  Pattern 10: Detect generic phishing greetings → +10 risk
  Return count of patterns detected
```

### 5. Risk Calculation Algorithm
```
calculateRiskScore(Message *msg):
  1. If riskScore < 0, set to 0
  2. If riskScore > 100, set to 100
  3. Return riskScore

determineRiskLevel(Message *msg):
  1. If score 0-30: set "LOW RISK"
  2. If score 31-60: set "MEDIUM RISK"
  3. If score 61-100: set "HIGH RISK"
```

### 6. Safety Advice Generation Algorithm
```
generateSafetyAdvice(Message *msg):
  1. Based on risk level (HIGH/MEDIUM/LOW), add general advice
  2. If "otp" detected: add OTP-specific advice
  3. If "password" detected: add password-specific advice
  4. If "kyc" detected: add KYC-specific advice
  5. If "lottery"/"winner" detected: add lottery scam advice
  6. If "urgent"/"immediately"/"act now": add urgency warning
  7. If "account blocked"/"account suspended": add account advice
```

### 7. File Handling Algorithm
```
saveReport(Message *msg):
  1. Open reports.txt in append mode
  2. Write: date, time, risk score, risk level
  3. Write: original message
  4. Write: detected keywords list
  5. Write: reasons list
  6. Write: safety advice list
  7. Close file

loadReports(Message reports[], int *count):
  1. Open reports.txt in read mode
  2. If file doesn't exist, return 0
  3. Parse file line by line
  4. Identify sections (DATE, TIME, SCORE, LEVEL, MESSAGE, KEYWORDS, REASONS, ADVICE)
  5. Populate array of Message structures
  6. Close file, return 1
```

### 8. Statistics Algorithm
```
viewScamStatistics():
  1. Load all reports using loadReports()
  2. For each report:
     - Increment appropriate counter (HIGH/MEDIUM/LOW)
  3. Display:
     - Total messages analyzed
     - Count and percentage for each risk level
     - Visual bar chart using # symbols
```

### 9. Help Display Algorithm
```
displayHelp():
  1. Section 1: What is Phishing?
     - Definition and examples
  2. Section 2: What is a Cyber Scam?
     - Types of scams
  3. Section 3: Cybersecurity Tips
     - 15 safety recommendations
  4. Section 4: About this Detector
     - Features and risk scale explanation
```

## Complexity Analysis
- Time Complexity: O(n * k) where n = message length, k = number of keywords
- Space Complexity: O(m) where m = size of Message structure
- File I/O: O(r) where r = number of reports

