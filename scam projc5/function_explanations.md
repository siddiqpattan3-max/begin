# Function Explanations - Cyber Scam & Phishing Detector

## Overview
This document provides detailed explanations of all functions used in the Cyber Scam & Phishing Detector C program. Total functions: 22

---

## 1. `int main(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Entry point of the program |
| **Input** | None |
| **Output** | Returns 0 on successful execution |
| **Working** | 1. Checks terminal color support<br>2. Enters infinite loop<br>3. Displays home menu<br>4. Reads user choice<br>5. Validates input<br>6. Switch-case handles choice (1-5)<br>7. Loop continues until Exit (choice 5) |
| **C Concepts** | Loop, Switch-Case, Function Calls |

---

## 2. `void displayHomeMenu(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Displays the main menu with ASCII borders |
| **Input** | None |
| **Output** | Prints menu to console (void) |
| **Working** | 1. Prints ASCII border<br>2. Sets cyan color for title<br>3. Prints "CYBER SCAM & PHISHING DETECTOR"<br>4. Prints menu options 1-5<br>5. Prints closing border |
| **C Concepts** | printf(), Color manipulation |

---

## 3. `void analyzeMessage(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Main analysis function - orchestrates the entire message analysis |
| **Input** | User input from console (multi-line message) |
| **Output** | Saves report to file, displays results |
| **Working** | 1. Initialize Message structure<br>2. Get date/time<br>3. Read multi-line input<br>4. Validate message<br>5. Convert to lowercase<br>6. Search keywords<br>7. Detect patterns<br>8. Calculate risk score<br>9. Determine risk level<br>10. Generate advice<br>11. Display results<br>12. Save to file |
| **C Concepts** | Structures, Strings, File I/O, Pointers |

---

## 4. `void convertToLowercase(const char *source, char *destination)`

| Property | Description |
|----------|-------------|
| **Purpose** | Converts all characters in a string to lowercase |
| **Input** | source - Original string, destination - Output buffer |
| **Output** | Populates destination with lowercase string |
| **Working** | 1. Loop through each character<br>2. Use tolower() on each char<br>3. Copy to destination<br>4. Null-terminate the result |
| **C Concepts** | String manipulation, tolower(), Loops |

---

## 5. `int searchSuspiciousKeywords(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Searches message for 50+ scam/phishing keywords |
| **Input** | msg - Pointer to Message structure |
| **Output** | Returns count of keywords found |
| **Working** | 1. Define array of keyword structs with scores<br>2. Loop through all keywords<br>3. Use strstr() to check occurrence<br>4. If found: add keyword, add score, add reason<br>5. Return total count |
| **C Concepts** | Arrays of Structures, strstr(), Loops, Pointers |

---

## 6. `int detectPatterns(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Detects suspicious patterns (URLs, emails, phones, etc.) |
| **Input** | msg - Pointer to Message structure |
| **Output** | Returns count of patterns detected |
| **Working** | 1. http:// detection (+20)<br>2. https:// detection (+15)<br>3. www. detection (+10)<br>4. Exclamation marks count (+3 each, max 20)<br>5. ALL CAPS word count (+5 each, max 25)<br>6. Currency symbols detection (+8 each, max 20)<br>7. Phone number detection (+15)<br>8. Email detection (+15)<br>9. Suspicious domain patterns<br>10. Phishing greeting detection (+10) |
| **C Concepts** | strstr(), strchr(), isalpha(), isupper(), isdigit(), Character analysis |

---

## 7. `int calculateRiskScore(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Finalizes and clamps the risk score between 0-100 |
| **Input** | msg - Pointer to Message structure |
| **Output** | Returns final risk score (0-100) |
| **Working** | 1. If score < 0, set to 0<br>2. If score > 100, set to 100<br>3. Return clamped score |
| **C Concepts** | Conditional statements, Value clamping |

---

## 8. `void determineRiskLevel(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Maps numeric risk score to risk level string |
| **Input** | msg - Pointer to Message structure |
| **Output** | Sets msg->riskLevel |
| **Working** | 1. 0-30 → "LOW RISK"<br>2. 31-60 → "MEDIUM RISK"<br>3. 61-100 → "HIGH RISK" |
| **C Concepts** | if-else ladder, strcpy(), String assignment |

---

## 9. `void generateSafetyAdvice(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Generates contextual safety advice based on findings |
| **Input** | msg - Pointer to Message structure |
| **Output** | Populates msg->safetyAdvice array |
| **Working** | 1. Add risk-level-based general advice<br>2. Check for OTP → add OTP advice<br>3. Check for password → add password advice<br>4. Check for KYC → add KYC advice<br>5. Check for lottery/winner → add lottery advice<br>6. Check for urgency words → add urgency advice<br>7. Check for account blocked → add account advice |
| **C Concepts** | strcmp(), strstr(), Conditional logic, String arrays |

---

## 10. `void displayResults(Message *msg, int colorSupported)`

| Property | Description |
|----------|-------------|
| **Purpose** | Displays complete analysis results to user |
| **Input** | msg - Message data, colorSupported - flag |
| **Output** | Prints formatted results to console |
| **Working** | 1. Clear screen<br>2. Display header<br>3. Show risk score<br>4. Show risk level with color (RED/YELLOW/GREEN)<br>5. List detected keywords<br>6. List reasons<br>7. Show safety advice<br>8. Show original message |
| **C Concepts** | Loops, Conditional formatting, Color output |

---

## 11. `void saveReport(Message *msg)`

| Property | Description |
|----------|-------------|
| **Purpose** | Saves analysis report to reports.txt file |
| **Input** | msg - Pointer to Message structure |
| **Output** | Appends data to reports.txt |
| **Working** | 1. Open file in append mode<br>2. Write date, time, score, level<br>3. Write message content<br>4. Write keywords list<br>5. Write reasons list<br>6. Write safety advice<br>7. Close file |
| **C Concepts** | File I/O (fopen, fprintf, fclose), Append mode |

---

## 12. `int loadReports(Message reports[], int *count)`

| Property | Description |
|----------|-------------|
| **Purpose** | Loads all saved reports from reports.txt into memory |
| **Input** | reports[] - Array to populate, count - pointer to store count |
| **Output** | Returns 1 on success, 0 on failure |
| **Working** | 1. Open file in read mode<br>2. Parse file line by line<br>3. Identify section headers<br>4. Extract data into Message structure<br>5. Track reading state (message/keywords/reasons/advice)<br>6. Close file when done |
| **C Concepts** | File I/O (fopen, fgets), String parsing, strstr(), State machine |

---

## 13. `void viewPreviousReports(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Displays all previously saved reports |
| **Input** | None |
| **Output** | Displays reports to console |
| **Working** | 1. Clear screen<br>2. Load reports from file<br>3. If no reports, show message<br>4. Loop through each report<br>5. Display date, time, score, level<br>6. Show keywords and truncated message<br>7. Show total count |
| **C Concepts** | Loops, Arrays of Structures, printf() formatting |

---

## 14. `void viewScamStatistics(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Calculates and displays aggregate statistics |
| **Input** | None |
| **Output** | Displays statistics with bar chart |
| **Working** | 1. Load all reports<br>2. Count high/medium/low risk<br>3. Calculate percentages<br>4. Display colored numbers<br>5. Show visual bar chart (# symbols) |
| **C Concepts** | Statistics, Loops, Percentage calculation, Visual output |

---

## 15. `void displayHelp(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Displays help/information about phishing, scams, and safety |
| **Input** | None |
| **Output** | Prints help text to console |
| **Working** | 1. Section 1: What is Phishing?<br>2. Section 2: What is a Cyber Scam?<br>3. Section 3: 15 Cybersecurity Tips<br>4. Section 4: About this Detector |
| **C Concepts** | printf(), String literals, Formatted output |

---

## 16. `void clearInputBuffer(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Clears stdin buffer to prevent scanf issues |
| **Input** | None |
| **Output** | None (void) |
| **Working** | Reads and discards characters until newline or EOF |
| **C Concepts** | getchar(), Loops |

---

## 17. `void printAsciiBorder(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Prints decorative ASCII border line |
| **Input** | None |
| **Output** | Prints 63 '=' characters |
| **Working** | Uses printf() to print the border string |
| **C Concepts** | printf() |

---

## 18. `void printAsciiHeader(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Prints ASCII art header with project name |
| **Input** | None |
| **Output** | Prints ASCII art to console |
| **Working** | 1. Print border<br>2. Set cyan color<br>3. Print ASCII art letters<br>4. Print version<br>5. Reset color<br>6. Print border |
| **C Concepts** | ASCII art, Color manipulation |

---

## 19. `int checkColorSupport(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Checks if terminal supports colored output |
| **Input** | None |
| **Output** | Returns 1 (always on Windows) |
| **Working** | Assumes Windows console supports SetConsoleTextAttribute |
| **C Concepts** | Return values |

---

## 20. `void setColor(int color)` / `void resetColor(void)`

| Property | Description |
|----------|-------------|
| **Purpose** | Sets/resets console text color on Windows |
| **Input** | color - Color constant (for setColor) |
| **Output** | Changes console text color |
| **Working** | Uses Windows API SetConsoleTextAttribute() to change color |
| **C Concepts** | Windows API, HANDLE |

---

## 21. `void getCurrentDateTime(char *date, char *time)`

| Property | Description |
|----------|-------------|
| **Purpose** | Gets current system date and time |
| **Input** | date, time - Buffers to store formatted strings |
| **Output** | Populates date (DD/MM/YYYY) and time (HH:MM:SS) |
| **Working** | 1. Get time using time()<br>2. Convert to local time using localtime()<br>3. Format using strftime() |
| **C Concepts** | time(), localtime(), strftime(), Pointers |

---

## 22. Utility Functions

### `void addReason(Message *msg, const char *reason)`
- Adds reason to message structure with bounds checking
- Uses strncpy() for safe string copy

### `void addAdvice(Message *msg, const char *advice)`
- Adds safety advice to message structure
- Prevents overflow with count check

### `void addKeyword(Message *msg, const char *keyword)`
- Adds keyword to detected list
- Checks for duplicates before adding
- Uses strncpy() with length limit

### `int containsSubstring(const char *str, const char *substr)`
- Checks if substr exists in str using strstr()
- Returns 1 if found, 0 otherwise

### `int isValidMessage(const char *message)`
- Validates message is not empty
- Checks if message contains non-space characters
- Returns 1 if valid, 0 if invalid

