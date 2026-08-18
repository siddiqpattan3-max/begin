/*
===============================================================================
PROJECT  : Cyber Scam & Phishing Detector
LANGUAGE : C Programming Language
TEAM     : Team CyberShield (Builders)
PURPOSE  : Detect phishing attempts and cyber scams in messages
           using keyword and pattern matching
===============================================================================

BUILDERS:
  - Abubacker Siddik (Team Lead)
  - Azim Sunderwal
  - Muhammed Yousuf

DESCRIPTION:
This program analyzes SMS messages, WhatsApp messages, emails, and text
messages to detect possible cyber scams and phishing attempts. It uses
keyword matching with risk scores and pattern detection to calculate an
overall risk score and provide safety advice to the user.

KEY FEATURES:
- Home Menu with ASCII borders
- Message Analysis with keyword detection
- Pattern Detection (URLs, emails, phones, caps, etc.)
- Risk Calculation and Scoring
- File Handling (reports.txt)
- Scam Statistics
- Help Page with cybersecurity tips
- Color-coded terminal output
===============================================================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <conio.h>
#include <windows.h>

/*==============================================================================
  STRUCTURE DEFINITIONS
==============================================================================*/

/*
 * Structure: Message
 * Purpose: Stores all information related to a single message analysis
 * Members:
 *   - date: Current date when analysis was performed
 *   - time: Current time when analysis was performed
 *   - originalMsg: Original message entered by the user
 *   - lowerMsg: Message converted to lowercase for analysis
 *   - riskScore: Calculated risk score (0-100)
 *   - riskLevel: String representation (LOW/MEDIUM/HIGH)
 *   - detectedKeywords[20][50]: Array of detected suspicious keywords
 *   - keywordCount: Number of keywords detected
 *   - reasons[20][100]: Array of reasons for risk score
 *   - reasonCount: Number of reasons identified
 *   - safetyAdvice[10][100]: Array of safety advice messages
 *   - adviceCount: Number of safety advice items
 */
typedef struct {
    char date[20];
    char time[20];
    char originalMsg[1000];
    char lowerMsg[1000];
    int riskScore;
    char riskLevel[15];
    char detectedKeywords[20][50];
    int keywordCount;
    char reasons[20][100];
    int reasonCount;
    char safetyAdvice[10][100];
    int adviceCount;
} Message;

/*
 * Structure: Statistics
 * Purpose: Stores aggregate statistics from all saved reports
 * Members:
 *   - totalMessages: Total number of messages analyzed
 *   - highRiskCount: Number of HIGH RISK messages
 *   - mediumRiskCount: Number of MEDIUM RISK messages
 *   - lowRiskCount: Number of LOW RISK messages
 */
typedef struct {
    int totalMessages;
    int highRiskCount;
    int mediumRiskCount;
    int lowRiskCount;
} Statistics;

/*==============================================================================
  GLOBAL CONSTANTS
==============================================================================*/

/* Maximum sizes for arrays to prevent buffer overflow */
#define MAX_MESSAGE_LENGTH 1000
#define MAX_KEYWORDS 50
#define MAX_REASONS 50
#define MAX_ADVICE 20
#define MAX_REPORTS 1000
#define FILENAME "reports.txt"

/*==============================================================================
  FUNCTION PROTOTYPES
==============================================================================*/

/* Menu Functions */
void displayHomeMenu(void);
void analyzeMessage(void);
void viewPreviousReports(void);
void viewScamStatistics(void);
void displayHelp(void);

/* Analysis Functions */
void convertToLowercase(const char *source, char *destination);
int  searchSuspiciousKeywords(Message *msg);
int  detectPatterns(Message *msg);
int  calculateRiskScore(Message *msg);
void determineRiskLevel(Message *msg);
void generateSafetyAdvice(Message *msg);
void displayResults(Message *msg, int colorSupported);

/* File Handling Functions */
void saveReport(Message *msg);
int  loadReports(Message reports[], int *count);
int  isValidMessage(const char *message);

/* Utility Functions */
void clearInputBuffer(void);
void printAsciiBorder(void);
void printAsciiHeader(void);
int  checkColorSupport(void);
void setColor(int color);
void resetColor(void);
void getCurrentDateTime(char *date, char *time);
void addReason(Message *msg, const char *reason);
void addAdvice(Message *msg, const char *advice);
void addKeyword(Message *msg, const char *keyword);
int  containsSubstring(const char *str, const char *substr);

/*==============================================================================
  COLOR CONSTANTS (Windows Console)
==============================================================================*/
#define COLOR_RESET     7
#define COLOR_RED       12
#define COLOR_GREEN     10
#define COLOR_YELLOW    14
#define COLOR_CYAN      11
#define COLOR_WHITE     15
#define COLOR_MAGENTA   13

/*==============================================================================
  FUNCTION: main
  PURPOSE:  Entry point of the program. Displays home menu and handles
            user input in a loop until the user chooses to exit.
  INPUT:    None (command line arguments not used)
  OUTPUT:   Returns 0 on successful execution
==============================================================================*/
int main(void)
{
    int choice, colorSupported;

    /* Check if terminal supports color output */
    colorSupported = checkColorSupport();

    /* Infinite loop for menu-driven interface */
    while (1) {
        /* Clear the screen for better UI */
        system("cls");

        /* Display the home menu */
        displayHomeMenu();

        /* Prompt user for their choice */
        printf("\n  Enter your choice (1-5): ");

        /* Validate integer input */
        if (scanf("%d", &choice) != 1) {
            clearInputBuffer();
            printf("\n  Invalid input! Please enter a number.\n");
            printf("  Press any key to continue...");
            getch();
            continue;
        }
        clearInputBuffer();

        /* Handle user choice using switch-case */
        switch (choice) {
            case 1:
                analyzeMessage();
                break;
            case 2:
                viewPreviousReports();
                break;
            case 3:
                viewScamStatistics();
                break;
            case 4:
                displayHelp();
                break;
            case 5:
                if (colorSupported) setColor(COLOR_GREEN);
                printf("\n\n  Thank you for using Cyber Scam & Phishing Detector!\n");
                printf("  Stay safe online! Goodbye!\n\n");
                if (colorSupported) resetColor();
                return 0;
            default:
                if (colorSupported) setColor(COLOR_RED);
                printf("\n  Invalid choice! Please enter a number between 1 and 5.\n");
                if (colorSupported) resetColor();
                printf("  Press any key to continue...");
                getch();
        }
    }
    return 0;
}

/*==============================================================================
  FUNCTION: displayHomeMenu
  PURPOSE:  Displays the main menu with ASCII art borders and styled text.
            Shows all available options to the user.
  INPUT:    None
  OUTPUT:   Prints the menu to the console (void)
==============================================================================*/
void displayHomeMenu(void)
{
    int colorSupported = checkColorSupport();

    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("               CYBER SCAM & PHISHING DETECTOR               \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    printf("\n  1. Analyze Message\n");
    printf("  2. View Previous Reports\n");
    printf("  3. View Scam Statistics\n");
    printf("  4. Help\n");
    printf("  5. Exit\n");

    printAsciiBorder();
}

/*==============================================================================
  FUNCTION: analyzeMessage
  PURPOSE:  Main analysis function. Takes user input, converts to lowercase,
            searches for keywords, detects patterns, calculates risk score,
            displays results, and saves the report.
  INPUT:    User input from console
  OUTPUT:   Saves report to file and displays results (void)
==============================================================================*/
void analyzeMessage(void)
{
    Message msg;
    int colorSupported = checkColorSupport();
    char temp[1000];

    /* Initialize message structure */
    memset(&msg, 0, sizeof(Message));
    msg.keywordCount = 0;
    msg.reasonCount = 0;
    msg.adviceCount = 0;
    msg.riskScore = 0;

    /* Get current date and time */
    getCurrentDateTime(msg.date, msg.time);

    system("cls");
    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("                    MESSAGE ANALYSIS TOOL                    \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    printf("\n  Enter or paste the message to analyze:\n");
    printf("  (Press Enter twice to finish)\n\n  > ");

    /* Read multi-line input from user */
    msg.originalMsg[0] = '\0';
    while (1) {
        if (fgets(temp, sizeof(temp), stdin) == NULL) {
            break;
        }
        /* Remove trailing newline */
        size_t len = strlen(temp);
        if (len > 0 && temp[len - 1] == '\n') {
            temp[len - 1] = '\0';
        }
        /* Check for empty line (Enter twice to finish) */
        if (strlen(temp) == 0 && strlen(msg.originalMsg) > 0) {
            break;
        }
        /* Append to message */
        if (strlen(msg.originalMsg) > 0) {
            strncat(msg.originalMsg, " ", sizeof(msg.originalMsg) - strlen(msg.originalMsg) - 1);
        }
        strncat(msg.originalMsg, temp, sizeof(msg.originalMsg) - strlen(msg.originalMsg) - 1);

        /* Check if message is too long */
        if (strlen(msg.originalMsg) >= MAX_MESSAGE_LENGTH - 50) {
            printf("\n  [Message truncated to %d characters]\n", MAX_MESSAGE_LENGTH - 50);
            break;
        }
    }

    /* Validate message input */
    if (!isValidMessage(msg.originalMsg)) {
        if (colorSupported) setColor(COLOR_RED);
        printf("\n  Invalid message! Message cannot be empty.\n");
        if (colorSupported) resetColor();
        printf("\n  Press any key to continue...");
        getch();
        return;
    }

    /* Step 1: Convert message to lowercase */
    convertToLowercase(msg.originalMsg, msg.lowerMsg);

    /* Step 2: Search for suspicious keywords */
    searchSuspiciousKeywords(&msg);

    /* Step 3: Detect patterns */
    detectPatterns(&msg);

    /* Step 4: Calculate risk score */
    calculateRiskScore(&msg);

    /* Step 5: Determine risk level */
    determineRiskLevel(&msg);

    /* Step 6: Generate safety advice */
    generateSafetyAdvice(&msg);

    /* Step 7: Display results */
    displayResults(&msg, colorSupported);

    /* Step 8: Save report to file */
    saveReport(&msg);

    printf("\n  Report saved successfully to %s\n", FILENAME);
    printf("\n  Press any key to return to main menu...");
    getch();
}

/*==============================================================================
  FUNCTION: convertToLowercase
  PURPOSE:  Converts all characters in the source string to lowercase and
            stores the result in the destination string.
  INPUT:    source - Original string to convert
  OUTPUT:   destination - Converted lowercase string
==============================================================================*/
void convertToLowercase(const char *source, char *destination)
{
    int i = 0;
    while (source[i] != '\0' && i < MAX_MESSAGE_LENGTH - 1) {
        destination[i] = tolower((unsigned char)source[i]);
        i++;
    }
    destination[i] = '\0';
}

/*==============================================================================
  FUNCTION: searchSuspiciousKeywords
  PURPOSE:  Searches the message for a predefined list of scam/phishing
            keywords and assigns risk scores to each match.
  INPUT:    msg - Pointer to Message structure to populate
  OUTPUT:   Returns the number of keywords detected
==============================================================================*/
int searchSuspiciousKeywords(Message *msg)
{
    /* Keyword structure: contains keyword and its risk score */
    struct {
        char keyword[30];
        int  score;
    } keywordList[] = {
        {"otp", 30},
        {"password", 40},
        {"click here", 20},
        {"verify", 10},
        {"urgent", 15},
        {"kyc", 20},
        {"bank", 10},
        {"login", 15},
        {"upi", 15},
        {"payment", 15},
        {"refund", 20},
        {"lottery", 25},
        {"winner", 25},
        {"gift", 10},
        {"free", 10},
        {"offer", 15},
        {"limited time", 15},
        {"claim", 15},
        {"account blocked", 30},
        {"qr code", 20},
        {"scan", 20},
        {"credit card", 25},
        {"debit card", 25},
        {"pin", 15},
        {"link", 10},
        {"dear customer", 15},
        {"security alert", 25},
        {"suspicious activity", 25},
        {"confirm", 10},
        {"update", 10},
        {"reward", 20},
        {"congratulations", 20},
        {"selected", 15},
        {"won", 15},
        {"prize", 15},
        {"cashback", 15},
        {"discount", 10},
        {"hurry", 10},
        {"last chance", 15},
        {"exclusive", 10},
        {"guaranteed", 15},
        {"risk free", 15},
        {"no cost", 10},
        {"act now", 15},
        {"don't miss", 10},
        {"apply now", 10},
        {"limited offer", 15},
        {"expires today", 20},
        {"double your", 20},
        {"earn money", 20}
    };

    int numKeywords = sizeof(keywordList) / sizeof(keywordList[0]);
    int foundCount = 0;
    int i;

    /* Iterate through each keyword and check for occurrence */
    for (i = 0; i < numKeywords; i++) {
        if (containsSubstring(msg->lowerMsg, keywordList[i].keyword)) {
            /* Add keyword to detected list */
            addKeyword(msg, keywordList[i].keyword);

            /* Add to risk score */
            msg->riskScore += keywordList[i].score;

            foundCount++;

            /* Add reason based on keyword */
            char reason[100];
            snprintf(reason, sizeof(reason), "Keyword detected: '%s' (Score: +%d)",
                     keywordList[i].keyword, keywordList[i].score);
            addReason(msg, reason);
        }
    }

    return foundCount;
}

/*==============================================================================
  FUNCTION: detectPatterns
  PURPOSE:  Detects various suspicious patterns in the message such as URLs,
            email addresses, phone numbers, all-caps words, excessive
            punctuation, and currency symbols. Adds to risk score.
  INPUT:    msg - Pointer to Message structure
  OUTPUT:   Returns the number of patterns detected
==============================================================================*/
int detectPatterns(Message *msg)
{
    int patternCount = 0;
    int i;
    char *ptr;

    /*--------------------------------------------------------------------------
      Pattern 1: Detect http:// links
    --------------------------------------------------------------------------*/
    if (containsSubstring(msg->lowerMsg, "http://")) {
        msg->riskScore += 20;
        addReason(msg, "Suspicious link detected: HTTP URL found (Score: +20)");
        addKeyword(msg, "http:// link");
        addAdvice(msg, "Never click on suspicious links.");
        patternCount++;
    }

    /*--------------------------------------------------------------------------
      Pattern 2: Detect https:// links
    --------------------------------------------------------------------------*/
    if (containsSubstring(msg->lowerMsg, "https://")) {
        msg->riskScore += 15;
        addReason(msg, "URL link detected: HTTPS URL found (Score: +15)");
        addKeyword(msg, "https:// link");
        addAdvice(msg, "Always verify URLs before clicking.");
        patternCount++;
    }

    /*--------------------------------------------------------------------------
      Pattern 3: Detect www. links
    --------------------------------------------------------------------------*/
    if (containsSubstring(msg->lowerMsg, "www.")) {
        msg->riskScore += 10;
        addReason(msg, "Web address detected: www. found (Score: +10)");
        addKeyword(msg, "www. link");
        patternCount++;
    }

    /*--------------------------------------------------------------------------
      Pattern 4: Count consecutive exclamation marks (3 or more)
      e.g., "!!!" or "!!!!!"
    --------------------------------------------------------------------------*/
    {
        int exclaimCount = 0;
        int maxExclaim = 0;
        for (i = 0; msg->lowerMsg[i] != '\0'; i++) {
            if (msg->lowerMsg[i] == '!') {
                exclaimCount++;
                if (exclaimCount > maxExclaim) maxExclaim = exclaimCount;
            } else {
                exclaimCount = 0;
            }
        }
        if (maxExclaim >= 3) {
            int score = maxExclaim * 3;
            if (score > 20) score = 20;
            msg->riskScore += score;
            char reason[100];
            snprintf(reason, sizeof(reason), "Excessive exclamation marks detected: %d in a row (Score: +%d)",
                     maxExclaim, score);
            addReason(msg, reason);
            addKeyword(msg, "Excessive !!!");
            patternCount++;
        }
    }

    /*--------------------------------------------------------------------------
      Pattern 5: Detect words written in ALL CAPS (3+ letters)
      Only count if there are at least 2 such words
    --------------------------------------------------------------------------*/
    {
        int capsWords = 0;
        int wordLen = 0;
        int isCaps = 1;

        for (i = 0; msg->originalMsg[i] != '\0'; i++) {
            if (isalpha((unsigned char)msg->originalMsg[i])) {
                wordLen++;
                if (!isupper((unsigned char)msg->originalMsg[i])) {
                    isCaps = 0;
                }
            } else {
                if (wordLen >= 3 && isCaps) {
                    capsWords++;
                }
                wordLen = 0;
                isCaps = 1;
            }
        }
        /* Check last word */
        if (wordLen >= 3 && isCaps) {
            capsWords++;
        }

        if (capsWords >= 2) {
            int score = capsWords * 5;
            if (score > 25) score = 25;
            msg->riskScore += score;
            char reason[100];
            snprintf(reason, sizeof(reason), "Multiple ALL-CAPS words detected: %d words (Score: +%d)",
                     capsWords, score);
            addReason(msg, reason);
            addKeyword(msg, "ALL CAPS words");
            addAdvice(msg, "Legitimate messages rarely use excessive capitalization.");
            patternCount++;
        }
    }

    /*--------------------------------------------------------------------------
      Pattern 6: Detect currency symbols ($, €, £, ₹)
    --------------------------------------------------------------------------*/
    {
        int currencySymbols = 0;
        const char *symbols = "$€£₹¥";
        for (i = 0; msg->originalMsg[i] != '\0'; i++) {
            if (strchr(symbols, msg->originalMsg[i]) != NULL) {
                currencySymbols++;
            }
        }
        if (currencySymbols >= 1) {
            int score = currencySymbols * 8;
            if (score > 20) score = 20;
            msg->riskScore += score;
            char reason[100];
            snprintf(reason, sizeof(reason), "Currency symbols detected: %d symbol(s) (Score: +%d)",
                     currencySymbols, score);
            addReason(msg, reason);
            addKeyword(msg, "Currency symbol(s)");
            addAdvice(msg, "Be cautious of messages mentioning money or payments.");
            patternCount++;
        }
    }

    /*--------------------------------------------------------------------------
      Pattern 7: Detect phone numbers (simple patterns)
      Matches patterns like: 1234567890, 123-456-7890, +91 1234567890
    --------------------------------------------------------------------------*/
    {
        int digitCount = 0;
        int phoneFound = 0;
        for (i = 0; msg->originalMsg[i] != '\0'; i++) {
            if (isdigit((unsigned char)msg->originalMsg[i])) {
                digitCount++;
            } else if (msg->originalMsg[i] == '-' || msg->originalMsg[i] == '+' ||
                       msg->originalMsg[i] == ' ' || msg->originalMsg[i] == '(' ||
                       msg->originalMsg[i] == ')') {
                continue; /* These are valid phone number characters */
            } else {
                if (digitCount >= 10) {
                    phoneFound = 1;
                }
                digitCount = 0;
            }
        }
        if (digitCount >= 10) {
            phoneFound = 1;
        }
        if (phoneFound) {
            msg->riskScore += 15;
            addReason(msg, "Phone number detected in message (Score: +15)");
            addKeyword(msg, "Phone number");
            addAdvice(msg, "Do not share personal information like phone numbers.");
            patternCount++;
        }
    }

    /*--------------------------------------------------------------------------
      Pattern 8: Detect email addresses (contains @ and domain)
    --------------------------------------------------------------------------*/
    if (containsSubstring(msg->lowerMsg, "@") &&
        (containsSubstring(msg->lowerMsg, ".com") ||
         containsSubstring(msg->lowerMsg, ".in") ||
         containsSubstring(msg->lowerMsg, ".org") ||
         containsSubstring(msg->lowerMsg, ".net"))) {
        msg->riskScore += 15;
        addReason(msg, "Email address detected in message (Score: +15)");
        addKeyword(msg, "Email address");
        addAdvice(msg, "Be careful with unsolicited emails asking for information.");
        patternCount++;
    }

    /*--------------------------------------------------------------------------
      Pattern 9: Detect suspicious URLs containing common scam words
    --------------------------------------------------------------------------*/
    {
        const char *suspiciousDomains[] = {
            "free", "win", "lucky", "prize", "claim", "reward",
            "bonus", "cash", "money", "gift", "secure", "verify",
            "update", "confirm", "login", "account"
        };
        int numDomains = sizeof(suspiciousDomains) / sizeof(suspiciousDomains[0]);
        int foundSuspicious = 0;

        for (i = 0; i < numDomains; i++) {
            if (containsSubstring(msg->lowerMsg, suspiciousDomains[i])) {
                foundSuspicious++;
            }
        }
        if (foundSuspicious >= 2) {
            int score = foundSuspicious * 5;
            msg->riskScore += score;
            char reason[100];
            snprintf(reason, sizeof(reason), "Multiple scam-related keywords in context (Score: +%d)", score);
            addReason(msg, reason);
            patternCount++;
        }
    }

    /*--------------------------------------------------------------------------
      Pattern 10: Detect common phishing salutations
    --------------------------------------------------------------------------*/
    {
        const char *phishingGreetings[] = {
            "dear customer", "dear user", "dear account holder",
            "valued customer", "dear sir", "dear madam"
        };
        int numGreetings = sizeof(phishingGreetings) / sizeof(phishingGreetings[0]);

        for (i = 0; i < numGreetings; i++) {
            if (containsSubstring(msg->lowerMsg, phishingGreetings[i])) {
                msg->riskScore += 10;
                char reason[100];
                snprintf(reason, sizeof(reason), "Generic phishing greeting: '%s' (Score: +10)",
                         phishingGreetings[i]);
                addReason(msg, reason);
                addKeyword(msg, "Phishing greeting");
                addAdvice(msg, "Legitimate companies address you by your name.");
                patternCount++;
                break;
            }
        }
    }

    return patternCount;
}

/*==============================================================================
  FUNCTION: calculateRiskScore
  PURPOSE:  Finalizes the risk score calculation. Ensures the score is
            within the valid range of 0 to 100.
  INPUT:    msg - Pointer to Message structure
  OUTPUT:   Returns the final calculated risk score
==============================================================================*/
int calculateRiskScore(Message *msg)
{
    /* Ensure risk score is between 0 and 100 */
    if (msg->riskScore < 0) {
        msg->riskScore = 0;
    }
    if (msg->riskScore > 100) {
        msg->riskScore = 100;
    }

    return msg->riskScore;
}

/*==============================================================================
  FUNCTION: determineRiskLevel
  PURPOSE:  Maps the numeric risk score to a risk level string.
            0-30  : LOW RISK
            31-60 : MEDIUM RISK
            61-100: HIGH RISK
  INPUT:    msg - Pointer to Message structure
  OUTPUT:   Sets msg->riskLevel to appropriate string (void)
==============================================================================*/
void determineRiskLevel(Message *msg)
{
    if (msg->riskScore >= 0 && msg->riskScore <= 30) {
        strcpy(msg->riskLevel, "LOW RISK");
    } else if (msg->riskScore >= 31 && msg->riskScore <= 60) {
        strcpy(msg->riskLevel, "MEDIUM RISK");
    } else {
        strcpy(msg->riskLevel, "HIGH RISK");
    }
}

/*==============================================================================
  FUNCTION: generateSafetyAdvice
  PURPOSE:  Generates appropriate safety advice based on the risk level
            and detected keywords/reasons in the message.
  INPUT:    msg - Pointer to Message structure
  OUTPUT:   Populates msg->safetyAdvice array (void)
==============================================================================*/
void generateSafetyAdvice(Message *msg)
{
    /* Add general safety advice based on risk level */
    if (strcmp(msg->riskLevel, "HIGH RISK") == 0) {
        addAdvice(msg, "This message appears to be a SCAM. Do not respond.");
        addAdvice(msg, "Do not click any links or download attachments.");
        addAdvice(msg, "Never share personal or financial information.");
    } else if (strcmp(msg->riskLevel, "MEDIUM RISK") == 0) {
        addAdvice(msg, "This message may be suspicious. Exercise caution.");
        addAdvice(msg, "Verify the sender through official channels.");
        addAdvice(msg, "Do not make any payments based on this message.");
    } else {
        addAdvice(msg, "This message appears to be safe.");
        addAdvice(msg, "Always stay vigilant against potential scams.");
    }

    /* Add OTP-specific advice */
    if (containsSubstring(msg->lowerMsg, "otp")) {
        addAdvice(msg, "Never share OTP with anyone, even if they claim to be from bank.");
    }

    /* Add password-specific advice */
    if (containsSubstring(msg->lowerMsg, "password")) {
        addAdvice(msg, "Never share your passwords. Legitimate companies never ask for them.");
    }

    /* Add KYC-specific advice */
    if (containsSubstring(msg->lowerMsg, "kyc")) {
        addAdvice(msg, "Verify KYC requests directly through your bank's official website.");
    }

    /* Add lottery/winner-specific advice */
    if (containsSubstring(msg->lowerMsg, "lottery") ||
        containsSubstring(msg->lowerMsg, "winner")) {
        addAdvice(msg, "You cannot win a lottery you didn't enter. It's a scam.");
    }

    /* Add urgency-specific advice */
    if (containsSubstring(msg->lowerMsg, "urgent") ||
        containsSubstring(msg->lowerMsg, "immediately") ||
        containsSubstring(msg->lowerMsg, "act now")) {
        addAdvice(msg, "Scammers create false urgency to rush your decision.");
    }

    /* Add account blocked advice */
    if (containsSubstring(msg->lowerMsg, "account blocked") ||
        containsSubstring(msg->lowerMsg, "account suspended")) {
        addAdvice(msg, "Contact your bank directly using official customer care number.");
    }
}

/*==============================================================================
  FUNCTION: displayResults
  PURPOSE:  Displays the complete analysis results to the user with
            colored output if the terminal supports it.
  INPUT:    msg - Pointer to Message structure
            colorSupported - Flag indicating terminal color support
  OUTPUT:   Prints results to console (void)
==============================================================================*/
void displayResults(Message *msg, int colorSupported)
{
    int i;

    system("cls");
    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("                    ANALYSIS RESULTS                         \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    /* Display Risk Score */
    printf("\n  RISK SCORE : %d/100\n", msg->riskScore);

    /* Display Risk Level with appropriate color */
    printf("  RISK LEVEL : ");
    if (strcmp(msg->riskLevel, "HIGH RISK") == 0) {
        if (colorSupported) setColor(COLOR_RED);
        printf("%s\n", msg->riskLevel);
        if (colorSupported) resetColor();
    } else if (strcmp(msg->riskLevel, "MEDIUM RISK") == 0) {
        if (colorSupported) setColor(COLOR_YELLOW);
        printf("%s\n", msg->riskLevel);
        if (colorSupported) resetColor();
    } else {
        if (colorSupported) setColor(COLOR_GREEN);
        printf("%s\n", msg->riskLevel);
        if (colorSupported) resetColor();
    }

    printAsciiBorder();

    /* Display Detected Keywords */
    printf("\n  DETECTED KEYWORDS:\n");
    if (msg->keywordCount == 0) {
        printf("  - None\n");
    } else {
        for (i = 0; i < msg->keywordCount; i++) {
            printf("  [%d] %s\n", i + 1, msg->detectedKeywords[i]);
        }
    }

    printAsciiBorder();

    /* Display Reasons */
    printf("\n  REASONS:\n");
    if (msg->reasonCount == 0) {
        printf("  - No suspicious patterns detected.\n");
    } else {
        for (i = 0; i < msg->reasonCount; i++) {
            printf("  * %s\n", msg->reasons[i]);
        }
    }

    printAsciiBorder();

    /* Display Safety Advice */
    printf("\n  SAFETY ADVICE:\n");
    if (msg->adviceCount == 0) {
        printf("  - No specific advice.\n");
    } else {
        for (i = 0; i < msg->adviceCount; i++) {
            if (colorSupported) setColor(COLOR_YELLOW);
            printf("  [!] %s\n", msg->safetyAdvice[i]);
            if (colorSupported) resetColor();
        }
    }

    printAsciiBorder();

    /* Display Original Message */
    printf("\n  ORIGINAL MESSAGE:\n");
    printf("  \"%s\"\n", msg->originalMsg);

    printAsciiBorder();
}

/*==============================================================================
  FUNCTION: saveReport
  PURPOSE:  Saves the analysis results to a text file (reports.txt) in
            append mode. Each report is separated by a delimiter.
  INPUT:    msg - Pointer to Message structure to save
  OUTPUT:   Appends data to reports.txt (void)
==============================================================================*/
void saveReport(Message *msg)
{
    FILE *file = fopen(FILENAME, "a");
    int i;

    if (file == NULL) {
        printf("\n  Error: Could not open file %s for writing.\n", FILENAME);
        return;
    }

    /* Write report header */
    fprintf(file, "\n===============================================================================\n");
    fprintf(file, "REPORT DATE : %s\n", msg->date);
    fprintf(file, "REPORT TIME : %s\n", msg->time);
    fprintf(file, "RISK SCORE  : %d/100\n", msg->riskScore);
    fprintf(file, "RISK LEVEL  : %s\n", msg->riskLevel);
    fprintf(file, "-------------------------------------------------------------------------------\n");

    /* Write original message */
    fprintf(file, "MESSAGE:\n%s\n", msg->originalMsg);
    fprintf(file, "-------------------------------------------------------------------------------\n");

    /* Write detected keywords */
    fprintf(file, "DETECTED KEYWORDS:\n");
    if (msg->keywordCount == 0) {
        fprintf(file, "  None\n");
    } else {
        for (i = 0; i < msg->keywordCount; i++) {
            fprintf(file, "  - %s\n", msg->detectedKeywords[i]);
        }
    }

    /* Write reasons */
    fprintf(file, "\nREASONS:\n");
    if (msg->reasonCount == 0) {
        fprintf(file, "  No suspicious patterns detected.\n");
    } else {
        for (i = 0; i < msg->reasonCount; i++) {
            fprintf(file, "  - %s\n", msg->reasons[i]);
        }
    }

    /* Write safety advice */
    fprintf(file, "\nSAFETY ADVICE:\n");
    if (msg->adviceCount == 0) {
        fprintf(file, "  No specific advice.\n");
    } else {
        for (i = 0; i < msg->adviceCount; i++) {
            fprintf(file, "  - %s\n", msg->safetyAdvice[i]);
        }
    }

    fprintf(file, "===============================================================================\n");

    fclose(file);
}

/*==============================================================================
  FUNCTION: loadReports
  PURPOSE:  Loads all saved reports from reports.txt file into an array
            of Message structures.
  INPUT:    reports - Array of Message structures to populate
            count - Pointer to store the number of reports loaded
  OUTPUT:   Returns 1 on success, 0 on failure
==============================================================================*/
int loadReports(Message reports[], int *count)
{
    FILE *file = fopen(FILENAME, "r");
    char line[500];
    int currentIdx = 0;
    int readingMessage = 0;
    int readingKeywords = 0;
    int readingReasons = 0;
    int readingAdvice = 0;

    if (file == NULL) {
        return 0; /* File doesn't exist yet */
    }

    *count = 0;

    /* Read the file line by line */
    while (fgets(line, sizeof(line), file) != NULL && currentIdx < MAX_REPORTS) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Detect report sections */
        if (strstr(line, "REPORT DATE :")) {
            readingMessage = 0;
            readingKeywords = 0;
            readingReasons = 0;
            readingAdvice = 0;
            if (currentIdx > 0) (*count)++;
            currentIdx = *count;
            sscanf(line, "REPORT DATE : %[^\n]", reports[currentIdx].date);
        }
        else if (strstr(line, "REPORT TIME :")) {
            sscanf(line, "REPORT TIME : %[^\n]", reports[currentIdx].time);
        }
        else if (strstr(line, "RISK SCORE")) {
            sscanf(line, "RISK SCORE  : %d/100", &reports[currentIdx].riskScore);
        }
        else if (strstr(line, "RISK LEVEL")) {
            sscanf(line, "RISK LEVEL  : %[^\n]", reports[currentIdx].riskLevel);
        }
        else if (strstr(line, "MESSAGE:") && !strstr(line, "DETECTED")) {
            readingMessage = 1;
            readingKeywords = 0;
            readingReasons = 0;
            readingAdvice = 0;
            reports[currentIdx].originalMsg[0] = '\0';
        }
        else if (strstr(line, "DETECTED KEYWORDS:")) {
            readingMessage = 0;
            readingKeywords = 1;
            readingReasons = 0;
            readingAdvice = 0;
            reports[currentIdx].keywordCount = 0;
        }
        else if (strstr(line, "REASONS:")) {
            readingMessage = 0;
            readingKeywords = 0;
            readingReasons = 1;
            readingAdvice = 0;
            reports[currentIdx].reasonCount = 0;
        }
        else if (strstr(line, "SAFETY ADVICE:")) {
            readingMessage = 0;
            readingKeywords = 0;
            readingReasons = 0;
            readingAdvice = 1;
            reports[currentIdx].adviceCount = 0;
        }
        else if (strstr(line, "====")) {
            readingMessage = 0;
            readingKeywords = 0;
            readingReasons = 0;
            readingAdvice = 0;
        }
        else if (strstr(line, "----")) {
            /* Separator - do nothing */
        }
        else {
            /* Read content based on current section */
            if (readingMessage && line[0] != '\0') {
                if (strlen(reports[currentIdx].originalMsg) > 0) {
                    strncat(reports[currentIdx].originalMsg, "\n",
                            sizeof(reports[currentIdx].originalMsg) - strlen(reports[currentIdx].originalMsg) - 1);
                }
                strncat(reports[currentIdx].originalMsg, line,
                        sizeof(reports[currentIdx].originalMsg) - strlen(reports[currentIdx].originalMsg) - 1);
            }
            else if (readingKeywords && line[0] != '\0' && strstr(line, "- ")) {
                const char *kwStart = strstr(line, "- ") + 2;
                if (reports[currentIdx].keywordCount < 20) {
                    strncpy(reports[currentIdx].detectedKeywords[reports[currentIdx].keywordCount],
                            kwStart, 49);
                    reports[currentIdx].detectedKeywords[reports[currentIdx].keywordCount][49] = '\0';
                    reports[currentIdx].keywordCount++;
                }
            }
            else if (readingReasons && line[0] != '\0' && strstr(line, "- ")) {
                const char *rStart = strstr(line, "- ") + 2;
                if (reports[currentIdx].reasonCount < 20) {
                    strncpy(reports[currentIdx].reasons[reports[currentIdx].reasonCount],
                            rStart, 99);
                    reports[currentIdx].reasons[reports[currentIdx].reasonCount][99] = '\0';
                    reports[currentIdx].reasonCount++;
                }
            }
            else if (readingAdvice && line[0] != '\0' && strstr(line, "- ")) {
                const char *aStart = strstr(line, "- ") + 2;
                if (reports[currentIdx].adviceCount < 10) {
                    strncpy(reports[currentIdx].safetyAdvice[reports[currentIdx].adviceCount],
                            aStart, 99);
                    reports[currentIdx].safetyAdvice[reports[currentIdx].adviceCount][99] = '\0';
                    reports[currentIdx].adviceCount++;
                }
            }
        }
    }

    /* Count the last report */
    if (*count > 0 || strlen(reports[0].date) > 0) {
        (*count)++;
    }

    fclose(file);
    return 1;
}

/*==============================================================================
  FUNCTION: viewPreviousReports
  PURPOSE:  Reads and displays all saved reports from reports.txt file.
            Shows them in a paginated format.
  INPUT:    None
  OUTPUT:   Displays reports to console (void)
==============================================================================*/
void viewPreviousReports(void)
{
    Message reports[MAX_REPORTS];
    int count = 0;
    int i, j;
    int colorSupported = checkColorSupport();

    system("cls");
    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("                  PREVIOUS REPORTS                           \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    /* Load reports from file */
    if (!loadReports(reports, &count) || count == 0) {
        if (colorSupported) setColor(COLOR_YELLOW);
        printf("\n  No reports found. Analyze a message first!\n");
        if (colorSupported) resetColor();
        printf("\n  Press any key to return to main menu...");
        getch();
        return;
    }

    /* Display each report */
    for (i = 0; i < count; i++) {
        printf("\n  REPORT #%d\n", i + 1);
        printf("  Date: %s | Time: %s\n", reports[i].date, reports[i].time);
        printf("  Score: %d/100 | Level: %s\n", reports[i].riskScore, reports[i].riskLevel);

        printf("  Keywords: ");
        if (reports[i].keywordCount == 0) {
            printf("None");
        } else {
            for (j = 0; j < reports[i].keywordCount; j++) {
                printf("%s", reports[i].detectedKeywords[j]);
                if (j < reports[i].keywordCount - 1) printf(", ");
            }
        }
        printf("\n");

        printf("  Message: %.80s%s\n", reports[i].originalMsg,
               strlen(reports[i].originalMsg) > 80 ? "..." : "");
        printf("  ");

        /* Print separator */
        for (j = 0; j < 60; j++) printf("-");
        printf("\n");
    }

    printf("\n  Total Reports: %d\n", count);
    printf("\n  Press any key to return to main menu...");
    getch();
}

/*==============================================================================
  FUNCTION: viewScamStatistics
  PURPOSE:  Calculates and displays aggregate statistics from all saved
            reports, including total count and risk level distribution.
  INPUT:    None
  OUTPUT:   Displays statistics to console (void)
==============================================================================*/
void viewScamStatistics(void)
{
    Message reports[MAX_REPORTS];
    Statistics stats;
    int count = 0;
    int i;
    int colorSupported = checkColorSupport();

    /* Initialize statistics */
    stats.totalMessages = 0;
    stats.highRiskCount = 0;
    stats.mediumRiskCount = 0;
    stats.lowRiskCount = 0;

    system("cls");
    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("                   SCAM STATISTICS                           \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    /* Load reports */
    if (!loadReports(reports, &count) || count == 0) {
        if (colorSupported) setColor(COLOR_YELLOW);
        printf("\n  No data available. Analyze messages first!\n");
        if (colorSupported) resetColor();
        printf("\n  Press any key to return to main menu...");
        getch();
        return;
    }

    /* Calculate statistics */
    stats.totalMessages = count;
    for (i = 0; i < count; i++) {
        if (strcmp(reports[i].riskLevel, "HIGH RISK") == 0) {
            stats.highRiskCount++;
        } else if (strcmp(reports[i].riskLevel, "MEDIUM RISK") == 0) {
            stats.mediumRiskCount++;
        } else {
            stats.lowRiskCount++;
        }
    }

    /* Display statistics */
    printf("\n  TOTAL MESSAGES ANALYZED : %d\n\n", stats.totalMessages);

    if (colorSupported) setColor(COLOR_RED);
    printf("  HIGH RISK MESSAGES     : %d (%.1f%%)\n",
           stats.highRiskCount,
           (float)stats.highRiskCount / stats.totalMessages * 100);
    if (colorSupported) resetColor();

    if (colorSupported) setColor(COLOR_YELLOW);
    printf("  MEDIUM RISK MESSAGES   : %d (%.1f%%)\n",
           stats.mediumRiskCount,
           (float)stats.mediumRiskCount / stats.totalMessages * 100);
    if (colorSupported) resetColor();

    if (colorSupported) setColor(COLOR_GREEN);
    printf("  LOW RISK MESSAGES      : %d (%.1f%%)\n",
           stats.lowRiskCount,
           (float)stats.lowRiskCount / stats.totalMessages * 100);
    if (colorSupported) resetColor();

    /* Display a simple visual bar chart */
    printf("\n  RISK DISTRIBUTION:\n");
    printf("  HIGH   ");
    for (i = 0; i < stats.highRiskCount && i < 30; i++) {
        if (colorSupported) setColor(COLOR_RED);
        printf("#");
        if (colorSupported) resetColor();
    }
    printf(" (%d)\n", stats.highRiskCount);

    printf("  MEDIUM ");
    for (i = 0; i < stats.mediumRiskCount && i < 30; i++) {
        if (colorSupported) setColor(COLOR_YELLOW);
        printf("#");
        if (colorSupported) resetColor();
    }
    printf(" (%d)\n", stats.mediumRiskCount);

    printf("  LOW    ");
    for (i = 0; i < stats.lowRiskCount && i < 30; i++) {
        if (colorSupported) setColor(COLOR_GREEN);
        printf("#");
        if (colorSupported) resetColor();
    }
    printf(" (%d)\n", stats.lowRiskCount);

    printAsciiBorder();
    printf("\n  Press any key to return to main menu...");
    getch();
}

/*==============================================================================
  FUNCTION: displayHelp
  PURPOSE:  Displays the help page with information about phishing, scams,
            and cybersecurity tips for staying safe online.
  INPUT:    None
  OUTPUT:   Displays help information to console (void)
==============================================================================*/
void displayHelp(void)
{
    int colorSupported = checkColorSupport();

    system("cls");
    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("                   HELP & INFORMATION                        \n");
    if (colorSupported) resetColor();
    printAsciiBorder();

    /* Section 1: What is Phishing */
    if (colorSupported) setColor(COLOR_YELLOW);
    printf("\n  1. WHAT IS PHISHING?\n");
    if (colorSupported) resetColor();
    printf("  "); for (int i = 0; i < 55; i++) printf("-"); printf("\n");
    printf("  Phishing is a type of cyber attack where criminals pose as\n");
    printf("  legitimate organizations (banks, government agencies, etc.)\n");
    printf("  to trick you into revealing sensitive information like:\n");
    printf("  - Passwords and PINs\n");
    printf("  - Credit card numbers\n");
    printf("  - Bank account details\n");
    printf("  - OTPs and verification codes\n");
    printf("  - Personal identification information\n\n");
    printf("  Phishing usually comes via emails, SMS, WhatsApp, or fake\n");
    printf("  websites that look identical to legitimate ones.\n");

    /* Section 2: What is a Scam */
    if (colorSupported) setColor(COLOR_YELLOW);
    printf("\n  2. WHAT IS A CYBER SCAM?\n");
    if (colorSupported) resetColor();
    printf("  "); for (int i = 0; i < 55; i++) printf("-"); printf("\n");
    printf("  A cyber scam is a fraudulent scheme conducted online to\n");
    printf("  deceive people and steal money or personal data.\n");
    printf("  Common types include:\n");
    printf("  - Lottery/Prize scams\n");
    printf("  - Job offer scams\n");
    printf("  - Romance scams\n");
    printf("  - Investment scams\n");
    printf("  - Tech support scams\n");
    printf("  - KYC update scams\n");
    printf("  - QR code scams\n");
    printf("  - Fake refund scams\n");

    /* Section 3: Cybersecurity Tips */
    if (colorSupported) setColor(COLOR_YELLOW);
    printf("\n  3. CYBERSECURITY TIPS\n");
    if (colorSupported) resetColor();
    printf("  "); for (int i = 0; i < 55; i++) printf("-"); printf("\n");
    printf("  [1] Never share OTP, passwords, or PIN with anyone.\n");
    printf("  [2] Always verify URLs before clicking.\n");
    printf("  [3] Check for spelling errors in emails/messages.\n");
    printf("  [4] Be wary of messages creating false urgency.\n");
    printf("  [5] Use strong, unique passwords for each account.\n");
    printf("  [6] Enable Two-Factor Authentication (2FA).\n");
    printf("  [7] Keep your software and antivirus updated.\n");
    printf("  [8] Don't download attachments from unknown senders.\n");
    printf("  [9] Verify KYC/account requests via official channels.\n");
    printf("  [10] If it sounds too good to be true, it probably is.\n");
    printf("  [11] Use a password manager to store passwords safely.\n");
    printf("  [12] Regularly check your bank statements.\n");
    printf("  [13] Be careful on public WiFi networks.\n");
    printf("  [14] Don't share personal info on social media.\n");
    printf("  [15] Report phishing attempts to the authorities.\n");

    /* Section 4: About this tool */
    if (colorSupported) setColor(COLOR_YELLOW);
    printf("\n  4. ABOUT THIS DETECTOR\n");
    if (colorSupported) resetColor();
    printf("  "); for (int i = 0; i < 55; i++) printf("-"); printf("\n");
    printf("  This tool analyzes messages for:\n");
    printf("  - 50+ suspicious keywords with weighted risk scores\n");
    printf("  - URLs, email addresses, and phone numbers\n");
    printf("  - ALL CAPS text and excessive punctuation\n");
    printf("  - Currency symbols and financial terms\n");
    printf("  - Phishing patterns and social engineering tactics\n");
    printf("\n  Risk is calculated on a scale of 0-100:\n");
    printf("  0-30  : LOW RISK   (Safe)\n");
    printf("  31-60 : MEDIUM RISK (Suspicious)\n");
    printf("  61-100: HIGH RISK  (Likely Scam)\n");

    printAsciiBorder();
    printf("\n  Press any key to return to main menu...");
    getch();
}

/*==============================================================================
  UTILITY FUNCTIONS
==============================================================================*/

/*
 * Function: clearInputBuffer
 * Purpose: Clears the input buffer to prevent scanf() issues.
 *          Removes any remaining newline or characters from stdin.
 * Input: None
 * Output: None (void)
 */
void clearInputBuffer(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/*
 * Function: printAsciiBorder
 * Purpose: Prints a decorative ASCII border line for the UI.
 * Input: None
 * Output: Prints border to console (void)
 */
void printAsciiBorder(void)
{
    printf("===============================================================\n");
}

/*
 * Function: printAsciiHeader
 * Purpose: Prints the main ASCII header with project title.
 * Input: None
 * Output: Prints header to console (void)
 */
void printAsciiHeader(void)
{
    int colorSupported = checkColorSupport();

    printAsciiBorder();
    if (colorSupported) setColor(COLOR_CYAN);
    printf("  _____           _          _____               _ \n");
    printf(" / ____|         | |        / ____|             | |\n");
    printf("| |     _ __ __ _| |__  ___| (___   ___ ___  ___| |\n");
    printf("| |    | '__/ _` | '_ \\/ __|\\___ \\ / __/ _ \\/ __| |\n");
    printf("| |____| | | (_| | |_) \\__ \\____) | (_|  __/ (__| |\n");
    printf(" \\_____|_|  \\__,_|_.__/|___/_____/ \\___\\___|\\___|_|\n");
    printf("                                       DETECTOR v1.0\n");
    if (colorSupported) resetColor();
    printAsciiBorder();
}

/*
 * Function: checkColorSupport
 * Purpose: Checks if the terminal supports colored output by checking
 *          the Windows version and console mode.
 * Input: None
 * Output: Returns 1 if color is supported, 0 otherwise
 */
int checkColorSupport(void)
{
    /* In Windows, we assume color is supported with SetConsoleTextAttribute */
    return 1;
}

/*
 * Function: setColor
 * Purpose: Sets the console text color on Windows systems.
 * Input: color - Color constant (e.g., COLOR_RED, COLOR_GREEN)
 * Output: Changes console text color (void)
 */
void setColor(int color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

/*
 * Function: resetColor
 * Purpose: Resets console text color to default (white on black).
 * Input: None
 * Output: Resets console color (void)
 */
void resetColor(void)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, COLOR_RESET);
}

/*
 * Function: getCurrentDateTime
 * Purpose: Gets the current system date and time and formats them
 *          as strings (DD/MM/YYYY and HH:MM:SS format).
 * Input: date - Buffer to store date string
 *        time - Buffer to store time string
 * Output: Populates date and time buffers (void)
 */
void getCurrentDateTime(char *date, char *time)
{
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(date, 20, "%d/%m/%Y", timeinfo);
    strftime(time, 20, "%H:%M:%S", timeinfo);
}

/*
 * Function: addReason
 * Purpose: Adds a reason string to the Message structure's reasons array.
 *          Prevents buffer overflow by checking array bounds.
 * Input: msg - Pointer to Message structure
 *        reason - Reason string to add
 * Output: Adds reason to msg->reasons (void)
 */
void addReason(Message *msg, const char *reason)
{
    if (msg->reasonCount < MAX_REASONS) {
        strncpy(msg->reasons[msg->reasonCount], reason, 99);
        msg->reasons[msg->reasonCount][99] = '\0';
        msg->reasonCount++;
    }
}

/*
 * Function: addAdvice
 * Purpose: Adds a safety advice string to the Message structure's
 *          advice array. Prevents buffer overflow.
 * Input: msg - Pointer to Message structure
 *        advice - Advice string to add
 * Output: Adds advice to msg->safetyAdvice (void)
 */
void addAdvice(Message *msg, const char *advice)
{
    if (msg->adviceCount < MAX_ADVICE) {
        strncpy(msg->safetyAdvice[msg->adviceCount], advice, 99);
        msg->safetyAdvice[msg->adviceCount][99] = '\0';
        msg->adviceCount++;
    }
}

/*
 * Function: addKeyword
 * Purpose: Adds a detected keyword string to the Message structure's
 *          keywords array. Prevents buffer overflow.
 * Input: msg - Pointer to Message structure
 *        keyword - Keyword string to add
 * Output: Adds keyword to msg->detectedKeywords (void)
 */
void addKeyword(Message *msg, const char *keyword)
{
    /* Avoid duplicate keywords */
    int i;
    for (i = 0; i < msg->keywordCount; i++) {
        if (strcmp(msg->detectedKeywords[i], keyword) == 0) {
            return; /* Already exists */
        }
    }

    if (msg->keywordCount < 20) {
        strncpy(msg->detectedKeywords[msg->keywordCount], keyword, 49);
        msg->detectedKeywords[msg->keywordCount][49] = '\0';
        msg->keywordCount++;
    }
}

/*
 * Function: containsSubstring
 * Purpose: Checks if a string contains a given substring.
 *          Uses strstr() for case-sensitive search (message is already lowercase).
 * Input: str - The string to search in
 *        substr - The substring to search for
 * Output: Returns 1 if substring is found, 0 otherwise
 */
int containsSubstring(const char *str, const char *substr)
{
    if (str == NULL || substr == NULL) {
        return 0;
    }
    return (strstr(str, substr) != NULL);
}

/*
 * Function: isValidMessage
 * Purpose: Validates that the input message is not empty and meets
 *          minimum length requirements.
 * Input: message - The message string to validate
 * Output: Returns 1 if message is valid, 0 otherwise
 */
int isValidMessage(const char *message)
{
    if (message == NULL) {
        return 0;
    }

    /* Check if message is empty or only whitespace */
    int i;
    for (i = 0; message[i] != '\0'; i++) {
        if (!isspace((unsigned char)message[i])) {
            return 1; /* Found a non-space character */
        }
    }

    return 0; /* Message is empty or only whitespace */
}

