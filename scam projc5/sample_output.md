# Sample Output - Cyber Scam & Phishing Detector

## 1. Home Menu Screen

```
===============================================================
               CYBER SCAM & PHISHING DETECTOR               
===============================================================

  1. Analyze Message
  2. View Previous Reports
  3. View Scam Statistics
  4. Help
  5. Exit

===============================================================

  Enter your choice (1-5):
```

## 2. Message Analysis - Input

```
===============================================================
                    MESSAGE ANALYSIS TOOL                    
===============================================================

  Enter or paste the message to analyze:
  (Press Enter twice to finish)

  > Dear Customer, your bank account has been blocked due to 
  > suspicious activity. Click here to verify your KYC immediately
  > and update your password. http://fake-bank-verify.com
  > Your OTP is 784512. Don't share this with anyone.
  > 
  > (empty line - input ends)
```

## 3. Analysis Results (HIGH RISK Example)

```
===============================================================
                    ANALYSIS RESULTS                         
===============================================================

  RISK SCORE : 85/100
  RISK LEVEL : [RED]HIGH RISK[/RED]

===============================================================

  DETECTED KEYWORDS:
  [1] otp
  [2] password
  [3] click here
  [4] verify
  [5] kyc
  [6] bank
  [7] suspicious activity
  [8] account blocked
  [9] http:// link
  [10] update

===============================================================

  REASONS:
  * Keyword detected: 'otp' (Score: +30)
  * Keyword detected: 'password' (Score: +40)
  * Keyword detected: 'click here' (Score: +20)
  * Keyword detected: 'verify' (Score: +10)
  * Keyword detected: 'kyc' (Score: +20)
  * Keyword detected: 'bank' (Score: +10)
  * Keyword detected: 'suspicious activity' (Score: +25)
  * Keyword detected: 'account blocked' (Score: +30)
  * Suspicious link detected: HTTP URL found (Score: +20)
  * Generic phishing greeting: 'dear customer' (Score: +10)

===============================================================

  SAFETY ADVICE:
  [!] This message appears to be a SCAM. Do not respond.
  [!] Do not click any links or download attachments.
  [!] Never share personal or financial information.
  [!] Never share OTP with anyone, even if they claim to be from bank.
  [!] Never share your passwords. Legitimate companies never ask for them.
  [!] Verify KYC requests directly through your bank's official website.
  [!] Contact your bank directly using official customer care number.

===============================================================

  ORIGINAL MESSAGE:
  "Dear Customer, your bank account has been blocked due to 
  suspicious activity. Click here to verify your KYC immediately
  and update your password. http://fake-bank-verify.com
  Your OTP is 784512. Don't share this with anyone."

===============================================================

  Report saved successfully to reports.txt

  Press any key to return to main menu...
```

## 4. Analysis Results (LOW RISK Example)

```
===============================================================
                    ANALYSIS RESULTS                         
===============================================================

  RISK SCORE : 10/100
  RISK LEVEL : [GREEN]LOW RISK[/GREEN]

===============================================================

  DETECTED KEYWORDS:
  - None

===============================================================

  REASONS:
  - No suspicious patterns detected.

===============================================================

  SAFETY ADVICE:
  [!] This message appears to be safe.
  [!] Always stay vigilant against potential scams.

===============================================================

  ORIGINAL MESSAGE:
  "Hi John, are we still meeting for lunch tomorrow at 1pm?"

===============================================================

  Report saved successfully to reports.txt

  Press any key to return to main menu...
```

## 5. Previous Reports Screen

```
===============================================================
                  PREVIOUS REPORTS                           
===============================================================

  REPORT #1
  Date: 15/04/2025 | Time: 14:30:25
  Score: 85/100 | Level: HIGH RISK
  Keywords: otp, password, click here, verify, kyc, bank, suspicious activity, account blocked
  Message: Dear Customer, your bank account has been blocked due to suspicious activity...
  ------------------------------------------------------------

  REPORT #2
  Date: 15/04/2025 | Time: 14:35:10
  Score: 10/100 | Level: LOW RISK
  Keywords: None
  Message: Hi John, are we still meeting for lunch tomorrow at 1pm?
  ------------------------------------------------------------

  Total Reports: 2

  Press any key to return to main menu...
```

## 6. Scam Statistics Screen

```
===============================================================
                   SCAM STATISTICS                           
===============================================================

  TOTAL MESSAGES ANALYZED : 2

  [RED]HIGH RISK MESSAGES     : 1 (50.0%)[/RED]
  [YELLOW]MEDIUM RISK MESSAGES   : 0 (0.0%)[/YELLOW]
  [GREEN]LOW RISK MESSAGES      : 1 (50.0%)[/GREEN]

  RISK DISTRIBUTION:
  [RED]HIGH   # (1)[/RED]
  [YELLOW]MEDIUM  (0)[/YELLOW]
  [GREEN]LOW    # (1)[/GREEN]

===============================================================

  Press any key to return to main menu...
```

## 7. Help Screen

```
===============================================================
                   HELP & INFORMATION                        
===============================================================

  1. WHAT IS PHISHING?
  -------------------------------------------------------
  Phishing is a type of cyber attack where criminals pose as
  legitimate organizations (banks, government agencies, etc.)
  to trick you into revealing sensitive information like:
  - Passwords and PINs
  - Credit card numbers
  - Bank account details
  - OTPs and verification codes
  - Personal identification information

  Phishing usually comes via emails, SMS, WhatsApp, or fake
  websites that look identical to legitimate ones.

  2. WHAT IS A CYBER SCAM?
  -------------------------------------------------------
  A cyber scam is a fraudulent scheme conducted online to
  deceive people and steal money or personal data.
  Common types include:
  - Lottery/Prize scams
  - Job offer scams
  - Romance scams
  - Investment scams
  - Tech support scams
  - KYC update scams
  - QR code scams
  - Fake refund scams

  3. CYBERSECURITY TIPS
  -------------------------------------------------------
  [1] Never share OTP, passwords, or PIN with anyone.
  [2] Always verify URLs before clicking.
  [3] Check for spelling errors in emails/messages.
  [4] Be wary of messages creating false urgency.
  [5] Use strong, unique passwords for each account.
  [6] Enable Two-Factor Authentication (2FA).
  [7] Keep your software and antivirus updated.
  [8] Don't download attachments from unknown senders.
  [9] Verify KYC/account requests via official channels.
  [10] If it sounds too good to be true, it probably is.

  4. ABOUT THIS DETECTOR
  -------------------------------------------------------
  This tool analyzes messages for:
  - 50+ suspicious keywords with weighted risk scores
  - URLs, email addresses, and phone numbers
  - ALL CAPS text and excessive punctuation
  - Currency symbols and financial terms
  - Phishing patterns and social engineering tactics

  Risk is calculated on a scale of 0-100:
  0-30  : LOW RISK   (Safe)
  31-60 : MEDIUM RISK (Suspicious)
  61-100: HIGH RISK  (Likely Scam)

===============================================================

  Press any key to return to main menu...
```

## 8. Error Handling Examples

### Invalid Input:
```
  Enter your choice (1-5): 6

  [RED]Invalid choice! Please enter a number between 1 and 5.[/RED]
  Press any key to continue...
```

### Empty Message:
```
  > (just pressed Enter)

  [RED]Invalid message! Message cannot be empty.[/RED]
  
  Press any key to continue...
```

### No Reports Available:
```
===============================================================
                  PREVIOUS REPORTS                           
===============================================================

  [YELLOW]No reports found. Analyze a message first![/YELLOW]

  Press any key to return to main menu...
```

