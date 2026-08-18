
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

## 🙏 Acknowledgments

- C Programming Language (Kernighan & Ritchie)
- Cybersecurity standards and best practices
- Open source C compiler tools
