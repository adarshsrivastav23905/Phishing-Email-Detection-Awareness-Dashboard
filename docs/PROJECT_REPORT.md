# Project Report: Phishing Email Detection & Awareness Dashboard

## 1. What is phishing?

Phishing is a social engineering technique that tricks a person into revealing sensitive information, clicking a malicious link, or taking an unsafe action. Attackers often impersonate trusted entities such as banks, university support, HR, or internal IT teams.

## 2. What is email phishing?

Email phishing abuses email as the delivery mechanism. The attacker sends a message that appears legitimate but contains fake urgency, pressure, or a deceptive link. The goal is to drive the recipient to click, respond, or share credentials.

## 3. Why phishing is dangerous

Phishing is dangerous because it often bypasses technical controls by targeting human behavior. A single deceptive email can lead to credential theft, malware infection, financial fraud, or account compromise.

## 4. Why phishing detection matters

Security teams use detection systems to reduce risk by identifying patterns such as suspicious sender domains, urgency language, abnormal URLs, and suspicious attachments. This project demonstrates the same core ideas in a safe and educational way.

## 5. Workflow implemented

1. Capture email input
2. Extract sender, subject, body, URLs, and attachments
3. Preprocess values while preserving security indicators
4. Analyze sender patterns and domain behavior
5. Score language and urgency cues
6. Check URLs for suspicious features
7. Apply rule-based risk scoring
8. Classify the email as SAFE, LOW RISK, SUSPICIOUS, or HIGH RISK / LIKELY PHISHING
9. Explain the decision and recommend safe actions
10. Display analytics and store history

## 6. Industry relevance

This project maps directly to modern cybersecurity operations:

- SOC teams monitor suspicious email activity and investigate user reporting
- Email security platforms block dangerous messages using heuristics and reputation intelligence
- Security awareness teams train users on social engineering threats
- Threat intelligence teams identify malicious infrastructure and patterns
- Incident response teams use risk signals to triage suspicious events

## 7. Role mapping

### SOC Analyst

- understands signal triage and threat context
- reviews suspicious indicators when a user reports an email

### Email Security Analyst

- examines sender reputation, message content, and malicious URL patterns
- balances detection quality with false positives

### Cybersecurity Analyst

- evaluates detection logic, risk scoring, and operational effectiveness

### Threat Intelligence Analyst

- recognizes patterns in social engineering campaigns
- studies malicious infrastructure, tactics, and user-targeting methods

### Incident Response Analyst

- uses detection insights to support investigation and user guidance

## 8. Key technical design choices

- The detection engine is rule-based and explainable
- It is intentionally defensive rather than offensive
- It uses synthetic data so it is safe and reproducible
- Weighting is simple enough for beginners to understand
- Optional ML support is included as an educational extension

## 9. Why explainability matters

A cybersecurity system should explain why it made a decision. In phishing detection, a model or rule engine that says something is suspicious without justification is much harder to trust. This project makes the decisions transparent and beginner-friendly.

## 10. Resume-ready summary

Developed a defensive cybersecurity dashboard that analyzes phishing emails using sender, URL, content, and attachment indicators. Built a rule-based detection engine, generated a synthetic email dataset, implemented dashboard analytics, and persisted history in SQLite. The project emphasizes explainability, social engineering awareness, and safe educational design.

## 11. Interview preparation tips

- Explain why phishing is a human-centered risk, not only a technical one
- Describe the difference between a phishing signal and a proof of phishing
- Talk about false positives and why context matters
- Mention that explainability is important for trust and analyst review
- Highlight that rule-based systems remain valuable and interpretable

## 12. Final project value

This project provides a strong demonstration of beginner-friendly defensive cyber engineering. It combines practical detection logic, safe synthetic data, dashboard visualization, and awareness education in one portfolio-ready project.
