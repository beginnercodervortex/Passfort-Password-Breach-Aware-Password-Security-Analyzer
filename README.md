# PassFort — Breach-Aware Password Security Analyzer
PassFort is a privacy-focused cybersecurity prototype that helps users evaluate, understand, and improve their password security in real time.

It goes beyond traditional password checkers by combining:

* Strength analysis

* Brute-force crack-time estimation

* Breach exposure detection

* Security education through quizzes and guidance

* All without storing the user’s raw password.


# Features
## 1. Password Strength Checker

* Evaluates length, character diversity, and complexity

* Provides real-time security feedback

* Explains why a password is weak or strong

## 2. Crack-Time Estimation

* Uses entropy-based calculations

* Predicts how long brute-force attacks may take

* Displays results in seconds → years scale

## 3. Breach Detection (Privacy-Safe)

* Integrates HaveIBeenPwned-style k-anonymity model

* Checks if a password appears in known data breaches

* Ensures raw passwords never leave the device

## 4. Secure Password Generator

* Cryptographically strong random generation

* Customizable:

1. Length

2. Uppercase / lowercase

3. Numbers

4. Symbols

## 5. Cybersecurity Awareness Quiz

* Tests user knowledge of:

1. Brute-force attacks

2. Phishing

3. Credential stuffing

4. Password best practices

5. Because security tools should educate, not just judge.

# Tech Stack

* Python — core logic

* CustomTkinter — modern desktop UI

* Hashing + entropy models — security analysis

* Breach-checking API architecture — real-world relevance

# Privacy & Security Design

* PassFort follows a privacy-first approach:

* No raw password storage

* Client-side analysis

* Secure hashing before breach checks

* Educational feedback instead of data collection



# How to Run
1. Clone the repository

  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;git clone <repo-link>

  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;cd passfort

2. Install dependencies
   
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;pip install customtkinter

3. Run the app
   
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python main.py




# Project Status

### Current:
* Functional desktop prototype with:

* Strength analysis

* Crack-time estimation

* Password generator

* Quiz module

* Breach-check integration ready

### Next Phase:

* AI-based password risk prediction

* Web/cloud deployment

* Real-time breach intelligence expansion

* Encrypted authentication layer



# Purpose

Weak and reused passwords remain a primary cause of cyber breaches worldwide.

### PassFort aims to:

* Improve everyday digital security awareness

* Provide real-world password risk insight

* Promote privacy-respecting cybersecurity tools



# Team

1. Akshita Singh

2. Fuzailur Rahman

3. Yashila Verma

4. Archana 

# License

Educational & research prototype.
Open for learning, improvement, and responsible use.
