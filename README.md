# AIO-WebSec Lab

AIO-WebSec Lab is an all-in-one sandbox for practicing and learning web application security vulnerabilities. It provides hands-on labs for ethical hacking, attack simulation, and defense techniques across multiple vulnerability categories.

## Features

- **Injection Attacks:** SQL Injection, XSS, Command Injection, SSTI, XXE, Deserialization
- **Access Control Flaws:** IDOR, CSRF, Session Management, State Abuse
- **File System Attacks:** LFI, RFI, Path Traversal, Insecure File Uploads
- **Business Logic Flaws:** Parameter Tampering, Logic Bypass, Race Condition
- **Server-Side Request Forgery (SSRF):** Internal resource access, cloud metadata simulation
- **Secrets & Misconfiguration:** Sensitive data exposure, improper cryptography, debug mode
- **Denial of Service & Automation:** Rate limiting, resource exhaustion, anti-automation bypass

## Security Levels

Each lab supports multiple security levels:
- **Low:** Highly vulnerable, no defenses
- **Medium:** Basic filtering, bypassable
- **High:** Secure, best practices applied

Switch security levels using the selector in the UI to compare vulnerable and secure code.

## Getting Started

1. Clone the repository.
   ```bash
   git clone https://github.com/KhitMinnyo/AiO-WebSec.git
   ```
2. Install dependencies (Python, Flask, etc.).
   ```bash
   pip3 install -r requirements.txt
   #If you use Kali, use Virtual Environment, uncomment and use following 3 commands.
   # python -m venv venv
   # source venv/bin/activate
   # pip3 install -r requirements.txt
   ```
3. Run the Flask application:
   ```bash
   python3 app.py
   ```
4. Access the labs via your browser at `http://localhost:8080`.

## Lab Structure

- `templates/` — HTML templates for each lab module
- `app.py` — Main Flask application
- `static/` — Static assets (CSS, JS)
- `uploads/` — Uploaded files (for file upload lab)

## Usage

- Select a lab from the homepage.
- Read the instructions and hints for each vulnerability.
- Experiment with attacks and defenses at different security levels.
- Use automation tools (Burp Suite, scripts) for advanced scenarios.

## Disclaimer

This project is for educational purposes only. Do not use these techniques on systems you do not own or have explicit permission to test.

## License

MIT License

