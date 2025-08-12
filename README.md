# API-Sheild: Automated API Security Test Case Generator

**api-sheild**
Generate comprehensive security test cases from Postman/Swagger specs. Identifies vulnerabilities like SQLi, XSS, IDOR, and more with detailed exploitation steps, payloads, and OWASP references. No AI dependencies, works offline. Perfect for DevSecOps integration.

**🚀 Why API-Sheild Stands Out**

API-Sheild revolutionizes API security testing by automatically generating comprehensive, actionable security test cases from your API specifications. Unlike traditional scanners that only identify vulnerabilities, API-Sheild helps you prevent them by providing detailed test cases during development.

**✨ What Makes API-Sheild Unique**

**Test Case Generation**
✅ Detailed, step-by-step test cases

**Specification-Driven**
✅ Uses Postman/Swagger to understand your API

**Context-Aware Testing**
✅ Generates relevant tests based on API context

**OWASP Top 10 Coverage**
✅ Comprehensive coverage with detailed guidance

**Offline Operation**
✅ No internet connection required

**No AI Dependencies**
✅ Reliable, consistent results


**💡 How API-Sheild Transforms Security Testing**

**1. Shift Left Security**
Integrate security testing early in the development lifecycle by generating test cases as soon as your API specification is available.

**2. Comprehensive Vulnerability Coverage**
API-Sheild automatically identifies and generates test cases for all major API security risks:

Injection Attacks (SQLi, Command Injection, XSS)

Authentication & Authorization (IDOR, Privilege Escalation)

Input Validation (Mass Assignment, Buffer Overflow)

Rate Limiting & Resource Exhaustion

File Upload Security (Malicious Uploads, Path Traversal)

Business Logic Flaws

Transport Security (HTTPS enforcement)


**3. Detailed, Actionable Test Cases**
Unlike simple vulnerability scanners, API-Sheild provides complete security test cases with:

Step-by-step testing procedures

Ready-to-use payloads for each vulnerability type

Exploitation rationale explaining how the attack works

Business impact assessment

OWASP API Security Top 10 references

Parameter-specific guidance


**4. Specification-Driven Intelligence**

API-Sheild analyzes your API specification to generate context-aware test cases.


**🎯 Key Benefits**

**For Security Teams**
Standardize testing across all API projects
Focus on high-risk areas with prioritized test cases
Reduce false positives with context-aware analysis
Improve test coverage with comprehensive vulnerability detection

**For Development Teams**
Shift security left by identifying issues early
Get clear remediation guidance with detailed test cases
Integrate with CI/CD for automated security testing
Reduce security debt by addressing issues during development

**For Organizations**
Reduce security testing costs by automating test case generation
Improve API security posture with comprehensive coverage
Ensure compliance with security standards and regulations
Accelerate secure development without sacrificing speed


**🚀 Getting Started
**Prerequisites
Python 3.7 or higher
pip package manager

# Installation
**Clone the repository**

git clone https://github.com/yourusername/api-sheild.git

cd api-sheild

**Install dependencies (minimal - no heavy AI libraries)**

pip install requests pyyaml

**Generate security tests from Postman collection**

python main.py --postman sample_data/sample_postman.json

**Generate security tests from Swagger/OpenAPI**

python main.py --swagger sample_data/sample_swagger.json

**Custom output file**

python main.py --postman my-api.json --output security_report.html

**🛠️ How It Works**

API-Sheild follows a three-step process to generate security test cases:

**1. Parse API Specification**

Extracts endpoints, parameters, methods, and authentication requirements

Analyzes request/response structures

Identifies sensitive parameters and business logic

**2. Apply Security Rules**

Matches endpoints against comprehensive security rules

Identifies potential vulnerabilities based on API context

Generates parameter-specific test cases

**3. Generate Comprehensive Report**

Creates detailed HTML report with all test cases

Provides step-by-step testing procedures

Includes ready-to-use payloads and exploitation guidance

Opens automatically in your default browser


📞 Support
For Queries / Feedback write to srahalkar@proton.me

If you find this tool useful, give a shout out on LinkedIn - https://www.linkedin.com/in/sagarrahalkar/

API-Sheild - Turning API specifications into comprehensive security test cases 🔐
