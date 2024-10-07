# Checklists ASVS Level 1

> **Level 1 is focusing on hackers that using “simple and low effort techniques”**
>
> This is the absolute minimum that we should include in any customer project. We need a buffer for that in every estimation.
> **Level 1** is for low assurance levels, and is completely penetration testable.

## Table of content

- [2. Authentication](#2.-Authentication)
- [3. Session Management](#3.-Session-Management)
- [4. Access Control](#4.-Access-Control)
- [5. Validation, Sanitization, and Encoding](#5.-Validation%2C-Sanitization%2C-and-Encoding)
- [6. Stored Cryptography](#6.-Stored-Cryptography)
- [7. Error Handling and Logging](#7.-Error-Handling-and-Logging)
- [8. Data Protection](#8.-Data-Protection)
- [9. Communication](#9.-Communication)
- [10. Malicious Code](#10.-Malicious-Code)
- [11. Business Logic](#11.-Business-Logic)
- [12. Files and Resources](#12.-Files-and-Resources)
- [13. API and Web Service](#13.-API-and-Web-Service)
- [14. Configuration](#14.-Configuration)

## Checklists 

### 2. Authentication

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **2.1** | **Password Security**                                        |            |
| 2.1.2   | Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined). |            |
| 2.1.2   | Verify that passwords of at least 64 characters are permitted and that passwords of more than 128 characters are denied. |            |
| 2.1.3   | Verify that password truncation is not performed. However, consecutive multiple spaces may be replaced by a single space |            |
| 2.1.4   | Verify that any printable Unicode character, including language neutral characters such as spaces and Emojis are permitted in passwords. |            |
| 2.1.5   | Verify users can change their password                       |            |
| 2.1.6   | Verify that password change functionality requires the user's current and new password |            |
| 2.1.7   | Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. If the password is breached, the application must require the user to set a new non-breached password |            |
| 2.1.8   | Verify that a password strength meter is provided to help users set a stronger password. |            |
| 2.1.9   | Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters |            |
| 2.1.10  | Verify that there are no periodic credential rotation or password history requirements. |            |
| 2.1.11  | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. |            |
| 2.1.12  | Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not have this as built-in functionality. |            |
| **2.2** | **General Authenticator Security**                           |            |
| 2.2.1   | Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. Such controls include blocking the most common breached passwords, soft lockouts, rate limiting, CAPTCHA, ever increasing delays between attempts, IP address restrictions, or risk-based restrictions such as location, first login on a device, recent attempts to unlock the account, or similar. Verify that no more than 100 failed attempts per hour is possible on a single account. |            |
| 2.2.2   | Verify that the use of weak authenticators (such as SMS and email) is limited to secondary verification and transaction approval and not as a replacement for more secure authentication methods. Verify that stronger methods are offered before weak methods, users are aware of the risks, or that proper measures are in place to limit the risks of account compromise. |            |
| 2.2.3   | Verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address changes, logging in from unknown or risky locations. The use of push notifications - rather than SMS or email - is preferred, but in the absence of push notifications, SMS or email is acceptable as long as no sensitive information is disclosed in the notification. |            |
| **2.3** | **Authenticator Lifecycle**                                  |            |
| 2.3.1   | Verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters long, and MAY contain letters and numbers, and expire after a short period of time. These initial secrets must not be permitted to become the long term password. |            |
| **2.5** | **Credential Recovery**                                      |            |
| 2.5.1   | Verify that a system generated initial activation or recovery secret is not sent in clear text to the user. |            |
| 2.5.2   | Verify password hints or knowledge-based authentication (so-called "secret questions") are not present. |            |
| 2.5.3   | Verify password credential recovery does not reveal the current password in any way. |            |
| 2.5.4   | Verify shared or default accounts are not present (e.g. "root", "admin", or "sa"). |            |
| 2.5.5   | Verify that if an authentication factor is changed or replaced, that the user is notified of this event. |            |
| 2.5.6   | Verify forgotten password, and other recovery paths use a secure recovery mechanism, such as time-based OTP (TOTP) or other soft token, mobile push, or another offline recovery mechanism. |            |
| **2.7** | **Out of Band Verifier**                                     |            |
| 2.7.1   | Verify that clear text out of band (NIST "restricted") authenticators, such as SMS or PSTN, are not offered by default, and stronger alternatives such as push notifications are offered first. |            |
| 2.7.2   | Verify that the out of band verifier expires out of band authentication requests, codes, or tokens after 10 minutes. |            |
| 2.7.3   | Verify that the out of band verifier authentication requests, codes, or tokens are only usable once, and only for the original authentication request. |            |
| 2.7.4   | Verify that the out of band authenticator and verifier communicates over a secure independent channel. |            |
| **2.8** | **One Time Verifier**                                        |            |
| 2.8.1   | Verify that time-based OTPs have a defined lifetime before expiring. |            |

### 3. Session Management

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **3.1** | **Fundamental Session Management Security**                  |            |
| 3.1.1   | Verify the application never reveals session tokens in URL parameters. |            |
| **3.2** | **Session Binding**                                          |            |
| 3.2.1   | Verify the application generates a new session token on user authentication. |            |
| 3.2.2   | Verify that session tokens possess at least 64 bits of entropy |            |
| 3.2.3   | Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage. |            |
| **3.3** | **Session Termination**                                      |            |
| 3.3.1   | Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties |            |
| 3.3.2   | If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. (30 days) |            |
| **3.4** | **Cookie-based Session Management**                          |            |
| 3.4.1   | Verify that cookie-based session tokens have the 'Secure' attribute set. |            |
| 3.4.2   | Verify that cookie-based session tokens have the 'HttpOnly' attribute set. |            |
| 3.4.3   | Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks. |            |
| 3.4.4   | Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie. |            |
| 3.4.5   | Verify that if the application is published under a domain name with other applications that set or use session cookies that might disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible. |            |
| **3.7** | **Defenses Against Session Management Exploits**             |            |
| 3.7.1   | Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications. |            |

### 4. Access Control

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **4.1** | **General Access Control Design**                            |            |
| 4.1.1   | Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed |            |
| 4.1.2   | Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized. |            |
| 4.1.3   | Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege |            |
| 4.1.5   | Verify that access controls fail securely including when an exception occurs. |            |
| **4.2** | **Operation Level Access Control**                           |            |
| 4.2.1   | Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records. |            |
| 4.2.2   | Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality. |            |
| **4.3** | **Other Access Control Considerations**                      |            |
| 4.3.1   | Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use. |            |
| 4.3.2   | Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders. |            |

### 5. Validation, Sanitization, and Encoding

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **5.1** | **Input Validation**                                         |            |
| 5.1.1   | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables). |            |
| 5.1.2   | Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar. |            |
| 5.1.3   | Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow lists). |            |
| 5.1.4   | Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail addresses, telephone numbers, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match). |            |
| 5.1.5   | Verify that URL redirects and forwards only allow destinations which appear on an allow list, or show a warning when redirecting to potentially untrusted content. |            |
| **5.2** | **Sanitization and Sandboxing**                              |            |
| 5.2.1   | Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature. |            |
| 5.2.2   | Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length. |            |
| 5.2.3   | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. |            |
| 5.2.4   | Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user input being included must be sanitized or sandboxed before being executed. |            |
| 5.2.5   | Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or sandboxed. |            |
| 5.2.6   | Verify that the application protects against SSRF attacks, by validating or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields, and uses allow lists of protocols, domains, paths and ports. |            |
| 5.2.7   | Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, especially as they relate to XSS resulting from inline scripts, and foreignObject. |            |
| 5.2.8   | Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. |            |
| **5.3** | **Output Encoding and Injection Prevention**                 |            |
| 5.3.1   | Verify that output encoding is relevant for the interpreter and context required. For example, use encoders specifically for HTML values, HTML attributes, JavaScript, URL parameters, HTTP headers, SMTP, and others as the context requires, especially from untrusted inputs (e.g. names with Unicode or apostrophes, such as ねこ or O'Hara). |            |
| 5.3.2   | Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled. |            |
| 5.3.3   | Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS. |            |
| 5.3.4   | Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks |            |
| 5.3.5   | Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection. |            |
| 5.3.6   | Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation. |            |
| 5.3.7   | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. |            |
| 5.3.8   | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. |            |
| 5.3.9   | Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks. |            |
| 5.3.10  | Verify that the application protects against XPath injection or XML injection attacks. |            |
| **5.5** | **Deserialization Prevention**                               |            |
| 5.5.1   | Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering. |            |
| 5.5.2   | Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. |            |
| 5.5.3   | Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers). |            |
| 5.5.4   | Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON. |            |

### 6. Stored Cryptography

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **6.2** | **Algorithms**                                               |            |
| 6.2.1   | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks. |            |

### 7. Error Handling and Logging

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **7.1** | **Log Content**                                              |            |
| 7.1.1   | Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form. |            |
| 7.1.2   | Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy. |            |
| **7.4** | **Error Handling**                                           |            |
| 7.4.1   | Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate. |            |

### 8. Data Protection

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **8.2** | **Client-side Data Protection**                              |            |
| 8.2.1   | Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers. |            |
| 8.2.2   | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data. |            |
| 8.2.3   | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. |            |
| **8.3** | **Sensitive Private Data**                                   |            |
| 8.3.1   | Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data. |            |
| 8.3.2   | Verify that users have a method to remove or export their data on demand. |            |
| 8.3.3   | Verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided opt-in consent for the use of that data before it is used in any way. |            |
| 8.3.4   | Verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how to deal with sensitive data. |            |

### 9. Communication

| **No.** | **Name**                                                     | **Result** |
| ------- | ------------------------------------------------------------ | ---------- |
| **9.1** | **Client Communication Security**                            |            |
| 9.1.1   | Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications. |            |
| 9.1.2   | Verify using up to date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred. |            |
| 9.1.3   | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol should be the preferred option. |            |

### 10. Malicious Code

| **No.**  | **Name**                                                     | **Result** |
| -------- | ------------------------------------------------------------ | ---------- |
| **10.3** | **Application Integrity**                                    |            |
| 10.3.1   | Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally signed. The update code must validate the digital signature of the update before installing or executing the update |            |
| 10.3.2   | Verify that the application employs integrity protections, such as code signing or subresource integrity. The application must not load or execute code from untrusted sources, such as loading includes, modules, plugins, code, or libraries from untrusted sources or the Internet. |            |
| 10.3.3   | Verify that the application has protection from subdomain takeovers if the application relies upon DNS entries or DNS subdomains, such as expired domain names, out of date DNS pointers or CNAMEs, expired projects at public source code repos, or transient cloud APIs, serverless functions, or storage buckets ([autogen-bucket-id.cloud.example.com](http://autogen-bucket-id.cloud.example.com)) or similar. Protections can include ensuring that DNS names used by applications are regularly checked for expiry or change. |            |

### 11. Business Logic

| **No.**  | **Name**                                                     | **Result** |
| -------- | ------------------------------------------------------------ | ---------- |
| **11.1** | **Business Logic Security**                                  |            |
| 11.1.1   | Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps. |            |
| 11.1.2   | Verify that the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly. |            |
| 11.1.3   | Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user basis. |            |
| 11.1.4   | Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads or denial of service attacks. |            |
| 11.1.5   | Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modeling or similar methodologies. |            |

### 12. Files and Resources

| **No.**  | **Name**                                                     | **Result** |
| -------- | ------------------------------------------------------------ | ---------- |
| **12.1** | **File Upload**                                              |            |
| 12.1.1   | Verify that the application will not accept large files that could fill up storage or cause a denial of service. |            |
| **12.3** | **File Execution**                                           |            |
| 12.3.1   | Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal. |            |
| 12.3.2   | Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI). |            |
| 12.3.3   | Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files via Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. |            |
| 12.3.4   | Verify that the application protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter, the response Content-Type header should be set to text/plain, and the Content-Disposition header should have a fixed filename. |            |
| 12.3.5   | Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection. |            |
| **12.4** | **File Storage**                                             |            |
| 12.4.1   | Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions. |            |
| 12.4.2   | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload and serving of known malicious content. |            |
| **12.5** | **File Download**                                            |            |
| 12.5.1   | Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage. For example, backup files (e.g. .bak), temporary working files (e.g. .swp), compressed files (.zip, .tar.gz, etc) and other extensions commonly used by editors should be blocked unless required. |            |
| 12.5.2   | Verify that direct requests to uploaded files will never be executed as HTML/JavaScript content. |            |
| **12.6** | **SSRF Protection**                                          |            |
| 12.6.1   | Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests or load data/files from. |            |

### 13. API and Web Service

| **No.**  | **Name**                                                     | **Result** |
| -------- | ------------------------------------------------------------ | ---------- |
| **13.1** | **Generic Web Service Security**                             |            |
| 13.1.1   | Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks. |            |
| 13.1.3   | Verify API URLs do not expose sensitive information, such as the API key, session tokens etc. |            |
| **13.2** | **RESTful Web Service**                                      |            |
| 13.2.1   | Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources. |            |
| 13.2.2   | Verify that JSON schema validation is in place and verified before accepting input. |            |
| 13.2.3   | Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks. |            |
| **13.3** | **SOAP Web Service**                                         |            |
| 13.3.1   | Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place. |            |

### 14. Configuration

| **No.**  | **Name**                                                     | **Result** |
| -------- | ------------------------------------------------------------ | ---------- |
| **14.2** | **Dependency**                                               |            |
| 14.2.1   | Verify that all components are up to date, preferably using a dependency checker during build or compile time. |            |
| 14.2.2   | Verify that all unneeded features, documentation, sample applications and configurations are removed. |            |
| 14.2.3   | Verify that if application assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset. |            |
| **14.3** | **Unintended Security Disclosure**                           |            |
| 14.3.2   | Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures. |            |
| 14.3.3   | Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components. |            |
| **14.4** | **HTTP Security Headers**                                    |            |
| 14.4.1   | Verify that every HTTP response contains a Content-Type header. Also specify a safe character set (e.g., UTF-8, ISO-8859-1) if the content types are text/*, /+xml and application/xml. Content must match with the provided Content-Type header. |            |
| 14.4.2   | Verify that all API responses contain a Content-Disposition: attachment; filename="api.json" header (or other appropriate filename for the content type). |            |
| 14.4.3   | Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities. |            |
| 14.4.4   | Verify that all responses contain a X-Content-Type-Options: nosniff header. |            |
| 14.4.5   | Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains. |            |
| 14.4.6   | Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties. |            |
| 14.4.7   | Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact resources is only allowed where necessary by using suitable Content-Security-Policy: frame-ancestors and X-Frame-Options response headers. |            |
| **14.5** | **HTTP Request Header Validation**                           |            |
| 14.5.1   | Verify that the application server only accepts the HTTP methods in use by the application/API, including pre-flight OPTIONS, and logs/alerts on any requests that are not valid for the application context. |            |
| 14.5.2   | Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker. |            |
| 14.5.3   | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted domains and subdomains to match against and does not support the "null" origin. |            |