

# Checklists ASVS Level 2

> **Level 2 is focusing “skilled and motivated attackers”**
>
> This should be offered to every customer and will increase the estimation by a value that should be specified. This level should be mandatory for customers that handle user data in any way. OWASP proposed to use this level for projects that handle “significant business-to-business transactions, including those that process healthcare information, implement business-critical or sensitive functions, or process other sensitive assets, or industries where integrity is a critical facet to protect their business, such as the game industry to thwart cheaters and game hacks.“
> **Level 2** is for applications that contain sensitive data, which requires protection and is the recommended level for most apps.

## Table of content

- [1. Architecture, Design, and Threat Modeling](#1.-Architecture%2C-Design%2C-and-Threat-Modeling)
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

### 1. Architecture, Design, and Threat Modeling

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **1.1**  | **Secure Software Development Lifecycle**                    |            |
| 1.1.1    | Verify the use of a secure software development lifecycle that addresses security in all stages of development. |            |
| 1.1.2    | Verify the use of threat modeling for every design change or sprint planning to identify threats, plan for countermeasures, facilitate appropriate risk responses, and guide security testing. |            |
| 1.1.3    | Verify that all user stories and features contain functional security constraints, such as "As a user, I should be able to view and edit my profile. I should not be able to view or edit anyone else's profile" |            |
| 1.1.4    | Verify documentation and justification of all the application's trust boundaries, components, and significant data flows. |            |
| 1.1.5    | Verify definition and security analysis of the application's high-level architecture and all connected remote services. |            |
| 1.1.6    | Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls. |            |
| 1.1.7    | Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers. |            |
| **1.2**  | **Authentication Architecture**                              |            |
| 1.2.1    | Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers. |            |
| 1.2.2    | Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components should have the least necessary privileges needed. |            |
| 1.2.3    | Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient logging and monitoring to detect account abuse or breaches. |            |
| 1.2.4    | Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such that there are no weaker alternatives per the risk of the application. |            |
| **1.4**  | **Access Control Architecture**                              |            |
| 1.4.1    | Verify that trusted enforcement points, such as access control gateways, servers, and serverless functions, enforce access controls. Never enforce access controls on the client. |            |
| 1.4.4    | Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this single mechanism to avoid copy and paste or insecure alternative paths. |            |
| 1.4.5    | Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role. Permissions should still be allocated using roles. |            |
| **1.5**  | **Input and Output Architecture**                            |            |
| 1.5.1    | Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws, regulations, and other policy compliance. |            |
| 1.5.2    | Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity controls (and possibly encryption if sensitive data is sent) are enforced to prevent deserialization attacks including object injection. |            |
| 1.5.3    | Verify that input validation is enforced on a trusted service layer. |            |
| 1.5.4    | Verify that output encoding occurs close to or by the interpreter for which it is intended. |            |
| **1.6**  | **Cryptographic Architecture**                               |            |
| 1.6.1    | Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key management standard such as NIST SP 800-57. |            |
| 1.6.2    | Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API based alternatives. |            |
| 1.6.3    | Verify that all keys and passwords are replaceable and are part of a welldefined process to re-encrypt sensitive data. |            |
| 1.6.4    | Verify that the architecture treats client-side secrets--such as symmetric keys, passwords, or API tokens--as insecure and never uses them to protect or access sensitive data. |            |
| **1.7**  | **Errors, Logging and Auditing Architecture**                |            |
| 1.7.1    | Verify that a common logging format and approach is used across the system. |            |
| 1.7.2    | Verify that logs are securely transmitted to a preferably remote system for analysis, detection, alerting, and escalation. |            |
| **1.8**  | **Data Protection and Privacy Architecture**                 |            |
| 1.8.1    | Verify that all sensitive data is identified and classified into protection levels. |            |
| 1.8.2    | Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity requirements, retention, privacy and other confidentiality requirements, and that these are applied in the architecture. |            |
| **1.9**  | **Communications Architecture**                              |            |
| 1.9.1    | Verify the application encrypts communications between components, particularly when these components are in different containers, systems, sites, or cloud providers. |            |
| 1.9.2    | Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks. For example, application components should validate TLS certificates and chains. |            |
| **1.10** | **Malicious Software Architecture**                          |            |
| 1.10.1   | Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system should have access control and identifiable users to allow traceability of any changes. |            |
| **1.11** | **Business Logic Architecture**                              |            |
| 1.11.1   | Verify the definition and documentation of all application components in terms of the business or security functions they provide. |            |
| 1.11.2   | Verify that all high-value business logic flows, including authentication, session management and access control, do not share unsynchronized state. |            |
| **1.12** | **Secure File Upload Architecture**                          |            |
| 1.12.2   | Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, such as a cloud file storage bucket. Implement a suitable Content Security Policy (CSP) to reduce the risk from XSS vectors or other attacks from the uploaded file. |            |
| **1.14** | **Configuration Architecture**                               |            |
| 1.14.1   | Verify the segregation of components of differing trust levels through welldefined security controls, firewall rules, API gateways, reverse proxies, cloud-based security groups, or similar mechanisms. |            |
| 1.14.2   | Verify that binary signatures, trusted connections, and verified endpoints are used to deploy binaries to remote devices. |            |
| 1.14.3   | Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions. |            |
| 1.14.4   | Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application infrastructure is software defined, such as cloud environment build scripts. |            |
| 1.14.5   | Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers from attacking other applications, especially when they are performing sensitive or dangerous actions such as deserialization. |            |
| 1.14.6   | Verify the application does not use unsupported, insecure, or deprecated client-side technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. |            |

### 2. Authentication

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **2.3**  | **Authenticator Lifecycle**                                  |            |
| 2.3.1    | Verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters long, and MAY contain letters and numbers, and expire after a short period of time. These initial secrets must not be permitted to become the long term password. |            |
| 2.3.2    | Verify that enrollment and use of user-provided authentication devices are supported, such as a U2F or FIDO tokens. |            |
| 2.3.3    | Verify that renewal instructions are sent with sufficient time to renew time bound authenticators. |            |
| **2.4**  | **Credential Storage**                                       |            |
| 2.4.1    | Verify that passwords are stored in a form that is resistant to offline attacks. Passwords SHALL be salted and hashed using an approved one-way key derivation or password hashing function. Key derivation and password hashing functions take a password, a salt, and a cost factor as inputs when generating a password hash. |            |
| 2.4.2    | Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For each credential, a unique salt value and the resulting hash SHALL be stored. |            |
| 2.4.3    | Verify that if PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, typically at least 100,000 iterations. |            |
| 2.4.4    | Verify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, with a minimum of 10. |            |
| 2.4.5    | Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier. Generate the salt value using an approved random bit generator [SP 800-90Ar1] and provide at least the minimum security strength specified in the latest revision of SP 800-131A. The secret salt value SHALL be stored separately from the hashed passwords (e.g., in a specialized device like a hardware security module). |            |
| **2.5**  | **Credential Recovery**                                      |            |
| 2.5.7    | Verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as during enrollment. |            |
| **2.6**  | **Look-up Secret Verifier**                                  |            |
| 2.6.1    | Verify that lookup secrets can be used only once.            |            |
| 2.6.2    | Verify that lookup secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with an approved one-way hash. |            |
| 2.6.3    | Verify that lookup secrets are resistant to offline attacks, such as predictable values. |            |
| **2.7**  | **Out of Band Verifier**                                     |            |
| 2.7.5    | Verify that the out of band verifier retains only a hashed version of the authentication code. |            |
| 2.7.6    | Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six digital random number is sufficient). |            |
| **2.8**  | **One Time Verifier**                                        |            |
| 2.8.2    | Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system based key storage. |            |
| 2.8.3    | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification of OTPs. |            |
| 2.8.4    | Verify that time-based OTP can be used only once within the validity period. |            |
| 2.8.5    | Verify that if a time-based multi-factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the device. |            |
| 2.8.6    | Verify physical single-factor OTP generator can be revoked in case of theft or other loss. Ensure that revocation is immediately effective across logged in sessions, regardless of location. |            |
| 2.8.7    | Verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know. |            |
| **2.9**  | **Cryptographic Verifier**                                   |            |
| 2.9.1    | Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a Trusted Platform Module (TPM) or Hardware Security Module (HSM), or an OS service that can use this secure storage. |            |
| 2.9.2    | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. |            |
| 2.9.3    | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification. |            |
| **2.10** | **Service Authentication**                                   |            |
| 2.10.1   | Verify that intra-service secrets do not rely on unchanging credentials such as passwords, API keys or shared accounts with privileged access. |            |
| 2.10.2   | Verify that if passwords are required for service authentication, the service account used is not a default credential. (e.g. root/root or admin/admin are default in some services during installation). |            |
| 2.10.3   | Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access. |            |
| 2.10.4   | Verify passwords, integrations with databases and thirdparty systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1), hardware TPM, or an HSM (L3) is recommended for password storage. |            |

### 3. Session Management

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **3.2** | **Session Binding**                                          |            |
| 3.2.4   | Verify that session tokens are generated using approved cryptographic algorithms. |            |
| **3.3** | **Session Termination**                                      |            |
| 3.3.2   | If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. (12 hours or 30 minutes of inactivity, 2FA optional) |            |
| 3.3.3   | Verify that the application gives the option to terminate all other active sessions after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties. |            |
| 3.3.4   | Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices. |            |
| **3.5** | **Token-based Session Management**                           |            |
| 3.5.1   | Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications. |            |
| 3.5.2   | Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations. |            |
| 3.5.3   | Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks. |            |

### 4. Access Control

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **4.3** | **Other Access Control Considerations**                      |            |
| 4.3.3   | Verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or segregation of duties for high value applications to enforce anti-fraud controls as per the risk of application and past fraud. |            |

### 5. Validation, Sanitization, and Encoding

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **5.4** | **Memory, String, and Unmanaged Code**                       |            |
| 5.4.1   | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. |            |
| 5.4.2   | Verify that format strings do not take potentially hostile input, and are constant. |            |
| 5.4.3   | Verify that sign, range, and input validation techniques are used to prevent integer overflows. |            |

### 6. Stored Cryptography

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **6.1** | **Data Classification**                                      |            |
| 6.1.1   | Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed likely to be subject to EU's GDPR. |            |
| 6.1.2   | Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized research records. ✓ |            |
| 6.1.3   | Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history, beneficiaries, or de-anonymized market or research records. |            |
| **6.2** | **Algorithms**                                               |            |
| 6.2.2   | Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography. |            |
| 6.2.3   | Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice. |            |
| 6.2.4   | Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers or modes, can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. |            |
| 6.2.5   | Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e. Triple-DES, Blowfish, etc.), and weak hashing algorithms (i.e. MD5, SHA1, etc.) are not used unless required for backwards compatibility. |            |
| 6.2.6   | Verify that nonces, initialization vectors, and other single use numbers must not be used more than once with a given encryption key. The method of generation must be appropriate for the algorithm being used. |            |
| **6.3** | **Random Values**                                            |            |
| 6.3.1   | Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure random number generator when these random values are intended to be not guessable by an attacker. |            |
| 6.3.2   | Verify that random GUIDs are created using the GUID v4 algorithm, and a Cryptographically-secure Pseudo-random Number Generator (CSPRNG). GUIDs created using other pseudo-random number generators may be predictable. |            |
| **6.4** | **Secret Management**                                        |            |
| 6.4.1   | Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets. |            |
| 6.4.2   | Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations. |            |

### 7. Error Handling and Logging

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **7.1** | **Log Content**                                              |            |
| 7.1.3   | Verify that the application logs security relevant events including successful and failed authentication events, access control failures, deserialization failures and input validation failures. |            |
| 7.1.4   | Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens. |            |
| **7.2** | **Log Processing**                                           |            |
| 7.2.1   | Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords. This should include requests with relevant metadata needed for security investigations. |            |
| 7.2.2   | Verify that all access control decisions can be logged and all failed decisions are logged. This should include requests with relevant metadata needed for security investigations. |            |
| **7.3** | **Log Protection**                                           |            |
| 7.3.1   | Verify that all logging components appropriately encode data to prevent log injection. |            |
| 7.3.3   | Verify that security logs are protected from unauthorized access and modification. |            |
| 7.3.4   | Verify that time sources are synchronized to the correct time and time zone. Strongly consider logging only in UTC if systems are global to assist with postincident forensic analysis. |            |
| **7.4** | **Error Handling**                                           |            |
| 7.4.2   | Verify that exception handling (or a functional equivalent) is used across the codebase to account for expected and unexpected error conditions. |            |
| 7.4.3   | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. |            |

### 8. Data Protection

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **8.1** | **General Data Protection**                                  |            |
| 8.1.1   | Verify the application protects sensitive data from being cached in server components such as load balancers and application caches. |            |
| 8.1.2   | Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user accesses the sensitive data. |            |
| 8.1.3   | Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values. |            |
| 8.1.4   | Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application. |            |
| **8.3** | **Sensitive Private Data**                                   |            |
| 8.3.5   | Verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data protection directives or where logging of access is required. |            |
| 8.3.6   | Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data. |            |
| 8.3.7   | Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity. |            |
| 8.3.8   | Verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted automatically, on a schedule, or as the situation requires. |            |

### 9. Communication

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **9.2** | **Server Communication Security**                            |            |
| 9.2.1   | Verify that connections to and from the server use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected. |            |
| 9.2.2   | Verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports, monitoring, authentication, API, or web service calls, database, cloud, serverless, mainframe, external, and partner connections. The server must not fall back to insecure or unencrypted protocols. |            |
| 9.2.3   | Verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated. |            |
| 9.2.4   | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. |            |

### 10. Malicious Code

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **10.2** | **Malicious Code Search**                                    |            |
| 10.2.1   | Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities. Where such functionality exists, obtain the user's permission for it to operate before collecting any data. |            |
| 10.2.2   | Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location. |            |

### 11. Business Logic

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **11.1** | **Business Logic Security**                                  |            |
| 11.1.6   | Verify that the application does not suffer from "Time Of Check to Time Of Use" (TOCTOU) issues or other race conditions for sensitive operations. |            |
| 11.1.7   | Verify that the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform actions out of order or actions which a normal user would never attempt. |            |
| 11.1.8   | Verify that the application has configurable alerting when automated attacks or unusual activity is detected. |            |

### 12. Files and Resources

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **12.1** | **File Upload**                                              |            |
| 12.1.2   | Verify that the application checks compressed files (e.g. zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. |            |
| 12.1.3   | Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. |            |
| **12.2** | **File Integrity**                                           |            |
| 12.2.1   | Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content. |            |
| **12.3** | **File Execution**                                           |            |
| 12.3.6   | Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node npm libraries, or server-side DLLs. |            |

### 13. API and Web Service

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **13.1** | **Generic Web Service Security**                             |            |
| 13.1.4   | Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, enforced by model-based permissions. |            |
| 13.1.5   | Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type). |            |
| **13.2** | **RESTful Web Service**                                      |            |
| 13.2.5   | Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json. |            |
| 13.2.6   | Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases as it provides both confidentiality and integrity protection. Per-message digital signatures can provide additional assurance on top of the transport protections for high-security applications but bring with them additional complexity and risks to weigh against the benefits. |            |
| **13.3** | **SOAP Web Service**                                         |            |
| 13.3.2   | Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service. |            |
| **13.4** | **GraphQL**                                                  |            |
| 13.4.1   | Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. For more advanced scenarios, query cost analysis should be used. |            |
| 13.4.2   | Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer. |            |

### 14. Configuration

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **14.1** | **Build and Deploy**                                         |            |
| 14.1.1   | Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI / CD automation, automated configuration management, and automated deployment scripts. |            |
| 14.1.2   | Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found. |            |
| 14.1.3   | Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use. |            |
| 14.1.4   | Verify that the application, configuration, and all dependencies can be redeployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion. |            |
| **14.2** | **Dependency**                                               |            |
| 14.2.4   | Verify that third party components come from pre-defined, trusted and continually maintained repositories. |            |
| 14.2.5   | Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use. |            |
| 14.2.6   | Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application. |            |
| **14.5** | **HTTP Request Header Validation**                           |            |
| 14.5.4   | Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application. |            |