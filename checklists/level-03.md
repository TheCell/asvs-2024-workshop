

# Checklists ASVS Level 3

> **Level 3 is focusing on “professional and high motivated hackers”**
>
> Is the highest level of security. “This level is typically reserved for applications that require significant levels of security verification, such as those that may be found within areas of military, health and safety, critical infrastructure, etc.“. This level should also be proposed to banks, power grid providers.
> **Level 3** is for the most critical applications - applications that perform high value transactions, contain sensitive medical data, or any application that requires the highest level of trust.

## Table of content

- [1. Architecture, Design, and Threat Modeling](#1.-Architecture%2C-Design%2C-and-Threat-Modeling)
- [2. Authentication](#2.-Authentication)
- [3. Session Management](#3.-Session-Management)
- [6. Stored Cryptography](#6.-Stored-Cryptography)
- [8. Data Protection](#8.-Data-Protection)
- [9. Communication](#9.-Communication)
- [10. Malicious Code](#10.-Malicious-Code)
- [14. Configuration](#14.-Configuration)

## Checklists

### 1. Architecture, Design, and Threat Modeling

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **1.11** | **Business Logic Architecture**                              |            |
| 1.11.3   | Verify that all high-value business logic flows, including authentication, session management and access control are thread safe and resistant to time-of-check and time-of-use race conditions. |            |

### 2. Authentication

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **2.2** | **General Authenticator Security**                           |            |
| 2.2.4   | Verify impersonation resistance against phishing, such as the use of multi-factor authentication, cryptographic devices with intent (such as connected keys with a push to authenticate), or at higher AAL levels, client-side certificates. |            |
| 2.2.5   | Verify that where a Credential Service Provider (CSP) and the application verifying authentication are separated, mutually authenticated TLS is in place between the two endpoints. |            |
| 2.2.6   | Verify replay resistance through the mandated use of One-time Passwords (OTP) devices, cryptographic authenticators, or lookup codes. |            |
| 2.2.7   | Verify intent to authenticate by requiring the entry of an OTP token or user-initiated action such as a button press on a FIDO hardware key. |            |

### 3. Session Management

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **3.3** | **Session Termination**                                      |            |
| 3.3.2   | If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. (12 hours or 15 minutes of inactivity, 2FA optional) |            |
| **3.6** | **Federated Re-authentication**                              |            |
| 3.6.1   | Verify that Relying Parties (RPs) specify the maximum authentication time to Credential Service Providers (CSPs) and that CSPs reauthenticate the user if they haven't used a session within that period. |            |
| 3.6.2   | Verify that Credential Service Providers (CSPs) inform Relying Parties (RPs) of the last authentication event, to allow RPs to determine if they need to re-authenticate the user. |            |

### 6. Stored Cryptography

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **6.2** | **Algorithms**                                               |            |
| 6.2.7   | Verify that encrypted data is authenticated via signatures, authenticated cipher modes, or HMAC to ensure that ciphertext is not altered by an unauthorized party. |            |
| 6.2.8   | Verify that all cryptographic operations are constant-time, with no 'shortcircuit' operations in comparisons, calculations, or returns, to avoid leaking information. |            |
| **6.3** | **Random Values**                                            |            |
| 6.3.3   | Verify that random numbers are created with proper entropy even when the application is under heavy load, or that the application degrades gracefully in such circumstances. |            |

### 8. Data Protection

| **No.** | **Name**                                                     | **Result** |
| :------ | :----------------------------------------------------------- | :--------- |
| **8.1** | **General Data Protection**                                  |            |
| 8.1.5   | Verify that regular backups of important data are performed and that test restoration of data is performed. |            |
| 8.1.6   | Verify that backups are stored securely to prevent data from being stolen or corrupted. |            |

### 9. Communication

| **No.** | **Name**                                                | **Result** |
| :------ | :------------------------------------------------------ | :--------- |
| **9.2** | **Server Communication Security**                       |            |
| 9.2.5   | Verify that backend TLS connection failures are logged. |            |

### 10. Malicious Code

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **10.1** | **Code Integrity**                                           |            |
| 10.1.1   | Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations and network connections. |            |
| **10.2** | **Malicious Code Search**                                    |            |
| 10.2.3   | Verify that the application source code and third party libraries do not contain back doors, such as hard-coded or additional undocumented accounts or keys, code obfuscation, undocumented binary blobs, rootkits, or anti-debugging, insecure debugging features, or otherwise out of date, insecure, or hidden functionality that could be used maliciously if discovered. |            |
| 10.2.4   | Verify that the application source code and third party libraries do not contain time bombs by searching for date and time related functions |            |
| 10.2.5   | Verify that the application source code and third party libraries do not contain malicious code, such as salami attacks, logic bypasses, or logic bombs. |            |
| 10.2.6   | Verify that the application source code and third party libraries do not contain Easter eggs or any other potentially unwanted functionality. |            |

### 14. Configuration

| **No.**  | **Name**                                                     | **Result** |
| :------- | :----------------------------------------------------------- | :--------- |
| **14.1** | **Build and Deploy**                                         |            |
| 14.1.5   | Verify that authorized administrators can verify the integrity of all securityrelevant configurations to detect tampering. |            |