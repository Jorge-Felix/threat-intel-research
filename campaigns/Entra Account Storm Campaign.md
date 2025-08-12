# CTI Report: Entra Account Storm Campaign

## 1. Executive Summary

The "Entra Account Storm Campaign" is a targeted cyberattack campaign focused on Microsoft Entra ID accounts. Threat actors, identified as **Storm-2372** and **Storm-0558**, use automated tools to perform password spraying, gain unauthorized access, and exfiltrate data. The attacks occur in waves, often originating from cloud services like AWS, combining stealth with bursts of intense activity. This campaign highlights the significant risks posed by weak credentials and insufficient cloud security monitoring.

*   **Detected Activity Period:** The campaign has been active since at least December 2024, with a peak in activity observed in January and February 2025.
*   **Affected Industries:** Government, NGOs, IT services, technology, defense, telecommunications, healthcare, and energy/oil & gas.
*   **Affected Regions:** Attacks originate primarily from infrastructure in the United States (Virginia) and Ireland (Dublin).

---

## 2. Context and Origin

*   **First Documented Detections:** Microsoft was first notified of anomalous data access on June 16, 2023, which was attributed to the threat actor **Storm-0558**. The actor was observed accessing Exchange Online data via Outlook Web Access (OWA).
*   **Probable Motivation:** The primary motivation appears to be espionage and data theft. The actor targets organizations to gain unauthorized access to email accounts and sensitive data through credential harvesting, phishing, and OAuth token attacks.
*   **Attribution:** Microsoft Threat Intelligence assesses with moderate confidence that **Storm-0558** is a China-based threat actor. While there are minor overlaps with other groups like Violet Typhoon (APT31), Storm-0558 is considered a distinct group.

---

## 3. Tactics, Techniques, and Procedures (TTPs)

The campaign utilizes the following MITRE ATT&CK techniques:

| Tactic | Technique ID | Technique Name | Description |
| :--- | :--- | :--- | :--- |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Attackers exploit software vulnerabilities to execute code with elevated permissions. This includes "Bring Your Own Vulnerable Driver" (BYOVD) tactics to bypass system restrictions. |
| Privilege Escalation, Defense Evasion | T1134 | Access Token Manipulation | The actor modifies access tokens to operate under a different user's security context (e.g., SYSTEM), evading standard access controls. APIs like `LogonUser` and `DuplicateTokenEx` are used for this purpose. |
| Credential Access | T1110 | Brute Force | This technique involves systematically guessing credentials. The campaign specifically uses the following sub-technique: |
| Credential Access | T1110.003 | Password Spraying | Instead of targeting one account with many passwords, the attacker uses a single common password against many different accounts. This method avoids account lockouts and effectively exploits weak or common passwords across an organization. |

---

## 4. Infrastructure and Hosting

*   **Cloud Providers:** The attack infrastructure is hosted on **Amazon Web Services (AWS)**. All identified IoCs belong to ASN **AS14618 (AMAZON-AES)**.
*   **Geographic Location of Attack Nodes:**
    *   **Primary:** Ashburn, Virginia, United States
    *   **Secondary:** Dublin, Ireland

---

## 5. Indicators of Compromise (IoCs)

The following IP addresses have been identified as part of the attacker's infrastructure:

*   `44.218.97.232`
*   `44.220.31.157`
*   `44.206.7.122`
*   `44.210.64.196`
*   `44.212.180.197`
*   `3.238.215.143`
*   `44.206.7.134`
*   `3.216.140.96`
*   `3.255.18.223`
*   `44.210.66.100`

---

## 6. Impact and Risk

### Data Exfiltration Risk

*   **Communication Data:** Access to emails (Exchange Online) and Microsoft Teams messages, revealing strategic plans, customer data, and internal discussions.
*   **Confidential Files:** Access to SharePoint Online and OneDrive, leading to the theft of intellectual property, financial reports, HR files, and legal documents.
*   **Identity and Configuration Data:** Exfiltration of user lists, organizational structure, and security policy details from Entra ID to plan future attacks.
*   **Third-Party Application Data:** If Entra ID is used for SSO, the compromise could extend to connected SaaS platforms like Salesforce, Workday, or GitHub.

### Operational and Reputational Risk

*   **Privilege Escalation:** High potential for attackers to escalate privileges to Global Administrator, leading to full tenant takeover.
*   **Reputational Impact:** A breach can lead to a loss of customer trust, brand damage, and a negative impact on stock value.
*   **Regulatory Impact:** The organization could face significant fines under regulations like GDPR and CCPA, mandatory breach notifications, and potential class-action lawsuits.

---

## 7. Detection Measures

Detection relies on monitoring **AuditLogs** and **SigninLogs** in the Microsoft Entra ID environment.

### Key Signals in `SigninLogs`

*   **Massive Sign-in Failures (Password Spraying):** A high volume of failed logins (`ResultType: 50126`) for many different users from a single IP address.
*   **Impossible Travel:** Successful logins for a single user from geographically distant locations in a short time.
*   **Logins from Anonymous/Suspicious IPs:** Access attempts from Tor nodes or known malicious IPs.
*   **Success After Multiple Failures:** A burst of failed login attempts followed by a successful one from the same IP.
*   **Legacy Authentication Usage:** Logins using protocols like POP3, IMAP, or SMTP that do not support MFA.

### Key Events in `AuditLogs`

*   **Privileged Role Assignment:** Monitor the `Add member to role` event for roles like "Global Administrator," "Privileged Role Administrator," or "Cloud Application Administrator."
*   **Adding Credentials to Service Principals:** Look for `Update Application - Credentials` or `Add service principal credentials` events, which indicate a persistence technique.
*   **Federation Settings Changes:** The `Set federation settings on domain` event could indicate an attacker is adding their own identity provider.

### KQL Detection Query

The following KQL query can be used in Microsoft Sentinel to detect activities associated with this campaign.

```kql
// This query combines multiple detection techniques for Microsoft Entra ID
// privilege escalation and password spraying attacks.
// It is designed to identify several TTPs associated with the "Entra
// Account Storm" campaign.

// Define a lookback period for the search.
let lookback = 1d;

// Part 1: Detects the assignment of highly privileged roles in Entra ID.
// Legitimate administrative activity can trigger this, so review the actor
// and target context.
let privilegedRoleAssignments = AuditLogs
 | where TimeGenerated > ago(lookback)
 | where Category == "RoleManagement" and OperationName == "Add member to role"
 | extend RoleDisplayName = tostring(TargetResources[0].modifiedProperties[0].newValue)
 | where RoleDisplayName has_any (
 "Global Administrator",
 "Privileged Role Administrator",
 "Cloud Application Administrator",
 "Application Administrator",
 "Hybrid Identity Administrator"
 )
 | extend TargetUser = tostring(TargetResources[0].userPrincipalName)
 | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
 | project
     TimeGenerated,
     DetectionType = "Privileged Role Assigned",
     Actor,
     TargetUser,
     RoleAssigned = RoleDisplayName,
     Description = strcat("User '", Actor, "' assigned role '", RoleAssigned, "' to user '", TargetUser, "'.")
 | extend IPAddress = tostring(InitiatedBy.user.ipAddress);

// Part 2: Detects when new credentials are added to an Application or Service Principal.
// This is a key persistence and escalation technique.
let credentialAddition = AuditLogs
 | where TimeGenerated > ago(lookback)
 | where OperationName in ("Update Application - Credentials", "Add service principal credentials", "Update service principal credentials")
 | extend TargetName = tostring(TargetResources[0].displayName)
 | extend TargetId = tostring(TargetResources[0].id)
 | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
 | project
     TimeGenerated,
     DetectionType = "Credentials Added to Principal",
     Actor,
     TargetName,
     TargetId,
     Description = strcat("User '", Actor, "' added new credentials to principal '", TargetName, "'.")
 | extend IPAddress = tostring(InitiatedBy.user.ipAddress);

// Part 3: Detects password spraying attacks.
// A single IP attempting to log in as many different users with a high failure rate.
// Tune the 'userThreshold' based on your environment's baseline.
let userThreshold = 15;
let passwordSpraying = SigninLogs
 | where TimeGenerated > ago(lookback)
 | where ResultType == 50126 // Error code for "Invalid username or password"
 | summarize
     StartTime = min(TimeGenerated),
     EndTime = max(TimeGenerated),
     FailedUserCount = dcount(UserPrincipalName),
     FailedUsers = make_set(UserPrincipalName, 100)
 by IPAddress, UserAgent
 | where FailedUserCount > userThreshold
 // Optional: Check for any successful logins from the same IP to see if the spray was partially successful.
 | join kind=leftouter (
     SigninLogs
     | where TimeGenerated > ago(lookback)
     | where ResultType == 0
     | summarize SuccessfulLogins = dcount(UserPrincipalName) by IPAddress
 ) on IPAddress
 | project
     TimeGenerated = StartTime,
     DetectionType = "Password Spraying Attack",
     IPAddress,
     UserAgent,
     FailedUserCount,
     SuccessfulLogins = todouble(SuccessfulLogins),
     Description = strcat("Potential password spray from IP '", IPAddress, "' targeting ", tostring(FailedUserCount), " users.");

// Union all detection parts into a single result set.
union privilegedRoleAssignments, credentialAddition, passwordSpraying
| project-rename
    Principal = Actor,
    Entity = TargetUser
| project
    TimeGenerated,
    DetectionType,
    Principal,
    Entity,
    IPAddress,
    Description
```

---

## 8. Mitigation Measures

Based on the observed TTPs, the following mitigation strategies are recommended:

*   **Against T1110.003 (Password Spraying) & T1110 (Brute Force):**
    *   **Enforce MFA:** Prioritize the enforcement of multi-factor authentication for all users, especially for administrative accounts.
    *   **Implement Strong Password Policies:** Use Microsoft Entra Password Protection to block weak and compromised passwords.
    *   **Block Legacy Authentication:** Create Conditional Access policies to block legacy protocols (IMAP, POP3, SMTP) that bypass MFA.

*   **Against T1068 (Exploitation for Privilege Escalation):**
    *   **Patch Management:** Maintain a robust patch management program to ensure all systems and applications are updated against known vulnerabilities.
    *   **Principle of Least Privilege:** Assign permissions based on the principle of least privilege. Regularly review and audit administrative roles.

*   **Against T1134 (Access Token Manipulation):**
    *   **User and Entity Behavior Analytics (UEBA):** Enable and monitor UEBA solutions to detect anomalous token usage and session activities.
    *   **Conditional Access Policies:** Implement risk-based Conditional Access policies that challenge or block logins based on location, device compliance, and sign-in risk.

*   **General Recommendations:**
    *   **Block Malicious IPs:** Add the identified IoCs to your firewall or Conditional Access blocklists.
    *   **Security Awareness Training:** Educate users on recognizing and reporting phishing attempts, which are often precursors to credential compromise.
