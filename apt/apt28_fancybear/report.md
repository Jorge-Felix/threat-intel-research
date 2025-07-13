# APT28 (Fancy Bear) Threat Intelligence Report

## Executive Summary

APT28, also known as Fancy Bear, STRONTIUM, and Sofacy, is a Russian state-sponsored cyber espionage group with a long-standing history of advanced operations targeting strategic sectors worldwide. With operations attributed to Russia’s GRU (military unit 26165), APT28 has orchestrated extensive campaigns against government, defense, energy, media, and critical infrastructure entities since at least 2004.

This report delves into the group's tactics, tools, and procedures with a particular focus on their recent "Nearest Neighbor Campaign" (2022–2024). This campaign has demonstrated APT28’s evolving capabilities through the deployment of phishing, credential harvesting, and sophisticated malware targeting European and NATO-aligned nations. The report aims to support defenders with actionable intelligence, detection guidance, and contextual analysis to enhance threat awareness and mitigation strategies.

## Attribution and Background

* **Group**: APT28 (Fancy Bear, STRONTIUM, Sednit)
* **Attribution**: Russian GRU (85th Main Special Service Center, Unit 26165)
* **First Observed**: 2004
* **Aliases**: Sofacy, Pawn Storm, Sednit, Tsar Team
* **Motivation**: Espionage, geopolitical influence, information warfare
* **Target Sectors**: Government, defense, energy, aerospace, media
* **Primary Tools**: X-Agent, XTunnel, CHOPSTICK, Zebrocy, SOURFACE, SkinnyBoy

APT28 has demonstrated a high level of operational discipline and has frequently aligned its campaigns with Russian state interests, particularly during periods of international tension. Known for its technical sophistication, the group is capable of conducting long-term intrusions and stealing sensitive political, military, and diplomatic data.

## Campaign Overview

* **Name**: Nearest Neighbor Campaign
* **Active Period**: February 2022 – November 2024
* **Primary Target Sectors**: Government, media, energy, defense
* **Regions Affected**: France, Germany, Sweden, Norway, Ukraine, USA
* **Initial Access Methods**: Spear-phishing, zero-day exploits, Wi-Fi compromise, credential stuffing

This campaign was notable for the use of highly tailored phishing emails impersonating trusted institutions and urgent government communications. The phishing vectors delivered malware loaders that dropped advanced payloads designed to evade detection. In addition, attackers leveraged known vulnerabilities in public-facing infrastructure and targeted undersecured Wi-Fi networks used by field operatives and diplomatic personnel.

## Malware Used

APT28’s malware arsenal is diverse and flexible, with tools designed to adapt to multiple operational phases and objectives. Prominent malware families include:

* **X-Agent**: A powerful Remote Access Trojan (RAT) capable of file exfiltration, keystroke logging, command execution, and screen capture.
* **XTunnel**: A network tunneling tool that encapsulates network traffic to facilitate encrypted outbound communications to command and control (C2) servers.
* **Zebrocy**: A malware family comprising downloaders and loaders often used in initial phishing campaigns; written in multiple languages (Delphi, .NET, Go).
* **CHOPSTICK**: A modular RAT used for establishing persistent access, gathering credentials, and enabling remote control.
* **SOURFACE**: Reconnaissance-focused malware used to collect system, user, and domain information prior to lateral movement.
* **SkinnyBoy**: A second-stage malware identified in 2021–2022, believed to be used for privilege escalation and facilitating more advanced operations post-compromise.

## Initial Access Vectors

APT28 relies on a combination of social engineering and software exploitation techniques to breach target networks. These access vectors are frequently customized based on the target’s profile and network posture.

* Spear-phishing emails with weaponized Microsoft Word documents or password-protected archive files containing malware.
* Exploitation of publicly exposed applications, notably Microsoft Exchange vulnerabilities like CVE-2020-0688.
* Web-based exploitation involving cross-site scripting (XSS) and SQL injection flaws in unpatched CMS or portals.
* Breach of poorly secured Wi-Fi networks in public locations or using portable rogue access points.
* Credential stuffing attacks against VPNs, webmail, or SSO portals using leaked credentials from previous breaches.

## Tactics, Techniques, and Procedures (TTPs)

APT28 exhibits full-spectrum intrusion capabilities and leverages techniques across the entire MITRE ATT\&CK matrix. A selection of key TTPs includes:

| Tactic               | Technique                             | ID        | Description                                  |
| -------------------- | ------------------------------------- | --------- | -------------------------------------------- |
| Initial Access       | Spearphishing Attachment              | T1566.001 | Malicious documents delivered via email      |
| Initial Access       | Exploit Public-Facing Application     | T1190     | Microsoft Exchange vulnerabilities exploited |
| Execution            | PowerShell                            | T1059.001 | Scripts executed for credential collection   |
| Persistence          | Registry Run Keys                     | T1547.001 | Run keys used to maintain persistence        |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068     | Multiple CVEs exploited                      |
| Defense Evasion      | Obfuscated Files or Information       | T1027     | Base64, XOR, RC4 used for payload encoding   |
| Credential Access    | Credential Dumping                    | T1003     | LSASS memory dumps, NTDS.dit, Mimikatz       |
| Discovery            | Account Discovery                     | T1087     | Active Directory enumeration                 |
| Lateral Movement     | Remote Desktop Protocol               | T1021.001 | RDP for internal pivoting                    |
| Command & Control    | Web Protocols                         | T1071.001 | HTTP/S for C2 communications                 |
| Exfiltration         | Exfiltration Over Web Service         | T1567     | Google Drive, HTTPS-based transfers          |

A full TTP mapping is available in the `ttp_mapping.json` file.

## Indicators of Compromise (IoCs)

APT28’s operational infrastructure evolves rapidly, but certain indicators have been consistently observed across recent campaigns. Below is a representative sample of known IOCs:

**Domains:**

* `malaytravelgroup[.]com`
* `beststreammusic[.]com`
* `picturecrawling[.]com`
* `truefashionnews[.]com`

**IP Addresses:**

* `139.5.177.205`
* `185.181.102.204`
* `185.86.150.205`
* `185.86.151.2`
* `23.163.0.59`

**Hashes (SHA-1):**

* `46e2957e699fae6de1a212dd98ba4e2bb969497d` (chost.exe)
* `c53930772beb2779d932655d6c3de5548810af3d` (msoutlook.dll)
* `913ac13ff245baeff843a99dc2cbc1ff5f8c025c` (codexgigas file - Zebrocy)

Complete IOC datasets are available in the `iocs.csv` file for threat hunting and alerting.

## Detection Rules

Detection engineering is critical to identifying APT28 malware artifacts and associated activity. The following rule sets have been crafted to aid defenders:

* **YARA Rules**: Signature-based detection for CHOPSTICK, SOURFACE, and SkinnyBoy binaries.
* **Snort Rules**: Network-based intrusion detection patterns for C2 communications via HTTP POST and known User-Agent strings.

These are included in `yara_rules.yar` and `snort_rules.rules`, and should be tailored to organizational environments.

## Detection Rule Samples

### YARA Rule: CHOPSTICK

```yara
rule CHOPSTICK_Artifact {
    meta:
        description = "Detects CHOPSTICK malware variant used by APT28"
        author = "Jorge Felix Gonzalez Arias"
        reference = "APT28 Report"
    strings:
        $a = "Microsoft\Windows\CurrentVersion\Run" wide
        $b = "Software\Microsoft\Windows\CurrentVersion\Policies" wide
        $x = { E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D0 }
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
```

### Snort Rule: XTunnel C2

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"APT28 XTunnel C2 Attempt";
    flow:established,to_server;
    content:"POST /data.cgi";
    http_method;
    content:"User-Agent|3A| Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)
```

## Infrastructure and Command & Control (C2)

APT28 maintains a resilient and layered C2 architecture. The group leverages:

* Compromised third-party servers and anonymized domains for staging.
* Use of commercial cloud services (e.g., Gmail, Google Drive) for encrypted data exfiltration.
* Protocol blending and port switching to bypass firewalls and evade deep packet inspection.
* Redundant proxying and Tor-based routing to mask traffic origins and destinations.

This infrastructure design enables high operational continuity and complicates threat attribution and response.

## Defensive Recommendations

To defend against APT28, organizations should implement comprehensive and layered security strategies:

* Block confirmed IoCs across perimeter and endpoint defenses.
* Enable logging and alerting for unusual scripting or PowerShell activity.
* Harden systems against known vulnerabilities with timely patching.
* Implement MFA for all remote and privileged access points.
* Train staff on recognizing phishing and social engineering attempts.
* Integrate YARA and Snort signatures into SOC tools for real-time monitoring.

Proactive threat hunting and incident response planning are essential to identifying and mitigating sophisticated adversaries like APT28.

## References

* MITRE ATT\&CK: [https://attack.mitre.org/groups/G0007](https://attack.mitre.org/groups/G0007)
* CrowdStrike: [https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
* US DOJ Indictment: [https://www.justice.gov/opa/page/file/1098481/download](https://www.justice.gov/opa/page/file/1098481/download)
* Cluster25: [https://cluster25.io/wp-content/uploads/2021/05/2021-05\_FancyBear.pdf](https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf)
* Microsoft Security Blog, FireEye Reports, Recorded Future Threat Intelligence
* Defense.gov (Drovorub, Brute Force Campaigns)

---

**Author**: Jorge Felix Gonzalez Arias
**Date**: July 13, 2025
**License**: MIT
