# APT41 - Winnti or Barium

## 1. General Identification

* **Campaign Name:** APT41 dust, C0017
* **APT Group:** APT41 (also known as: Amoeba, BARIUM, BRONZE ATLAS, BRONZE EXPORT, Blackfly, Brass Typhoon, Double Dragon, Earth Baku, G0044, G0096, Grayfly, HOODOO, LEAD, Leopard Typhoon, Red Kelpie, TA415, TG-2633, WICKED PANDA, WICKED SPIDER, Winnti)
* **Activity Date:** First campaign in May 2021 and latest in June 2024.
* **Motivation:** State-sponsored espionage group that also conducts financially-motivated operations (cybercrime).
* **Victimology:** Telecommunications providers in the United States, Australia, China (Tibet), Chile, India, Indonesia, Malaysia, Pakistan, Singapore, South Korea, Taiwan, and Thailand. They have targeted various industries including healthcare, telecom, technology, finance, education, retail, and video game industries across 14 countries.

## 2. Objectives and Context

* **Sectors Attacked:** As mentioned in the victimology, APT41 has targeted telecommunications providers and other industries such as healthcare, technology, finance, education, retail, and video games.
* **Impacts and Public Statements:** Explicit information regarding specific economic, political, or technological impacts, as well as public statements from companies or governments, is not detailed in the provided sources.

## 3. Attack Vectors

* **Initial Access:**
    * **Compromised Accounts:** APT41 has used stolen valid accounts for initial access and other operations (`T1078`).
    * **Vulnerability Exploitation:** The use of the obfuscated BADPOTATO exploit has been observed for local privilege escalation.
* **Other Vectors:** Specific information on spear-phishing with malicious PDF/Word attachments or the use of specific CVEs as an initial access vector is not detailed in the provided sources.

## 4. Malware and Tools Used

APT41 uses a broad arsenal of tools and malware, including:

| Software/Tool | Description |
| :------------ | :---------- |
| Acunetix | Used for SQL injection vulnerability scanning. |
| ADORE.XSEC | Backdoor exploited via a hidden script. |
| Adore-NG | Rootkit used. |
| ANTSWORD | Web shell for persistence. |
| BADPOTATO | ConfuserEx obfuscated exploit for local privilege escalation. |
| BLUEBEAM | Web shell for persistence. |
| BrowserGhost | Tool to retrieve browser credentials. |
| CLASSFON | Tool for network communication proxying. |
| Cobalt Strike | Used for malware deployment and persistence (BEACON loader). |
| ConfuserEx | Obfuscator used with the BADPOTATO exploit. |
| CRACKSHOT | Known APT41 malware. |
| DUSTPAN | Dropper and loader for decrypting embedded payloads, sometimes disguised as a legitimate binary. |
| DUSTTRAP | Malware and components signed with stolen certificates, executed via DLL search order hijacking. |
| Encryptor RaaS | Ransomware used to encrypt files. |
| HIGHNOON | Variety of malware to enumerate active RDP sessions. |
| JexBoss | Tool to identify vulnerabilities in Java applications. |
| KEYPLUG | Windows backdoor with frequently updated dead drop resolvers. |
| LOWKEY.PASSIVE | Passive backdoor configured to disguise web traffic. |
| Mimikatz | Used to dump password hashes from memory. |
| MiPing | Used to discover active systems on the victim's network. |
| NATBypass | Used to bypass firewall restrictions and access compromised systems via RDP. |
| PINEGROVE | Used to collect information from local systems and databases. |
| POISONPLUG | Known APT41 malware. |
| PowerSploit | Used for persistence via WMI. |
| Procdump | Used to dump password hashes from memory. |
| Speculoos Backdoor | Backdoor used by APT41. |
| SQLULDR2 | Used to collect data from Oracle databases. |
| TIDYELF | Malware that loads the main WINTERLOVE component by injecting it into `iexplore.exe`. |
| WIDETONE | Variety of malware to perform port scans on specific subnets. |
| Windows Credential Editor | Used to dump password hashes from memory. |
| WINTERLOVE | Main component loaded by TIDYELF. |
| Winnti | Used for Windows, loaded via DLL search order hijacking. |
| YSoSerial.NET | Deserialization exploitation tool. |

* **Common Techniques:**
    * **DLL Sideloading:** Observed with malware like `Winnti`, which is loaded via DLL search order hijacking.
    * **Living off the Land Binaries (LOLBins):** While "LOLBins" is not explicitly mentioned, the group uses built-in system tools such as `net` commands and `makecab.exe` for various operations.
* **Specific Backdoors:** Tools like Voldemort, Spark, or HealthKick are not specifically mentioned in the provided sources.

## 5. TTPs (MITRE ATT&CK Mapped)

APT41 employs a variety of TTPs to carry out its operations, mapped to MITRE ATT&CK (version v4.1 - attack v17):

* **Initial Access**
    * `T1078: Valid Accounts` - The use of compromised valid accounts for initial access.
* **Execution**
    * `T1047: Windows Management Instrumentation` - Use of WMI for command execution (WMIEXEC) and persistence (PowerSploit).
    * `T1059.003: Windows Command Shell` - Use of `cmd.exe` for command execution.
* **Persistence**
    * `T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder` - Use of the registry `Run` key for automatic execution.
* **Privilege Escalation**
    * `T1134: Token Manipulation` - Use of the obfuscated BADPOTATO exploit for local privilege escalation to `NT AUTHORITY\SYSTEM`.
* **Defense Evasion**
    * `T1027.002: Obfuscated Files or Information: Software Packing` - Employment of string obfuscation.
    * `T1218.011: Signed Binary Proxy Execution: Rundll32` - Technique observed with malware like `Winnti` via DLL sideloading.
* **Credential Access**
    * `T1003: OS Credential Dumping` - Use of tools like Mimikatz, `pwdump`, and Windows Credential Editor to dump password hashes.
* **Discovery**
    * `T1087.001: Account Discovery: Domain Account` - Enumeration of domain administrator users.
    * `T1087.002: Account Discovery: Local Account` - Enumeration of local administrator groups.
* **Collection**
    * `T1005: Data from Local System` - Use of tools like PINEGROVE to collect information from local systems and databases.
    * `T1560.001: Archive Collected Data: Archive via Utility` - Use of `makecab.exe` to compress data.
* **Lateral Movement**
    * `T1021.001: Remote Services: Remote Desktop Protocol` - Use of RDP for access to compromised systems.
* **Command and Control**
    * `T1071.001: Application Layer Protocol: Web Protocols` - Use of legitimate websites (GitHub, Pastebin, Microsoft TechNet) as "dead drop resolvers" for C2.
    * `T1090: Proxy` - Use of the MiPing proxy tool for network communications.

Techniques T1566.001 (Phishing: Spearphishing Attachment) and T1041 (Exfiltration Over C2 Channel) are not explicitly detailed in the provided JSON or PDF with a direct MITRE ATT&CK ID associated with APT41's observed behavior.

## 6. C2 Infrastructure

* **Connection Methods:** APT41 has utilized legitimate websites such as GitHub, Pastebin, and Microsoft TechNet as "dead drop resolvers" (DDR) for their Command and Control (C2) communications, frequently updating posts. Communications implicitly involve web application layer protocols like HTTP.
* **TLS Certificates:** The group has used revoked certificates in some of its operations. YARA rules include signatures for these certificates.
* **Public IPs, Open Ports, Specific Domains, GeoIP/Reputation:** Detailed information regarding specific public IPs, open ports, exclusive malicious C2 domains, as well as GeoIP data or IP reputation, is not found in the provided sources.

## 7. Indicators of Compromise (IoCs)

### Hashes

* **POISONPLUG:** `70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e`, `0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb`, `2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd`, `5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90`, `f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661`, `3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f`
* **POISONPLUG SHADOW:** `462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8`
* **CRACKSHOT:** `993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31`
* **HIGHNOON:** `63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7`, `4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213`
* **HIGHNOON.BIN:** `490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994`, `79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d`, `c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d`
* **Speculoos Backdoor:** `6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167`, `99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28`
* **`7.dll.exe`:** `151257e9dfda476cdafd9983266ad3255104d72a66f9265caa8417a5fe1df5d7`

### Domains and URLs

* Legitimate websites used for C2 (dead drop resolvers - DDR): GitHub, Pastebin, Microsoft TechNet.

### Suspicious File Names

* `ma_lockdown_service.dll`
* `acbde.dll`
* `TSMSISrv.DLL`
* `tcpview.exe`
* `procmon64.exe`
* `netmon.exe`
* `MiniSniffer.exe`
* `smsniff.exe`
* `workdll64.dll`
* `PlusDll.dll`
* `ShutDownEvent.dll`
* `badshell`
* `hw.physmem`
* `7.dll.exe`

### Common Paths

* `\Fonts\Error.log`
* `\svchost.exe`
* `\Device\PORTLESS_DeviceName`
* `%s%s\Security`
* `%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`
* `%s%s\Enum`
* `H:\RBDoor\` (PDB path)
* `\RbDoorX64.pdb` (PDB path)
* `%s\NtKlRes.dat`
* `/usr/sbin/config.bak`
* `nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS` (reversed version of `Software\Microsoft\Windows\CurrentVersion\Run`)

### Suspicious Strings and Signatures

The YARA rules provided in `apt41.yar` contain a variety of suspicious strings and other signatures that can be used for the detection of APT41 activity.

## 8. Detection

* **YARA Rules:** Custom YARA rules for specific APT41 executables and payloads are available in the `apt41.yar` file in this repository. These rules enable signature-based detection of the group's artifacts.
* **Observable Behavior:** The TTPs mapped to MITRE ATT&CK provide guidance for observable behavior, including processes, registry key modifications (such as `Run` keys), unusual network traffic (connections to legitimate sites used as C2), and the use of system tools for malicious purposes.
* **Sigma, Snort/Suricata Rules:** Information for generating specific Sigma or Snort/Suricata rules is not explicitly provided in the source materials.

## 9. Mitigation and Defense

Detailed information on specific mitigation and defense strategies (such as phishing blocking, endpoint hardening, incident response procedures, or IoC blocklists) is not explicitly found in the provided sources. However, the YARA rules and IoCs can be used to feed security systems for detection and containment.

## 10. References

* [FireEye: APT41 Dual Espionage and Cyber Crime Operation](https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html)
* [Palo Alto Networks Unit 42: APT41 Using New Speculoos Backdoor to Target Organizations Globally](https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/)
* [MITRE ATT&CK: Group G0096 (APT41)](https://attack.mitre.org/groups/G0096/)
* [Mandiant: APT41 - Dual Operation](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)
* fbi.gov
* resecurity.com
* malpedia
* virustotal
* threat.zone
* abuse.ch