# Mirai Variant (2024-2025) Threat Intelligence Report

## Executive Summary

Mirai is a notorious botnet malware family known for compromising IoT devices with weak or default credentials. First appearing in the mid-2010s, it was responsible for some of the most disruptive DDoS attacks in history. While the original creators were apprehended, Mirai's open-source code has led to hundreds of active variants. This report focuses on a modern Mirai-based variant identified in early 2024, nicknamed **Mirai.Nomi**, which exhibits new features such as DGA (Domain Generation Algorithm), expanded brute-force mechanisms, and adaptive payload delivery strategies.

## Malware Classification

* **Name**: Mirai.Nomi (variant tentative)
* **Type**: IoT Botnet Malware
* **Architecture**: ELF binaries targeting Linux-based systems (MIPS, ARM, SPARC)
* **Purpose**: DDoS attacks, proxy routing, device reconnaissance
* **Discovered**: March 2024
* **Attribution**: Unknown (original Mirai author: Anna-Senpai)

## Infection Vector and Propagation

* **Initial Access**: Internet-wide scanning for IoT devices with exposed Telnet/SSH services
* **Attack Methods**:

  * Brute-force login attempts using hardcoded/default credentials
  * Exploitation of known vulnerabilities (e.g., CVE-2023-44487, CVE-2019-9511/9513/9516)
  * Dropper binary hosted at `http://154.91.254.95/rondo.i586`
* **Target Devices**: Routers, IP cameras, DVRs, and other IoT systems
* **Self-Replication**: Uses infected devices to scan and infect others

## Malware Behavior

Upon execution, the malware performs the following:

* Collects system information (kernel version, CPU, memory)
* Establishes persistence (modifies `/etc/rc.local`, runs from `/var/run/gcc.pid`)
* Communicates with C2 infrastructure using TCP threads
* Kills competing malware processes and security tools
* Downloads secondary payloads or rootkits from C2

## Command and Control Infrastructure

* **Active IPs**:

  * `190.217.148.227:4886` (critical, Chile)
  * `179.51.168.26:10428` (critical, Chile)
  * `164.77.147.186:12652` (critical, privacy)
  * `186.67.227.98:65300` (critical, Chile)
  * `200.72.199.205:1542` (critical, Chile)
  * `216.155.93.238:33194` (critical, Chile)

* **C2 Communication**:

  * Uses TCP, HTTP, Telnet
  * May involve DGA or dynamic IPs

## Technical Indicators (Partial)

### New IOC Indicators:

| **Indicator**                                                  | **Type** | **Risk** | **Added**           | **Updated**         | **Seen**            | **Retired** | **Reference**                                                        | **Geo Location**       |
| -------------------------------------------------------------- | -------- | -------- | ------------------- | ------------------- | ------------------- | ----------- | -------------------------------------------------------------------- | ---------------------- |
| [http://190.217.148.227:4886/i](http://190.217.148.227:4886/i) | URL      | Critical | 2024-04-12 10:50:49 | 2025-08-07 22:31:22 | 2025-08-07 22:31:22 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58248076) | Osorno, Chile          |
| [http://179.51.168.26:10428/i](http://179.51.168.26:10428/i)   | URL      | Critical | 2024-04-12 10:50:53 | 2025-08-07 22:31:40 | 2025-08-07 22:31:40 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58248122) | Paine, Chile           |
| [http://164.77.147.186:12652/i](http://164.77.147.186:12652/i) | URL      | Critical | 2024-04-16 18:04:08 | 2025-08-07 00:41:23 | 2025-08-07 00:41:23 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58412218) | \[Privacy], \[Privacy] |
| [http://186.67.227.98:65300/i](http://186.67.227.98:65300/i)   | URL      | Critical | 2024-04-16 18:04:09 | 2025-08-02 00:12:07 | 2025-08-02 00:12:07 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58412221) | Santiago, Chile        |
| [http://200.72.199.205:1542/i](http://200.72.199.205:1542/i)   | URL      | Critical | 2024-04-16 18:04:09 | 2025-08-07 00:41:21 | 2025-08-07 00:41:21 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58412224) | Santiago, Chile        |
| [http://216.155.93.238:33194/i](http://216.155.93.238:33194/i) | URL      | Critical | 2024-04-16 18:04:09 | 2025-08-07 00:41:21 | 2025-08-07 00:41:21 | N/A         | [PulseDive Indicator](https://pulsedive.com/indicator/?iid=58412225) | Quell�n, Chile         |

---

### Sample Hashes (Updated):

* `57573779f9a62eecb80737d41d42165af8bb9884579c50736766abb63d2835ba`
* `72a4fa3544e43a836ffcb268ce06ccdbc55d44d5e6b1b1c19216a53ea98301fd`
* `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`

## Tactics, Techniques, and Procedures (TTPs)

| Tactic            | Technique                         | ID        | Description                                      |
| ----------------- | --------------------------------- | --------- | ------------------------------------------------ |
| Initial Access    | Brute Force: Default Credentials  | T1110.001 | Telnet/SSH brute-force attacks                   |
| Execution         | Command and Scripting Interpreter | T1059     | Execution of shell commands to deploy malware    |
| Persistence       | Modify System Configuration       | T1543.004 | Editing rc.local and background process creation |
| Defense Evasion   | Rootkit                           | T1014     | Installation of kernel-level rootkits            |
| Command & Control | Application Layer Protocol        | T1071.001 | TCP/HTTP-based C2 communication                  |
| Lateral Movement  | Exploit Public-Facing Application | T1190     | Scans and exploits vulnerable IoT services       |
| Impact            | Service Stop                      | T1489     | Kills competing malware and AV processes         |

## Vulnerabilities Exploited

* CVE-2023-44487
* CVE-2021-23017
* CVE-2021-3618
* CVE-2019-20372
* CVE-2019-9516
* CVE-2019-9513
* CVE-2019-9511
* CVE-2018-16845 / 16844 / 16843

## Detection and Mitigation

### YARA Rules

Generic and architecture-specific YARA rules for detection included in `mirai.yar`

### Mitigation Recommendations

* Block Telnet (ports 23, 2323) and SSH (port 22) on IoT devices
* Replace default credentials with strong, unique passwords
* Disable UPnP, mDNS, and unused web interfaces
* Segment IoT networks using VLANs or firewalls
* Apply firmware updates for all vulnerable devices

## References

* Cloudflare
* Fortinet
* Shodan
* MITRE
* Malpedia
* Abuse.ch
* PulseDive

---

**Author**: Jorge Felix Gonzalez Arias
**Date**: July 14, 2025
**License**: MIT

