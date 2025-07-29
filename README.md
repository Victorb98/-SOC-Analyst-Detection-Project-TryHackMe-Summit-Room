# 🔍 SOC Analyst Detection Lab – TryHackMe Summit 🧠
🛡️ A hands-on detection engineering lab simulating real SOC analyst tasks using TryHackMe's Summit room. Includes malware analysis, Sigma rule creation, and layered threat detection across the Pyramid of Pain.
user@desktop:~$ cat README.md


## 🔍 Project Overview

This repository documents my complete walkthrough of the **Summit** room on TryHackMe. This project simulates a real-world purple team engagement where, as a Blue Team / SOC Analyst, my objective was to analyze malware behavior and build resilient detections to stop an external penetration tester.

The entire exercise is structured around the **Pyramid of Pain**, progressively moving from simple, low-effort indicators to complex, high-effort behavioral detections (TTPs). The goal wasn't just to stop the attack but to make it prohibitively expensive for the adversary to re-tool and try again.

---

### 🧠 Skills Demonstrated:
-   🔎 **Malware Analysis:** Deconstructing malware behavior in a simulated environment.
-   🛡️ **Detection Engineering:** Writing custom detection rules based on observed activity.
-   🔥 **Firewall & DNS Management:** Blocking malicious network indicators (IPs, Domains).
-   📈 **Log Analysis:** Correlating events to identify attacker TTPs like C2 beaconing and persistence.
-   📝 **Sigma & YARA:** Applying knowledge of Sigma rule logic for threat detection.
-   🗺️ **MITRE ATT&CK Framework:** Mapping adversary behaviors to standardize threat reporting.
-   ⚙️ **Hands-on Tooling:** Using a simulated EDR/SIEM platform (PicoSecure) to deploy detections.

---

### 🔧 Tools & Concepts:
-   **Pyramid of Pain:** Guiding framework for prioritizing indicators.
-   **Sigma Rules:** Creating vendor-agnostic detection logic.
-   **Signature-based Detection:** Blocking known-bad hashes and network IOCs.
-   **Behavioral Detection (TTPs):** Identifying *how* an attacker operates, not just *what* they use.
-   **Cyber Kill Chain:** Understanding the stages of a cyber attack.

---

## 🎯 The Scenario: A Purple Team Engagement

Our mission, assigned by PicoSecure, was to collaborate with an external penetration tester. The tester would execute a series of malware samples on a workstation while our job was to build and refine our security tools to detect and prevent each attempt.

 <img width="1274" height="221" alt="Summit tryhackme Objective 1" src="https://github.com/user-attachments/assets/e0d0a8c9-b6ba-4105-9550-fadaaa53f882" /> 

 ## 🧗 Climbing the Pyramid of Pain: Walkthrough & Detections

I successfully detected and blocked all 6 malware samples, receiving a flag for each successful prevention. Here's a breakdown of the technique used for each sample.

### 1️⃣ Sample 1: The Easy Catch (Hash Values)
The first sample was a known malicious executable. This represents the lowest level of the Pyramid of Pain. While effective for this specific file, attackers can easily change a single bit to alter the hash and bypass the detection.

-   **Threat Type:** Malicious Executable (`sample1.exe`)
-   **Detection Method:** The file's unique SHA256 hash was added to a blocklist, preventing it from ever executing.
-   **Flag:** `THM{f3cbf08151a11a6a331db9c6cf5f4fe4}`

<img width="1314" height="587" alt="Summit tryhackme Hashing Malware 1" src="https://github.com/user-attachments/assets/51ff28f9-f86a-43d9-a00f-2f2397e3cc39" />
### 3️⃣ Sample 3: A Step Up (Domain Names)
Similar to blocking an IP, this sample used a domain name for C2 communication. Blocking domains is slightly more effective, as an attacker might cycle through multiple IPs behind a single domain.

-   **Threat Type:** DNS-based C2 Communication (`sample3.exe`)
-   **Detection Method:** The malicious domain was added to a DNS filter/blocklist, preventing the workstation from resolving it to an IP address.
-   **Flag:** `THM{4eca9e2f61a19ecd5df34c788e7dce16}`

### 4️⃣ Sample 4: Attacking the Defenses (Registry Modifications)
Here, the adversary moved from simple network indicators to **behavior (TTPs)**. The malware attempted to disable Windows Defender's real-time monitoring by modifying a specific registry key. This is a common defense evasion technique.

-   **Threat Type:** Defense Evasion (`sample4.exe`)
-   **Detection Method:** A Sysmon detection rule was created to alert on any process attempting to write a value of `1` to the `DisableRealtimeMonitoring` registry key. This is a high-fidelity indicator of malicious activity.
-   **ATT&CK ID:** [TA0005 - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
-   **Flag:** `THM{c956f455fc076aea829799c0876ee399}`

<img width="517" height="424" alt="Summit tryhackme Registry modifications Malware 1" src="https://github.com/user-attachments/assets/24b76fa4-1ff4-476a-8d03-29d7a51268ad" /> 

### 5️⃣ Sample 5: The "Heartbeat" (C2 Beaconing)
This sample established persistence and beaconed out to the C2 server at regular intervals. Instead of blocking a specific artifact, we detected the *pattern* of communication.

-   **Threat Type:** C2 Beaconing (`sample5.exe`)
-   **Detection Method:** A log-based Sigma rule was created to detect a process making repeated outbound network connections over a specific time interval. This is a powerful TTP-based detection.
-   **Flag:** `THM{46b21c4410e47dc5729ceadef0fc722e}`

### 6️⃣ Sample 6: Staging for Exfiltration (File & Process Creation)
The final sample, "Sphinx," performed a classic data staging operation. It used the command prompt (`cmd.exe`) to gather data and write it to a log file in the temporary directory before exfiltration.

-   **Threat Type:** Data Collection (`Sphinx`/`sample6.exe`)
-   **Detection Method:** A process creation rule was written to detect `cmd.exe` being used with a command line that references a specific log file (`%temp%\exfiltr8.log`) created for staging data.
-   **ATT&CK ID:** [TA0009 - Collection](https://attack.mitre.org/tactics/TA0009/)
-   **Flag:** `THM{c8951b2ad24bbc0ac60c16cf2c83d92c}`

<img width="522" height="350" alt="Summit tryhackme Process Creation Malware 1" src="https://github.com/user-attachments/assets/c55a6993-bece-4e4d-94ef-70a94d437a1c" />

🏆 Final Results & Key Takeaways

This room was a fantastic practical exercise in defensive thinking. The key takeaway is the value of moving up the Pyramid of Pain. While blocking hashes and IPs provides immediate value, they are trivial for an attacker to overcome. Building robust, behavior-based detections (TTPs) is the only way to create a truly resilient security posture.

<img width="1284" height="631" alt="Summit tryhackme final dashboard Malware 1" src="https://github.com/user-attachments/assets/9dc7a842-fcda-42f7-9550-e3b30023bbc0" />
