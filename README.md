# SOC Automation Pipeline

A production-grade Security Operations Center (SOC) automation lab built entirely on local infrastructure using VirtualBox VMs, with cloud integration via Microsoft Azure. This project demonstrates end-to-end threat detection, automated response, and multi-SIEM visibility across a simulated enterprise environment.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ATTACK SIMULATION                            │
│   Kali Linux (192.168.56.30)  ──────►  Windows 10 (192.168.56.20)  │
│           │ SSH Brute Force              Privilege Escalation       │
│           │ Nmap Reconnaissance          New User Creation          │
└───────────┼─────────────────────────────────────────┬───────────────┘
            │                                         │
            ▼                                         ▼
┌───────────────────────────┐             ┌───────────────────────────┐
│   Wazuh SIEM              │             │   Wazuh Agent             │
│   192.168.56.10           │◄────────────│   WIN10-TARGET            │
│   Manager + Indexer +     │             │   KALI-ATTACKER           │
│   Dashboard               │             └───────────────────────────┘
└─────────────┬─────────────┘
              │
     ┌────────┴────────┐
     │                 │
     ▼                 ▼
┌─────────┐    ┌───────────────┐
│  n8n    │    │   Azure Arc   │
│  SOAR   │    │   + AMA       │
│  :5678  │    │               │
└────┬────┘    └───────┬───────┘
     │                 │
     ▼                 ▼
┌─────────┐    ┌───────────────────────┐
│  Email  │    │  Microsoft Sentinel   │
│  Alerts │    │  Log Analytics        │
└─────────┘    │  KQL Detection Rules  │
               │  Incident Management  │
               └───────────────────────┘
```

---

## Tools & Technologies

| Category | Tool | Purpose |
|----------|------|---------|
| SIEM | Wazuh 4.12 | On-premises threat detection and log analysis |
| SOAR | n8n | Automated alert response and email notifications |
| Cloud SIEM | Microsoft Sentinel | Cloud-native security analytics and incident management |
| Log Storage | Azure Log Analytics | Centralized log ingestion and KQL querying |
| Cloud Agent | Azure Monitor Agent (AMA) | Forwards Wazuh syslog to Azure via Azure Arc |
| Attack Platform | Kali Linux | Simulated adversary — reconnaissance and brute force |
| Target | Windows 10 | Endpoint with Wazuh agent, subject to attack simulation |
| Hypervisor | VirtualBox 7.2 | Local VM hosting for entire on-prem stack |
| Log Forwarding | Splunk Enterprise | Live alert streaming and visualization dashboards *(self-implemented)* |

---

## Project Phases

### Phase 1 — Environment Setup
- Provisioned 4 VirtualBox VMs: Wazuh Server, Windows 10, Kali Linux, SOAR Server
- Configured dual-adapter networking: NAT (internet) + Host-Only (192.168.56.0/24)
- Assigned static IPs to all VMs for stable agent communication
- Configured Azure free tier account with Log Analytics Workspace and Microsoft Sentinel

### Phase 2 — Wazuh SIEM Deployment
- Deployed Wazuh all-in-one stack (Manager, Indexer, Dashboard) on Ubuntu 24.04
- Enrolled Windows 10 and Kali Linux endpoints as monitored agents
- Verified real-time telemetry flowing to Wazuh dashboard
- Extended LVM partition to resolve OpenSearch disk capacity issue

### Phase 3 — Custom Detection Rules
Wrote four custom XML detection rules targeting high-value security events:

| Rule ID | Trigger | Severity | MITRE Tactic |
|---------|---------|----------|--------------|
| 100001 | SSH brute force attack | Level 10 | Credential Access |
| 100002 | SSH brute force followed by success | Level 14 | Credential Access |
| 100003 | New user account created on endpoint | Level 12 | Persistence |
| 100005 | User added to Administrators group | Level 14 | Privilege Escalation |

All rules validated by triggering real attack scenarios and confirming alerts in the Wazuh dashboard.

### Phase 4 — SOAR Automation with n8n
- Deployed n8n workflow automation on a dedicated Ubuntu VM
- Configured Wazuh ossec.conf webhook integration to forward level 10+ alerts to n8n
- Built a workflow that receives Wazuh alert JSON, parses rule ID, agent name, and description
- Implemented automated email alerting — every triggered detection rule generates an email notification with full alert context
- Implemented Splunk live log forwarding for real-time visualization and dashboards *(self-implemented)*

**n8n Workflow Logic:**
```
Wazuh Alert Fired
       │
       ▼
Webhook Trigger (POST /webhook/...)
       │
       ▼
Code Node — Parse alert JSON
  - Extract rule.id, agent.name, description, severity
       │
       ▼
Email Node — Send alert notification
  - Subject: "WAZUH ALERT: {rule description}"
  - Body: Rule ID, Agent, Severity, Timestamp
```

### Phase 5 — Microsoft Sentinel Integration
- Registered Wazuh VM as Azure Arc machine for non-Azure VM management
- Installed Azure Monitor Agent (AMA) extension via Azure Arc
- Created Data Collection Rule (DCR) to stream syslog from Wazuh to Log Analytics Workspace
- Enabled Syslog via AMA data connector in Microsoft Sentinel
- Authored two KQL analytics rules for automated incident creation:

**SSH Brute Force KQL Rule:**
```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password" or SyslogMessage contains "Invalid user"
| summarize FailureCount = count(), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated) by HostName, Computer
| where FailureCount >= 5
| extend AlertDetail = strcat("SSH brute force detected: ", tostring(FailureCount), " failures on ", Computer)
```

**Privilege Escalation KQL Rule:**
```kql
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "sudo" or SyslogMessage contains "su:" or SyslogMessage contains "usermod"
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by HostName, Computer, SyslogMessage
| where Count >= 1
| extend AlertDetail = strcat("Possible privilege escalation detected on ", Computer)
```

### Phase 6 — Attack Simulation
Executed a coordinated multi-stage attack from Kali Linux to validate the full detection pipeline:

| Attack | Tool | Target | Detection |
|--------|------|--------|-----------|
| Network reconnaissance | Nmap -sS -sV | Windows 10 | Wazuh network rules |
| SSH brute force | Custom bash loop | Wazuh Server | Rule 100001 + Sentinel incident |
| User account creation | net user | Windows 10 | Rule 100003 + n8n alert |
| Privilege escalation | net localgroup | Windows 10 | Rule 100005 + n8n alert + Sentinel |

**Results:** All attack stages detected across all three monitoring layers simultaneously — Wazuh dashboard, n8n email alerts, and Microsoft Sentinel incidents.

---

## Detection Pipeline Results

Each simulated attack triggered the full response chain:

```
Attack Executed
     │
     ├──► Wazuh Custom Rule Fired (local SIEM)
     │         Rule 100001 / 100003 / 100005
     │
     ├──► n8n Webhook Triggered (SOAR)
     │         Alert parsed and email sent
     │         "WAZUH ALERT: Rule XXXXX fired on agent WIN10-TARGET"
     │
     └──► Microsoft Sentinel Incident Created (cloud SIEM)
               High severity, Credential Access / Privilege Escalation
               Incident queue populated for analyst triage
```

---

## Key Skills Demonstrated

- **SIEM Engineering** — Deployed and configured Wazuh on-premises SIEM with custom detection rules
- **Detection Rule Authoring** — Wrote XML (Wazuh) and KQL (Sentinel) detection logic targeting real attack patterns
- **SOAR Development** — Built automated response workflows in n8n with webhook integration and email alerting
- **Cloud Security** — Integrated on-prem infrastructure with Azure via Arc, AMA, and Microsoft Sentinel
- **Threat Simulation** — Executed multi-stage attacks (recon, brute force, privilege escalation) against live endpoints
- **Multi-SIEM Architecture** — Designed hybrid SOC with parallel on-prem (Wazuh) and cloud (Sentinel) SIEM layers
- **Log Forwarding** — Configured Splunk Enterprise as a live log destination for visualization and dashboards
- **Network Architecture** — Designed isolated lab network with static IP addressing and dual-adapter VM networking

---

## Environment Specifications

| VM | OS | IP | RAM | Role |
|----|----|----|-----|------|
| Wazuh-Server | Ubuntu 24.04 LTS | 192.168.56.10 | 6 GB | SIEM + Manager |
| Win10-Target | Windows 10 Pro | 192.168.56.20 | 4 GB | Monitored endpoint |
| Kali-Attacker | Kali Linux 2024 | 192.168.56.30 | 2 GB | Attack simulation |
| SOAR-Server | Ubuntu 24.04 LTS | 192.168.56.40 | 2 GB | n8n SOAR platform |

**Cloud:** Microsoft Azure (Free Tier) — Log Analytics Workspace + Microsoft Sentinel + Azure Arc

---

## Repository Structure

```
soc-automation-pipeline/
├── README.md
├── wazuh/
│   └── local_rules.xml          # Custom Wazuh detection rules
├── n8n/
│   └── workflow.json            # n8n SOAR workflow export
├── sentinel/
│   └── kql_rules.md             # KQL analytics rule queries
├── screenshots/
│   ├── wazuh-dashboard.png
│   ├── wazuh-custom-rules-firing.png
│   ├── n8n-executions.png
│   ├── n8n-alert-output.png
│   ├── sentinel-incidents.png
│   └── sentinel-kql-results.png
└── docs/
    └── architecture-diagram.png
```

---

## Author

**Raymand** — Junior CS Student, Michigan State University  
CompTIA Security+ | AWS Certified Cloud Practitioner | Google Cybersecurity Professional  
[GitHub](https://github.com/dengray1)

---

*This project was built entirely for educational and portfolio purposes. All attack simulations were conducted in an isolated local network environment.*
