# Wireshark PCAP Analysis Lab - NetSupport RAT C2 Detection

**Tools:** Wireshark  
**Sample:** 2026-02-28-traffic-analysis-exercise.pcap (Malware Traffic Analysis)  
**Source:** https://www.malware-traffic-analysis.net/2026/02/28/index.html  
**Threat:** NetSupport Manager RAT C2 beacon traffic  
**MITRE ATT&CK:** T1219, T1071.001, T1568

---

## Scenario

Working a SIEM alert at a SOC. Several signature hits for NetSupport Manager RAT from `45.131.214[.]85` over TCP port 443, starting 2026-02-28 at 19:55 UTC. A PCAP of the internal host that triggered the alerts has been retrieved. The task is to identify the infected machine and document the C2 activity for an incident report.

**Environment:**
- LAN segment: `10.2.28.0/24`
- Domain: `easyas123.tech`
- AD environment: `EASYAS123`
- Domain controller: `10.2.28.2` (EASYAS123-DC)
- Gateway: `10.2.28.1`

---

## Methodology

### Step 1 - Protocol Hierarchy Overview

First step on any unknown PCAP is Statistics -> Protocol Hierarchy to understand what types of traffic are present before filtering anything.

Key observations from the hierarchy:
- **80.9% TCP** -- high TCP volume, expected for a Windows AD environment
- **TLS at 12%** -- encrypted traffic, expected for HTTPS/AD Kerberos
- **HTTP at 2.3%** -- unencrypted HTTP is worth looking at, especially alongside TLS
- **SMB2 at 5.1%** -- normal for AD domain environment
- **Kerberos at 0.1%** -- authentication traffic, useful for username extraction
- **LDAP at 3.3%** -- AD directory queries

The HTTP presence alongside TLS is the first flag. In a normal environment HTTP traffic should be minimal or absent on port 443.

### Step 2 - Identify the Infected Host

Statistics -> Conversations -> TCP tab, sorted by bytes descending.

**10.2.28.88** dominates the conversation list, appearing as the source in nearly every high-volume connection. This is the infected host.

Applied filter to confirm:
```
ip.addr == 45.131.214.85
```

All traffic to and from the C2 IP originates from `10.2.28.88`.

### Step 3 - Confirm C2 Traffic

Applied filter:
```
http.request.method == "POST"
```

This immediately surfaces the C2 beacon pattern -- repeated HTTP POST requests from `10.2.28.88` to `45.131.214[.]85` on TCP port 443:

```
POST http://45.131.214.85/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Host: 45.131.214.85
Connection: Keep-Alive
```

Three things confirm this as NetSupport RAT C2:

**1. User-Agent string** -- `NetSupport Manager/1.3` is the hardcoded User-Agent NetSupport RAT uses for C2 communication. This is a well-documented indicator.

**2. The URL** -- `/fakeurl.htm` is a hardcoded callback URI used by NetSupport RAT. It is not a real file -- it is a C2 endpoint that processes beacon data server-side.

**3. Plaintext HTTP over port 443** -- Wireshark flagged this with an Expert Info warning: "Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration." The RAT uses port 443 to blend with HTTPS traffic at the firewall level, but the actual C2 communication is unencrypted HTTP. The raw packet data shows `CMD=POLL` and `ACK=1` in plaintext -- the RAT keepalive command visible in the wire data.

**Beacon interval:** Approximately 60 seconds between POSTs -- consistent with NetSupport RAT's default polling interval.

### Step 4 - MAC Address

Filtered for the first ARP packet from the infected host:
```
arp
```

Packet 3 shows the ARP request from `10.2.28.88` with source MAC `00:19:d1:b2:4d:ad` (Intel NIC). The Ethernet header confirms this throughout the capture.

### Step 5 - Hostname

Applied filter:
```
smb
```

Used Find (Ctrl+F) searching for string `DESKTOP-` in packet list. Packet 225 shows a NetBIOS Browser Host Announcement from `10.2.28.88`:

```
Host Announcement DESKTOP-TEYQ2NR, Workstation, Server, NT Workstation
Host Name: DESKTOP-TEYQ2NR
OS Major Version: 10
OS Minor Version: 0
```

Hostname also confirmed in the Kerberos AS-REQ packet addresses field: `DESKTOP-TEYQ2NR<20>`.

### Step 6 - Username

Applied filter:
```
kerberos
```

The AS-REQ (Authentication Service Request) packets from `10.2.28.88` to the DC at `10.2.28.2` show the authenticating principal:

```
cname:
  name-type: kRB5-NT-PRINCIPAL (1)
  CNameString: brolf
realm: EASYAS123
```

Username: **brolf**

### Step 7 - Full Name

The username `brolf` is a short account name. To get the full name, looked at SAMR (Security Account Manager Remote Protocol) traffic -- this is the protocol Windows uses to query user account details from the DC.

Used Find (Ctrl+F) searching string `Rolf` in packet details. Located a SAMR response containing UserInfo21 data:

```
Full Name: Becka Rolf
```

This is the display name associated with the `brolf` account.

---

## Incident Report

| Field | Value |
|---|---|
| IP address | 10.2.28.88 |
| MAC address | 00:19:d1:b2:4d:ad |
| Hostname | DESKTOP-TEYQ2NR |
| Username | brolf |
| Full name | Becka Rolf |
| C2 IP | 45.131.214[.]85 |
| C2 port | 443 (TCP) |
| C2 protocol | HTTP (unencrypted, masquerading as HTTPS) |
| C2 URI | /fakeurl.htm |
| Malware | NetSupport Manager RAT v1.3 |
| Beacon interval | ~60 seconds |
| First seen | 2026-02-28 12:55 (PCAP time) |

---

## C2 Traffic Analysis

NetSupport Manager is a legitimate remote access tool that is frequently abused as a RAT. The C2 communication pattern in this capture is characteristic of the malicious variant:

**Why port 443?** Firewalls and security tools commonly allow outbound port 443 (HTTPS) without deep inspection. By using port 443 for HTTP traffic, the RAT bypasses basic port-based blocking.

**Why is it detectable?** TLS inspection or any tool that can see packet contents will immediately identify the traffic as unencrypted HTTP -- the HTTP headers, URI, and C2 commands are all in plaintext. The User-Agent `NetSupport Manager/1.3` and URI `/fakeurl.htm` are well-documented signatures that any SIEM with up-to-date rules will catch, which is consistent with how this alert was triggered.

**CMD=POLL** -- visible in the raw packet bytes, this is the keepalive beacon the RAT sends to check for operator commands. The operator connects to the same C2 server and issues commands which the beacon retrieves on each poll cycle.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Remote Access Software | T1219 | NetSupport Manager RAT used for C2 |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP used for C2 communication |
| Dynamic Resolution | T1568 | RAT polling C2 endpoint for operator commands |

---

## Key Takeaways

**Protocol hierarchy is the starting point.** Before filtering anything, the hierarchy view gives a map of what is present. HTTP alongside TLS on an AD domain network is immediately suspicious and narrows the search before a single filter is applied.

**C2 beacons have patterns.** The 60-second interval between POSTs is a dead giveaway once you know to look for it. Manual review of timestamps would catch this; automated SIEM rules catch it at scale.

**Plaintext C2 on port 443 is a common evasion technique.** Perimeter rules that only check port numbers will miss this entirely. Detection requires either TLS inspection or a SIEM signature that matches on User-Agent strings or known URIs.

**Username extraction from Kerberos is a standard technique.** Any time a Windows host authenticates to a domain controller, the Kerberos AS-REQ contains the principal name in plaintext. For investigators, Kerberos traffic is one of the most reliable sources of user identity in a domain capture.

**SAMR gives you the full name, not just the account name.** Account names like `brolf` are short aliases. The full display name lives in the SAMR response from the DC -- useful for identifying the actual person behind the account in an incident report.

---

## Repo Structure

```
wireshark-netsupport-rat-analysis/
├── README.md
└── screenshots/
    ├── 01-protocol-hierarchy.png
    ├── 02-conversations-tcp.png
    ├── 03-c2-post-beacon.png
    ├── 04-c2-http-filtering.png
    ├── 05-kerberos-username.png
    ├── 06-kerberos-as-req.png
    ├── 07-smb-hostname.png
    ├── 08-arp-mac-address.png
    └── 09-samr-full-name.png
```

---

## References

- [Malware Traffic Analysis -- 2026-02-28 Exercise](https://www.malware-traffic-analysis.net/2026/02/28/index.html)
- [MITRE ATT&CK T1219 -- Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1071.001 -- Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [NetSupport RAT -- Any.run Threat Intelligence](https://any.run/malware-trends/netsupport)
