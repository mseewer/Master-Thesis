# Notes Master Thesis Meetings

## 04.03.24
TODOs:
- Select topic / focus -> read test concept
- read into related work (BGP, Attacker models) + make notes


## 12.03.24
DONE:
- Test concept
  - contains network setup
  - What about Anapaya Core / Gate devices? -> No (root) Access?
    - What are different devices types? Edge, Core, Gate

Focus (in order of preference):
- test Anapaya devices + its software/configuration (LinPEAS?)
- Computational DDos Attacks
- routing + path discovery mechanism (malicious AS -> can create valid-looking signature, but wrong path) -> access to 2 ISD (Estonia?)
- traffic sniffing -> privacy? fingerprinting?
- Malformed packets (-> fuzzing -> previous work?)
- Volumetric DDoS attacks (-> COLIBRI)
- (PKI -> quick check, uses ecdsa + SHA2)

TODOs:

- Edge device (Nessus + OpenSoucre)
  - test softwware + config
  - Computational DDoS Attacks (SCION + others)
- Vulnerability tools (OpenVAS (Greenbone) -> test version = enterprise trial version)
- nmap
- look at anapaya docs
- presentation duration 15 min

## 19.03.24
- https://www.greenbone.net/en/testnow/ -> enterprise trial version
  - By default, the Greenbone Enterprise TRIAL uses the Greenbone Community Feed instead of the more comprehensive Greenbone Enterprise Feed.
- Checked Anapaya Docs (https://scion.docs.anapaya.net/en/latest/)
  

- Jordi: Anapaya: 
  - scionproto for CS
  - own implementation for BR + SIG (but interoperable with scionproto)

Attack Ideas (also look at Hager chapter 7):
HW/Firmware:
  - check passwords complexity
  - Password of BIOS -> Secure boot?
  - physical access to devices + their interfaces (USB / network / ... ports)
- OS:
  - services/apps running (compare to SCION forensics work)
  - 2FA?
  - SSH certificates
  - File encryption
  - Logs
- Filesystem
  - Check permissions
- PKI:
  - where are keys stored? HSM? Redundancy?
  
Vulnerability Tools:
- (We don't need web app scanners)
- Nessus
- OpenVAS
- OpenSCAP (https://www.open-scap.org/download/)
- nmap -> vulners
- Vuls (https://github.com/future-architect/vuls)
- Archery (https://github.com/archerysec/archerysec)
  - combines multiple open source tools
    - OpenVAS, OWASP Zap (for web apps), Burp, NMAP Vulners
    - -> just use openVAs + nmap
- tsunami security scanner (pre-alpha)
- Lynis (Lynis was used in Forensics Framework related work)
- LinPEAS (Priv Esc)
- InsightVM (Rapid7) -> Nexpose -> See Mail for License Key
- Qualys

Questions:
- VPN -> no internet? -> solved!
- Nessus License? -> use essentials version (free up to 16 IPs)
- OpenVAS Enterprise Trial? -> Stick to Open Source Version?
- rsync (port 873 is maybe blocked -> needed to install OpenVAS)


TODO:
- send pk SSH -> DONE


## 26.03.24
DONE: 
  - Configured Nessus + OpenVAS
  - Made (un)authenticated scans -> some critical vulnerabilities found
    - A few exploits/POCs found -> see Findings-Notes.md
  - Manual investigation of SCION device
    - Open ports -> Mismatch official docs vs findings (do you have special config?)
  - LinPEAS (scan freezes)
    - Check again on offline device if priv esc is possible
    - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation
  - Wrote some line in background section

Questions:
  - DDoS defense (no Colibri in Anapaya) -> relies on hidden/multi path (not possible in our setup?)
  - Cyber Alp Retreat 2023

TODO:
  - LinPEAS on offline device (see above)
  - Docker Scout + Trivy (https://github.com/aquasecurity/trivy) on offline device (analysis of docker containers)
  - Inspect docker images offline
  - Look at appliance in more detail

## 02.04.24
DONE:
  - Anapaya appliance (poc.py) to interact with the API (GET, PUT, POST requests)
  - Exported docker image "scion-all" + "appliance"
  - Used docker scout + trivy to scan the image
    - scout -> nothing found
    - trivy -> critical & more vulnerabilities found

QUESTIONS:
  - SCION Topology (more ASes?)
  - Move meeting to 10am?

TODO:
  - run docker on kali machine
  - Look at SCION code (MAC / Signature algos + their verification)
  - Router verification of hop fields -> look at open source code (not anapaya implementation for now)
  - 

## Questions Anapaya:
- What are these signatures in the Appliance (https://docs.anapaya.net/en/release-v0.35/configuration/api/index.html#tag/signing/operation/post-signatures)
- Also what are the public signing keys?


## 09.04.24
DONE:
  - look at SCION code (MAC algo for HopField -> need master key -> if not in filesystem -> probably panic) -> more details: Findings-Notes.md
  - installed SCION on Kali machine
  - read in SCION book + code to get more overview -> attack ideas (see Attck-Ideas.md)
  - Started looking at packet layout / fields

TODO:
  - CIS guidelines -> passwordless sudo
  - check MAC on anapaya router
  - send SCION packets over EDGE device (approaches: SSH, docker, docker proxy)

## 16.04.24
DONE:
  - CIS guidelines -> passwordless sudo
    - See literature/CIS PDF
    - Chapter 5.4.6 / 5.4.7
  - Setup SCION on Kali:
    - Run Dispatcher + Daemon on kali -> configure (add certs, create topology, config)
    - scion ping etc. -> works
  - installed scapy for scion (https://github.com/lschulz/scapy-scion-int)
    - can record + send packets
    - currently: trying to craft own packets + select own path
      - need to know which are up/core/down segments

TODO:
  - Still: check MAC on anapaya router (once own packets can be crafted)
  - craft own packets + select own path

## 30.04.24
DONE:
  - found CIS for ubuntu 22.04 -> Chapter 5.2.5 (Ensure re-authentication for privilege escalation is not disabled globally)
    - MITRE ATT&CK -> https://attack.mitre.org/techniques/T1548/003/
  - Path selection:
    - Use scion showpaths to get paths
    - User selects/defines path
    - use scion ping to create proper SCION path (Ping AS, but can set wrong IP address)
    - use this SCION path in own SCION packets
  - Path graph visualization
  - Tried out different packet manipulations
    - set Segment length of all to 0 -> not working (even though path is valid)
    - create correct path out of valid paths -> not working (probably due to wrong MAC)
    - Flag bits + other bits -> not protected by MAC (exploit?)
    - Intercept + modify path + send + response revert path back -> WORKS (client sees the same response both times)
    - Add hops infront + send (I assume packet will return until local BR -> checks in router/dataplane.go l. 1389 -> if it is last hop when packet has arrived in dstIA)
      - double check by sniffing on BR or in Thun -> Question
  - MAC calculation:
    - get MAC secret from router + derive key
    - don't get same result...

Questions:
  - tshark on anapaya does not see my packets?
    - exact overview of network (interfaces/IPs)
  - Security Challenge 2024-02 -> Thun
  - Nesssus License? (Can't access reports anymore)
  - Thun access?
  - MAC -> according to Jordi, they use the same MAC algo

TODO:
  - MAC?
  - tshark on anapaya (check if extending path works) or get access to Thun
  - Analyze new machines

## 14.05.24
DONE:
  - MAC calc is working: Timezone was wrong (-2h -> UTC)
  - Sudo passwordless only on ZH machine (not in Thun, not on new test machine)
  - Thun:
    - can't setup scion on Kali in Thun (need config from Thun anapaya)
    - Thun anapaya: no special Firewall config
  - New offline Anapaya machine:
    - set up Appliance + set basic auth in CLI -> still uses default auth when accessing GUI (= intended)
    - not accessible outside ZH Wifi
    - installing over internet works
  - tshark still not working (nothing captured on anapaya devices)
  - Nessus:
    - Compliance check -> see PDF + Findings-Notes.md


Questions:
 - AccessToken for base image ?

TODO:
  - Attack: SYN flooding
  - tshark pcap
  - path extension

## 21.05.24
DONE:
- SYN flooding:
  - SYN Cookies are enabled! (Nessus check was misleading)
  - SYN flooding attack partially works -> see Findings-Notes.md
- tshark/tcpdump:
  - only captures packets with src or dst IP of the machine -> no transit packets
- Extend path
  - works (see details Findings-Notes.md)
  - measure latency + plot it (not significant difference)
- check robustness of key fetching (comp. DDoS attack)
  - DRKeys (Packet Authentication)
  - not available in Anapaya? -> currently checking

Questions:
- Test machine -> no access (192.168.130.129 not reachable) -> FIXED


TODO:
  - DDoS with BPG impact on SCION
  - DDoS Control service? or any TLS enabled port (cve-2022-0778) -> check findings
  - Try out other exploits (BUT not local access required)
  - source IP / AS spoofing
  - SYN flood from extern + check appliance version

## 11.06.24
DONE:
- TAP works on test machine
- found reason why not always SCMP parameter problem is return during path extension (see Findings-Notes.md)
- SYN flood
  - Thun has older appliance version (v0.34.1) than Zürich+Lausanne (v0.35.4)
    - only Zürich seems to be vulnerable (high CPU usage)
  - measured impact on SCION (only local impact but not extern)
  - SYN flood from extern only over SCION (but also CPU impact)
- spoofing
  - setup Lausanne
  - IP address spoofing possible (local AS)
  - script which stores down segments (1 new segment per ~5 min) -> valid for 6h
  - (Core) ASes don't forward packets with path expiry in 30 sec or less
  - No egress (outbound) spoofing protection = no egress filtering
- Presentation
- Appliance access:
    {
      "comment": "accept from keen public range",
      "rule": "ip saddr 146.148.116.135 counter accept", -> wireguard endpoint
      "sequence_id": 4
    },
    {
      "comment": "accept from keen private range",
      "rule": "ip saddr 198.18.0.0/15 counter accept", -> wireguard subnet 
      "sequence_id": 5
    },
    {
      "comment": "accept from office range",
      "rule": "ip saddr 84.253.61.72/29 counter accept", -> office anapaya??
      "sequence_id": 6
    },
- Started looking at exploits:
  - Jumbo packets (9000B) can cause DoS (but MTU is only at 9000B on scion-gateway interface)
  - x509 policy check can lead to DoS (code does not check for policies)


Questions:
- Jordi Teams Link
- Nessus License?

TODO:
- Try out other exploits (BUT not local access required)
  - what if some need interaction with Core AS?
- SCION access from ETH (wait on Jordi)
- DDOS

## 25.06.24
DONE:
- Docker container scion
  - openssl binary + library are outdated + vulnerable (see Findings-Notes.md)
- Thun has some weaknesses
- VM at ETH with access to SCION (can ping CYD)


## 05.07.24
DONE:
- Started writing:
  - Findings
  - related work
- Add Nessus Scan Result (Vulnerabilities + Compliance) to Repo (as HTML, PDF or CSV)
- libc vulnerabilities: check if vulnerable function in use (in Docker containers) 
  - -> No
  - linker vulnerability should be possible but needs local access
- Web server (caddy) -> Crash -> See Findings-Notes.md
  - tried to trigger it over SCION -> not working (no response)
- Structure report:
  - abstract
  - acknowledgements
  - introduction
  - literature review / related work (andreas maurer)
    - justification of work
  - background / SCION
    - SCION (technical overview)
    - Anapaya
    - Pentesting (generell Tools)
  - Problem statement
    - what is the problem that we address?
    - Attacker models
  - Methodology:
    - environment
      - 3 CYD locations (+ETH?)
      - 
    - types of attack vectors (device, network, SCION)
    - tools + technologies (Nessus, OpenVAS, Docker, wireshark, scapy, scion)
  - implementation
    - what was coded and how?
  - Results / Findings
  - discussion
    - compare to related work
    - future work?
    - implications / limitations
  - conclusion

Question:
- Declaration of originality -> Roland (3rd option)

TODO:
- Entwurf für anapaya (wesentliche findings)
- HTTP server crash (caddy) -> check if it can be triggered over SCION


## 16.07.24
DONE:
- Declaration of originality (Jordi okay mit 3. Option)
- Anapaya Entwurf



TODO:
- Prepare DOS attack (need IPs of CYD, SWITCH?, tool to measure scion bandwidth + scion latency (scion bwtester + scion ping))
- anapaya sections for their statements to findings


## 23.07.24
DONE:
- Test device -> double-checked if authentication was set -> it was not (no default)!
- almost done with Findings

Questions:
- How to cite/reference to scan report?

TODO:
- make precise overview on how to structure thesis report
- write
- DDoS attack
- rerun Nessus scan after update

## 30.07.24
DONE:
- Structure:
  - Abstract
  - Acknowledgements
  - Introduction
    - Importance network security (more cyber threats, etc.)
    - Anapaya/commercial SCION = emerging technology
    - Motivation of CYD -> check what Confederation/Government is interested in
    - Trust is good, control is better (check if Anapaya SCION is secure)
    - short outline of thesis
  - Related work
    - works on security of SCION (in how much detail?)
    - put related works in comparison to ours + show relevance of our work
  - Background
    - SCION
      - Core Concepts (Scalability, Control, Isolation)
      - Control plane: Path construction (PCB, MAC: calculation + verification)
      - Data plane: path segment combination, SCION path header
      - SCION Security/Authentication (a bit TRC, DRKey, SPAO)
    - Anapaya
      - role in SCION ecosystem
    - Pentesting / Security Tools
  - Problem Statement
    - SCION open source != Anapaya SCION
    - Attacker models (local end host, on-path, off-path, no SCION access)
      - capabilities + impact of attacker (what can be disrupted)
    - Impact of attacks (DoS (volumetric), path manipulation (data integrity), sniffing, spoofing, exploit misconfiguration)
    - objectives of thesis:
      - focus on operational devices
      - SCION network in use (mostly data plane)
      - separation SCION + normal internet
  - Methodology
    - general approach (explorative, due to new landscape of operational SCION devices + CYD network)
    - SCION network
      - CYD general structure + Kali VMs (config from BR) + test device
      - ETH VM (VMs?)
    - Automatic scans (Nessus, OpenVAS, SSH audit, systemd, compliance)
      - to check security aspects of device
    - manual investigation (SCION devices, SCION network, configuration)
      - to check security aspects of device
      - SCION network interactions / manipulation
    - data collection (packet capture with tshark/wireshark, scapy)
      - observing network flows
      - analyzing packet structure
  - Implementation
    - use SCION end host stack (dispatcher, daemon)
      - build from open source code
      - used to send SCION packets
      - fetch + save SCION paths
    - General open source code
      - used to verify hypotheses (if implementation is same in Anapaya SCION or not)
    - SCION packets (manipulation, crafting)
      - scapy + python code
      - uses SCION end host stack
    - How different attacker models were implemented/simulated
    - volumetric DoS
      - scion bwtester + scion ping
      - measure impact on SCION network
  - Findings
    - SCION related findings
    - Anapaya router findings
  - Discussion
    - interpretation of findings (relevance)
    - compare to related work (e.g. some compliance findings were also found already in Maurer2021)
    - future work
  - Conclusion
    - restate what goals were
    - mention most important findings
    - implication of work (Anapaya fixes some findings)

- DoS:
  - Iperf3: needs server + client (not realistic, but can measure achieved bandwidth)
  - TRex: https://trex-tgn.cisco.com/trex/release/ -> take this one

Public IP CYD: 195.176.0.50

- Questions:
  - How many details on related work?
  - DoS: Status? IPs at CYD? Access ETH? SCION bw limitation?
  - present / past tense

- Goal: 
  - End of week: related work - findings (except vol. DoS) written



## 12.08.24
TRex:
- (OVA image: https://trex-tgn.cisco.com/trex/T_Rex_162_VM_Fedora_21.ova
- Docker image)
- x86 processor -> HW recommendations: https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation
- superuser privileges

- Scrubbing at SWITCH? or ETH?
- date/time ?

- eher zu randzeiten, generell okay mit 10-20 gbit/s


Feedback:
- Related work: "et al"
- cite from book at a specific page/section ? -> \cite[Section 2.3]{book}, \cite[p. 123]{book}
- passive generell nicht gut oder wie?




## 20.08.24
- Presentation
- CYD Public IP not reachable
- TRex not working (interfaces down)
- SCION bwtester not achieving high bandwidth -> ok to test if attack impact
  


18:23: 5 Gbps
18:33: 6 Gbps
18:43: 7 Gbps
18:48: 8 Gbps
18:53: 9 Gbps
18:58: 10 Gbps
18:03: 11 Gbps
19:08: 12 Gbps
19:13: 13 Gbps
19:18: 14 Gbps
19:23: 15 Gbps
