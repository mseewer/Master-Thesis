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



