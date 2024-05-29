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
  - Thun has older appliance version (v0.34.1) than Zürich (v0.35.4)
  - measured impact on SCION (only local impact but not extern)
  - SYN flood from extern only over SCION
- spoofing
  - setup Lausanne
  - IP address spoofing possible (local AS)
  - script which stores down segments (1 new segment per ~5 min) -> valid for 6h
  - 
