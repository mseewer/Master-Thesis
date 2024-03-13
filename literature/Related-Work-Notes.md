# Previous Work at NetSec
Dominik Lehmann. Data Plane Security Aspects in Next-Generation Internet Architecture Design. Bachelor's thesis, August 2021. Advisors: Joel Wanner and Prof. Adrian Perrig.
    - Data plan attacks + their effects (in SCIONLab)
    - 1. DDoS using multi-path
      - using temporal lensing -> seems to work
    - 2. prepend AS to path -> spoof = attacker can intercept replies from server
         -> works = many QUIC connections in parallel
    - Contains Threat Model of each attack
Alexander Kunze. Efficient Automated Testing Framework for the SCION Architecture. Bachelor's thesis, March 2020. Advisors: Benjamin Rothenberger and Prof. Adrian Perrig.
    - Fuzzing SCION components
    - found bug in border router bound checks for packets (BUT now this part is formally verified)
Joel Wanner. Formal Verification of DoS-Resilient Protocols. Master's thesis, August 2019. Advisors: Dr. Christoph Sprenger, Dr. Ralf Sasse, and Prof. Adrian Perrig.
    - not all attacks captured: Slow DoS attacks
Annika Glauser. Efficient DDoS Defense for SCION Services. Master's thesis, June 2019. Advisors: Benjamin Rothenberger and Prof. Adrian Perrig.
    - check how vulnerable SCION services are
    - implement diff. filters (packet/request/whitelisting/path/rate-limiting filters)
        -> no to some little overhead (throughput) -> less than 5%
    - has some threat model
Benjamin Rothenberger. Security Analysis of a Future Internet Architecture. Master's thesis, April 2016. Advisors: Dr. David Barrera and Prof. Adrian Perrig.
    - attacks on: infrastructure services, routing protocols (in control plane), confidentiality, availability
    - Threat model
    - also compared to BGPsec / DNSSEC
    - used Fortify static code analysis to find security vulnerabilities of source code

COLIBRI -> defend against volumetric attacks

# Hager - SCION unangreifbar und unaufklärbar
SCION Kommunikation -> Nicht anonym 

# Silvan - Testbed

Packet reordering -> affect performance of SCION IP Gateway (SIG)
Network Tap device -> subset of Dolev-Yao model
Edge device -> Interconnection SCION<->IP
Device Configuration: 
    Only Prometheus + SSH (with Public Key) exposed
    Has VPN (WireGuard) tunnel
    Configure over GUI / REST API (from localhost or remote (create pw-account))
    stored in JSON
SCION IP Gateway (SIG)
    No checksum (is 0), authentication, encryption -> need to ensured by upper-layers
Endhosts:
    Dispatcher: send + receive packets (port mapping)
    Daemon: fetches path info, verifies path (authenticated)
    bootstrapper: Client queries bootstrap server -> downloads + installs config to enabel dispatcher + daemon

Tools:
    Read, drop, modify, insert packets

Reorder only on fragments
No SCION-specific firewall


Network Setup -> page 11

TODOs
- Check OS (still Ubuntu 18.04.6)




# SCION Forensics
(sehr viel blabla)

Automatic SCION Security Audit Tool (Based on Lynis)
    Result: solid + secure Ubuntu config (only if server setup is hardened)
SCION hinterlässt sehr wenig Spuren

vieles in VMs

Tripwire als tool (nicht CIS CAT Pro, aber wäre auch gut) -> Lynis gebraucht


# Anapaya

Route control, failure isolation, explicit trust information for end-to-end communication

# A Survey of BGP Security Issues and Solutions (Tells more about solutions)
# A Survey of BGP Security

BGP: no guarantees provided
introduce false information -> snoop on traffic -> impersonate/block web sites
BPG using TCP: no need for error corretion / retransmission
    no confidentiality, no integrity -> MitM
    DoS: even remotely: rust sent RST TCP packet to close connection / SYN flooding
Solutions:
    Pairwise Keying -> does not scale
    Hash
    MAC (needs sym. key)
    DH Key Exchange
    PKI -> sign BGP messages (does not exist)
    Certificates
Implemented Solutions:
    Integrity between pairs of routers + can authenticate each other (using MD5 but also others hash functions)
    Peers share key -> Encrypt + Add sequence number, PREDECESSOR to messages -> and sign it (using Digital Signature)
        -> complex as the number of peers scales


# The Complete Guide to SCION
Chapter 7 -> Security Analysis

Security Goals:
    P1 Global connectivity
    P2 Routing security (routing information can't be altered)
    P3 absence of kill switches (no global outage)
    P4 weak / strong detectability (on-path attacker can't disguise presence to subsequent ASes + destination -> strong if entities can detect it too)
    P5 Beacon authorization
    P6 path authorization (packets only forwarded along authorized paths)
    P7 source authentication
    P8 path transparency + control
    P9 truthful forwarding (ASes forward packets along the intended path)
    P10 same as P7 but for end host
    P11 Packet integrity
    P12 Path validation
    P13 Condifdentiality
    P14 Censorship resilience
    P15 Anonymity
Threat Model
    connectivity + availability between 2 entities can't be guaranteed if no attacker-free path exists
Has Code-level verification -> on SCIONs border router


# In depth analysis of BGP protocol, its security vulnerabilities and solutions
(many snapshots, doesn't look like a scientific paper)

Security issues in BGP:
    Eaves dropping (since not encrypted)
    Inserting forged routes into BGP
    Increasing the length of AS path
    Resetting the BGP neighbor relationship and flooding bgp using synchronous attack
        (MitM, spoof IP of BGP originator and send RST packet)
    Route flapping (change routes rapidly -> instability -> no convergence -> Slowdown/loss of traffic) -> solution: route flap dampening (ignore flapping routes for a certain time)
    DoS + DDoS attacks
    Line cutting attacks

# Secure Border Gateway Protocol (S-BGP)

Defines Threat model (accidental + malicious misconfiguration) -> not PoLP
Countermeasrues:
    2 PKIs, new field "attestations", use of IPsec
    1. PKI: BPG speakers have a certificate
    2. PKI: Certificate for address allocation (own a part of IP address space)
    Attestations: Route + address attestations
    Route validation: validate each advertised route (check IP address, AS path)
    IPsec: protect BGP messages -> no encryption, just authentication, data integrity, anti-replay (betwenn point-to-point)

Still vulnerabilities:
    eavesdropping still possible
    suppression of malicious BGP speaker still possible
    slower, more to transmit, more to store, more to process


# On interdomain routing security and pretty secure BGP (psBGP)