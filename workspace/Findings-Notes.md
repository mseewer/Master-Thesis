

# Nessus:
- Fix: Mostly just update Kernel
- Many attacks need CAP_NET_ADMIN capability
- An issue was discovered in the USB subsystem in the Linux kernel through 6.4.2. There is an out-of-bounds and crash in read_descriptors in drivers/usb/core/sysfs.c. (CVE-2023-37453) -> Exploit (https://syzkaller.appspot.com/bug?extid=18996170f8096c6174d0)

- A NULL pointer dereference flaw was found in the Linux kernel ipv4 stack. The socket buffer (skb) was assumed to be associated with a device before calling __ip_options_compile, which is not always the case if the skb is re-routed by ipvs. This issue may allow a local user with CAP_NET_ADMIN privileges to crash the system. (CVE-2023-42754) -> Exploit (https://seclists.org/oss-sec/2023/q4/14), IPVS not in use on Anapaya device

- A use-after-free vulnerability was found in drivers/nvme/target/tcp.c` in `nvmet_tcp_free_crypto` due to a logical bug in the NVMe-oF/TCP subsystem in the Linux kernel. This issue may allow a malicious local privileged user to cause a use-after-free and double-free problem, which may permit remote code execution or lead to local privilege escalation problem. (CVE-2023-5178)  -> Exploit, POC: https://github.com/rockrid3r/CVE-2023-5178?tab=readme-ov-file

- An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel before 6.5.3. A buffer size may not be adequate for frames larger than the MTU. (CVE-2023-45871) -> Explain how to exploit (https://www.linkedin.com/pulse/dont-rely-only-advisories-untold-story-cve-2023-45871-eric-heindl-oaajf?trk=articles_directory)


- An issue was discovered in the Linux kernel before 6.5.9, exploitable by local users with userspace access to MMIO registers. Incorrect access checking in the #VC handler and instruction emulation of the SEV-ES emulation of MMIO accesses could lead to arbitrary write access to kernel memory (and thus privilege escalation). This depends on a race condition through which userspace can replace an instruction before the #VC handler reads it. (CVE-2023-46813) -> Exploit https://github.com/Freax13/cve-2023-46813-poc

python-pip
- urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user.
However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5. (CVE-2023-43804) -> POC: https://github.com/JawadPy/CVE-2023-43804-Exploit


-An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.
(CVE-2023-6606) -> PoC: https://bugzilla.kernel.org/show_bug.cgi?id=218218

Vim:
- Vim before 9.0.2142 has a stack-based buffer overflow because did_set_langmap in map.c calls sprintf to write to the error buffer that is passed down to the option callback functions. (CVE-2024-22667) -> https://gist.githubusercontent.com/henices/2467e7f22dcc2aa97a2453e197b55a0c/raw/7b54bccc9a129c604fb139266f4497ab7aaa94c7/gistfile1.txt


- An array indexing vulnerability was found in the netfilter subsystem of the Linux kernel. A missing macro could lead to a miscalculation of the `h->nets` array offset, providing attackers with the primitive to arbitrarily increment/decrement a memory buffer out-of-bound. This issue may allow a local user to crash the system or potentially escalate their privileges on the system. (CVE-2023-42753) -> PoC: https://seclists.org/oss-sec/2023/q3/216

- A flaw was found in the IPv4 Resource Reservation Protocol (RSVP) classifier in the Linux kernel. The xprt pointer may go beyond the linear part of the skb, leading to an out-of-bounds read in the `rsvp_classify` function. This issue may allow a local user to crash the system and cause a denial of service.
(CVE-2023-42755) -> PoC: https://seclists.org/oss-sec/2023/q3/229

- A flaw was found in the Netfilter subsystem of the Linux kernel. A race condition between IPSET_CMD_ADD and IPSET_CMD_SWAP can lead to a kernel panic due to the invocation of `__ip_set_put` on a wrong `set`.
This issue may allow a local user to crash the system. (CVE-2023-42756) -> PoC: https://seclists.org/oss-sec/2023/q3/242

- A use-after-free vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited to achieve local privilege escalation. When the plug qdisc is used as a class of the qfq qdisc, sending network packets triggers use-after-free in qfq_dequeue() due to the incorrect .peek handler of sch_plug and lack of error checking in agg_dequeue(). We recommend upgrading past commit 8fc134fee27f2263988ae38920bc03da416b03d8. (CVE-2023-4921) -> Exploit: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8fc134fee27f2263988ae38920bc03da416b03d8


libxml2
- An issue was discovered in libxml2 before 2.11.7 and 2.12.x before 2.12.5. When using the XML Reader interface with DTD validation and XInclude expansion enabled, processing crafted XML documents can lead to an xmlValidatePopElement use-after-free. (CVE-2024-25062) -> https://gitlab.gnome.org/GNOME/libxml2/-/issues/604


## remote attacker
- Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30 may allow an unauthenticated user to potentially enable escalation of privilege via network access.
(CVE-2023-25775)




## Compliance
- [WRONG] No SYN Cookies -> they are enabled
  - SYN Flood attack

- No password policy (like minlen)

- password hashing algorithm = SHA512 -> not ideal

- USB Storage Devices are allowed


# OpenVAS + NMAP
- Weak SSH MAC Algorithms Enabled (64 bit MAC)
  - umac-64-etm@openssh.com
  - umac-64@openssh.com


## Open ports on the server

sudo netstat -tuUnpa 
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 198.18.30.2:443         0.0.0.0:*               LISTEN      505313/caddy        -> Web server (for Anapaya appliance)
tcp        0      0 198.18.30.2:80          0.0.0.0:*               LISTEN      505313/caddy        
tcp        0      0 127.0.0.1:51119         0.0.0.0:*               LISTEN      553625/promtail     -> Prometheus (sends data out)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      503671/systemd-reso -> DNS
tcp        0      0 192.168.111.1:80        0.0.0.0:*               LISTEN      505313/caddy        
tcp        0      0 192.168.111.1:443       0.0.0.0:*               LISTEN      505313/caddy        
tcp        0      0 127.0.0.1:443           0.0.0.0:*               LISTEN      505313/caddy        
tcp        0      0 127.0.0.1:33333         0.0.0.0:*               LISTEN      553814/vpp          -> Vector Packet Processor (VPP)
tcp        0      0 192.168.111.1:30252     0.0.0.0:*               LISTEN      553537/scion-all    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      506056/sshd: /usr/s -> SSH
tcp        0      0 127.0.0.1:41001         0.0.0.0:*               LISTEN      553537/scion-all    
tcp        0      0 127.0.0.1:41000         0.0.0.0:*               LISTEN      553537/scion-all    
tcp        0      0 127.0.0.1:41201         0.0.0.0:*               LISTEN      553473/scion-all    
tcp        0      0 127.0.0.1:41200         0.0.0.0:*               LISTEN      553473/scion-all    
tcp        0      0 127.0.0.1:41101         0.0.0.0:*               LISTEN      553843/scion-all    
tcp        0      0 127.0.0.1:41100         0.0.0.0:*               LISTEN      553843/scion-all    
tcp        0      0 127.0.0.1:41301         0.0.0.0:*               LISTEN      553855/scion-all    
tcp        0      0 127.0.0.1:41300         0.0.0.0:*               LISTEN      553855/scion-all    
tcp        0      0 127.0.0.1:41302         0.0.0.0:*               LISTEN      553855/scion-all    
tcp        0      0 127.0.0.1:41401         0.0.0.0:*               LISTEN      553809/scion-all    
tcp        0      0 127.0.0.1:41400         0.0.0.0:*               LISTEN      553809/scion-all    
tcp        0      0 127.0.0.1:41601         0.0.0.0:*               LISTEN      553961/scion-all    
tcp        0      0 127.0.0.1:41600         0.0.0.0:*               LISTEN      553961/scion-all    
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      553747/otelcol-cont -> Open Telemetry Collector
tcp        0      0 127.0.0.1:9080          0.0.0.0:*               LISTEN      553625/promtail     -> Prometheus (sends data out)
tcp        0      0 127.0.0.1:9100          0.0.0.0:*               LISTEN      553603/node_exporte -> Prometheus (collects HW/kernel data)
tcp        0      0 127.0.0.1:48001         0.0.0.0:*               LISTEN      528952/appliance-in 
tcp        0      0 127.0.0.1:48000         0.0.0.0:*               LISTEN      528952/appliance-in 
tcp        0      0 127.0.0.1:48021         0.0.0.0:*               LISTEN      553093/appliance    -> Anapaya appliance / SCION configuration
tcp        0      0 127.0.0.1:48020         0.0.0.0:*               LISTEN      553093/appliance    
tcp        0      0 127.0.0.1:48022         0.0.0.0:*               LISTEN      553093/appliance    
tcp        0      0 127.0.0.1:48031         0.0.0.0:*               LISTEN      553563/appliance    
tcp        0      0 127.0.0.1:48030         0.0.0.0:*               LISTEN      553563/appliance    
tcp        0      0 127.0.0.1:48041         0.0.0.0:*               LISTEN      553747/otelcol-cont 
tcp        0      0 127.0.0.1:48050         0.0.0.0:*               LISTEN      505313/caddy        
tcp        0      0 127.0.0.1:41201         127.0.0.1:56642         ESTABLISHED 553473/scion-all    
tcp        0      0 127.0.0.1:50476         127.0.0.1:41300         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:48021         127.0.0.1:59394         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:56990         127.0.0.1:41400         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:58506         127.0.0.1:48050         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:54966         127.0.0.1:48001         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:8888          127.0.0.1:51004         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:48001         127.0.0.1:54966         ESTABLISHED 528952/appliance-in 
tcp        0      0 127.0.0.1:51004         127.0.0.1:8888          ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:51652         127.0.0.1:41401         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:41200         127.0.0.1:60860         ESTABLISHED 553473/scion-all    
tcp        0      0 127.0.0.1:56642         127.0.0.1:41201         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:48041         127.0.0.1:52872         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:59394         127.0.0.1:48021         ESTABLISHED 528952/appliance-in 
tcp        0      0 127.0.0.1:57828         127.0.0.1:48050         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 192.168.111.1:52574     192.168.111.1:30252     TIME_WAIT   -                   
tcp        0      0 127.0.0.1:41000         127.0.0.1:57112         ESTABLISHED 553537/scion-all    
tcp        0      0 127.0.0.1:57112         127.0.0.1:41000         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:59094         127.0.0.1:41301         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:41302         127.0.0.1:56198         ESTABLISHED 553855/scion-all    
tcp        0      0 198.18.30.2:443         198.18.0.1:54562        ESTABLISHED 505313/caddy        
tcp        0      0 127.0.0.1:54298         127.0.0.1:9080          ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:48050         127.0.0.1:60524         TIME_WAIT   -                   
tcp        0      0 127.0.0.1:56672         127.0.0.1:41600         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:53152         127.0.0.1:9100          ESTABLISHED 553747/otelcol-cont 
tcp        0   3172 192.168.111.1:22        192.168.111.25:59364    ESTABLISHED 583501/sshd: anapay 
tcp        0      0 127.0.0.1:52872         127.0.0.1:48041         ESTABLISHED 505313/caddy        
tcp        0      0 127.0.0.1:50564         127.0.0.1:48031         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:41300         127.0.0.1:50476         ESTABLISHED 553855/scion-all    
tcp        0      0 127.0.0.1:48031         127.0.0.1:50564         ESTABLISHED 553563/appliance    
tcp        0      0 127.0.0.1:48022         127.0.0.1:57606         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:53528         127.0.0.1:41001         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:41301         127.0.0.1:59094         ESTABLISHED 553855/scion-all    
tcp        0      0 127.0.0.1:48050         127.0.0.1:57828         ESTABLISHED 505313/caddy        
tcp        0      0 127.0.0.1:56198         127.0.0.1:41302         ESTABLISHED 553473/scion-all    
tcp        0      0 127.0.0.1:58804         127.0.0.1:41601         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:60860         127.0.0.1:41200         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:41001         127.0.0.1:53528         ESTABLISHED 553537/scion-all    
tcp        0      0 127.0.0.1:57606         127.0.0.1:48022         ESTABLISHED 505313/caddy        
tcp        0      0 127.0.0.1:54160         127.0.0.1:41100         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:41401         127.0.0.1:51652         ESTABLISHED 553809/scion-all    
tcp        0      0 127.0.0.1:53928         127.0.0.1:41101         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:48020         127.0.0.1:57494         ESTABLISHED 553093/appliance    
tcp        0      0 127.0.0.1:41101         127.0.0.1:53928         ESTABLISHED 553843/scion-all    
tcp        0      0 127.0.0.1:57494         127.0.0.1:48020         ESTABLISHED 553747/otelcol-cont 
tcp        0      0 127.0.0.1:41601         127.0.0.1:58804         ESTABLISHED 553961/scion-all    
tcp        0      0 127.0.0.1:48050         127.0.0.1:58506         ESTABLISHED 505313/caddy        
tcp        0      0 127.0.0.1:60922         127.0.0.1:41302         TIME_WAIT   -                   
tcp        0      0 127.0.0.1:9100          127.0.0.1:53152         ESTABLISHED 553603/node_exporte 
tcp        0      0 198.18.30.2:58580       198.18.0.238:443        ESTABLISHED 553625/promtail     
tcp        0      0 127.0.0.1:41400         127.0.0.1:56990         ESTABLISHED 553809/scion-all    
tcp        0      0 127.0.0.1:9080          127.0.0.1:54298         ESTABLISHED 553625/promtail     
tcp        0      0 127.0.0.1:41600         127.0.0.1:56672         ESTABLISHED 553961/scion-all    
tcp        0      0 127.0.0.1:41100         127.0.0.1:54160         ESTABLISHED 553843/scion-all    
tcp6       0      0 :::80                   :::*                    LISTEN      505313/caddy        
tcp6       0      0 :::22                   :::*                    LISTEN      506056/sshd: /usr/s 
tcp6       0      0 :::42001                :::*                    LISTEN      505313/caddy        
tcp6       0      0 198.18.30.2:42001       198.18.0.1:59918        ESTABLISHED 505313/caddy        
udp        0      0 127.0.0.53:53           0.0.0.0:*                           503671/systemd-reso 
udp        0      0 198.18.30.2:443         0.0.0.0:*                           505313/caddy        
udp        0      0 192.168.111.1:443       0.0.0.0:*                           505313/caddy        
udp        0      0 127.0.0.1:443           0.0.0.0:*                           505313/caddy        
udp        0      0 0.0.0.0:51021           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:54222         127.0.0.1:6831          ESTABLISHED 553625/promtail     
udp        0      0 0.0.0.0:30041           0.0.0.0:*                           553809/scion-all    -> Dispatcher
udp        0      0 192.168.111.1:30042     0.0.0.0:*                           553814/vpp          
udp6       0      0 :::51021                :::*                                -                   -> Wireguard (Anapaya)
udp6       0      0 :::30041                :::*                                553809/scion-all    -> Dispatcher


## Services running
systemctl list-units --type=service --state=running
  UNIT                         LOAD   ACTIVE SUB     DESCRIPTION                                   
  appliance-controller.service loaded active running Anapaya Appliance Controller Service
  appliance-installer.service  loaded active running Anapaya Appliance Installer
  containerd.service           loaded active running containerd container runtime
  cron.service                 loaded active running Regular background program processing daemon
  dbus.service                 loaded active running D-Bus System Message Bus
  docker.service               loaded active running Docker Application Container Engine
  getty@tty1.service           loaded active running Getty on tty1
  irqbalance.service           loaded active running irqbalance daemon
  multipathd.service           loaded active running Device-Mapper Multipath Device Controller
  polkit.service               loaded active running Authorization Manager
  rsyslog.service              loaded active running System Logging Service
  serial-getty@ttyS0.service   loaded active running Serial Getty on ttyS0
  ssh.service                  loaded active running OpenBSD Secure Shell server
  systemd-journald.service     loaded active running Journal Service
  systemd-logind.service       loaded active running User Login Management
  systemd-networkd.service     loaded active running Network Configuration
  systemd-resolved.service     loaded active running Network Name Resolution
  systemd-timesyncd.service    loaded active running Network Time Synchronization
  systemd-udevd.service        loaded active running Rule-based Manager for Device Events and Files
  thermald.service             loaded active running Thermal Daemon Service
  udisks2.service              loaded active running Disk Manager
  upower.service               loaded active running Daemon for power management


## Appliance
- new config (also change firewall rules)
- Add new TRC
- upload/install/delete system packages (binary)
- upload/install/delete SCION packages (binary)
- install signatures + public signing keys (what are these?)

served with Caddy Web Server (version 2.6.4)  
- CVE-2023-44487: Vulnerable to denial of service (Rapid Reset Attack)
- Requires certificate of server
- Impl. with SCION + scapy  (https://github.com/secdev/scapy/blob/master/doc/notebooks/HTTP_2_Tuto.ipynb)



## Docker Trivy
vpp-dataplane:latest, appliance:latest (debian 11.1)  -> same results as scion-all

scion-all:latest (debian 11.1)
==================================
Total: 58 (UNKNOWN: 0, LOW: 10, MEDIUM: 27, HIGH: 14, CRITICAL: 7)

┌───────────┬──────────────────┬──────────┬──────────────┬───────────────────┬──────────────────┬──────────────────────────────────────────────────────────────┐
│  Library  │  Vulnerability   │ Severity │    Status    │ Installed Version │  Fixed Version   │                            Title                             │
├───────────┼──────────────────┼──────────┼──────────────┼───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libc6     │ CVE-2021-33574   │ CRITICAL │ fixed        │ 2.31-13+deb11u2   │ 2.31-13+deb11u3  │ glibc: mq_notify does not handle separately allocated thread │
│           │                  │          │              │                   │                  │ attributes                                                   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-33574                   │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-23218   │          │              │                   │                  │ glibc: Stack-based buffer overflow in svcunix_create via     │
│           │                  │          │              │                   │                  │ long pathnames                                               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-23218                   │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-23219   │          │              │                   │                  │ glibc: Stack-based buffer overflow in sunrpc clnt_create via │
│           │                  │          │              │                   │                  │ a long pathname                                              │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-23219                   │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2021-3999    │ HIGH     │              │                   │ 2.31-13+deb11u4  │ glibc: Off-by-one buffer overflow/underflow in getcwd()      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-3999                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-4911    │          │              │                   │ 2.31-13+deb11u7  │ glibc: buffer overflow in ld.so leading to privilege         │
│           │                  │          │              │                   │                  │ escalation                                                   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4911                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-2961    │          │              │                   │ 2.31-13+deb11u9  │ glibc: Out of bounds write in iconv may lead to remote       │
│           │                  │          │              │                   │                  │ code...                                                      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2961                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-33599   │          │              │                   │ 2.31-13+deb11u10 │ glibc: stack-based buffer overflow in netgroup cache         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-33599                   │
│           ├──────────────────┼──────────┼──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-4806    │ MEDIUM   │ affected     │                   │                  │ glibc: potential use-after-free in getaddrinfo()             │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4806                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-4813    │          │              │                   │                  │ glibc: potential use-after-free in gaih_inet()               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4813                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-33600   │          │ fixed        │                   │ 2.31-13+deb11u10 │ glibc: null pointer dereferences after failed netgroup cache │
│           │                  │          │              │                   │                  │ insertion                                                    │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-33600                   │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-33601   │          │              │                   │                  │ glibc: netgroup cache may terminate daemon on memory         │
│           │                  │          │              │                   │                  │ allocation failure                                           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-33601                   │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-33602   │          │              │                   │                  │ glibc: netgroup cache assumes NSS callback uses in-buffer    │
│           │                  │          │              │                   │                  │ strings                                                      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-33602                   │
│           ├──────────────────┼──────────┼──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2010-4756    │ LOW      │ affected     │                   │                  │ glibc: glob implementation can cause excessive CPU and       │
│           │                  │          │              │                   │                  │ memory consumption due to...                                 │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2010-4756                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2018-20796   │          │              │                   │                  │ glibc: uncontrolled recursion in function                    │
│           │                  │          │              │                   │                  │ check_dst_limits_calc_pos_1 in posix/regexec.c               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2018-20796                   │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2019-1010022 │          │              │                   │                  │ glibc: stack guard protection bypass                         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010022                 │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2019-1010023 │          │              │                   │                  │ glibc: running ldd on malicious ELF leads to code execution  │
│           │                  │          │              │                   │                  │ because of...                                                │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010023                 │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2019-1010024 │          │              │                   │                  │ glibc: ASLR bypass using cache of thread stack and heap      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010024                 │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2019-1010025 │          │              │                   │                  │ glibc: information disclosure of heap addresses of           │
│           │                  │          │              │                   │                  │ pthread_created thread                                       │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010025                 │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2019-9192    │          │              │                   │                  │ glibc: uncontrolled recursion in function                    │
│           │                  │          │              │                   │                  │ check_dst_limits_calc_pos_1 in posix/regexec.c               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-9192                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2021-43396   │          │ fixed        │                   │ 2.31-13+deb11u3  │ glibc: conversion from ISO-2022-JP-3 with iconv may emit     │
│           │                  │          │              │                   │                  │ spurious NUL character on...                                 │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-43396                   │
├───────────┼──────────────────┼──────────┤              ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libssl1.1 │ CVE-2022-1292    │ CRITICAL │              │ 1.1.1k-1+deb11u1  │ 1.1.1n-0+deb11u2 │ openssl: c_rehash script allows command injection            │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-1292                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-2068    │          │              │                   │ 1.1.1n-0+deb11u3 │ openssl: the c_rehash script allows command injection        │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2068                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-0778    │ HIGH     │              │                   │ 1.1.1k-1+deb11u2 │ openssl: Infinite loop in BN_mod_sqrt() reachable when       │
│           │                  │          │              │                   │                  │ parsing certificates                                         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-0778                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-4450    │          │              │                   │ 1.1.1n-0+deb11u4 │ openssl: double free after calling PEM_read_bio_ex           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4450                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0215    │          │              │                   │                  │ openssl: use-after-free following BIO_new_NDEF               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0215                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0286    │          │              │                   │                  │ openssl: X.400 address type confusion in X.509 GeneralName   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0286                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0464    │          │              │                   │ 1.1.1n-0+deb11u5 │ openssl: Denial of service by excessive resource usage in    │
│           │                  │          │              │                   │                  │ verifying X509 policy...                                     │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0464                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2021-4160    │ MEDIUM   │              │                   │ 1.1.1k-1+deb11u2 │ openssl: Carry propagation bug in the MIPS32 and MIPS64      │
│           │                  │          │              │                   │                  │ squaring procedure                                           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-4160                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-2097    │          │              │                   │ 1.1.1n-0+deb11u4 │ openssl: AES OCB fails to encrypt some bytes                 │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2097                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-4304    │          │              │                   │                  │ openssl: timing attack in RSA Decryption implementation      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4304                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0465    │          │              │                   │ 1.1.1n-0+deb11u5 │ openssl: Invalid certificate policies in leaf certificates   │
│           │                  │          │              │                   │                  │ are silently ignored                                         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0465                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0466    │          │              │                   │                  │ openssl: Certificate policy check not enabled                │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0466                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-2650    │          │              │                   │                  │ openssl: Possible DoS translating ASN.1 object identifiers   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-3446    │          │              │                   │ 1.1.1v-0~deb11u1 │ openssl: Excessive time spent checking DH keys and           │
│           │                  │          │              │                   │                  │ parameters                                                   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-3817    │          │              │                   │                  │ OpenSSL: Excessive time spent checking DH q parameter value  │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-5678    │          │ affected     │                   │                  │ openssl: Generating excessively long X9.42 DH keys or        │
│           │                  │          │              │                   │                  │ checking excessively long X9.42...                           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-0727    │          │              │                   │                  │ openssl: denial of service via null dereference              │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-4741    │          │ fix_deferred │                   │                  │ openssl: Use After Free with SSL_free_buffers                │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-2511    │ LOW      │              │                   │                  │ openssl: Unbounded memory growth with session handling in    │
│           │                  │          │              │                   │                  │ TLSv1.3                                                      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                    │
├───────────┼──────────────────┼──────────┼──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│ openssl   │ CVE-2022-1292    │ CRITICAL │ fixed        │                   │ 1.1.1n-0+deb11u2 │ openssl: c_rehash script allows command injection            │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-1292                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-2068    │          │              │                   │ 1.1.1n-0+deb11u3 │ openssl: the c_rehash script allows command injection        │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2068                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-0778    │ HIGH     │              │                   │ 1.1.1k-1+deb11u2 │ openssl: Infinite loop in BN_mod_sqrt() reachable when       │
│           │                  │          │              │                   │                  │ parsing certificates                                         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-0778                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-4450    │          │              │                   │ 1.1.1n-0+deb11u4 │ openssl: double free after calling PEM_read_bio_ex           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4450                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0215    │          │              │                   │                  │ openssl: use-after-free following BIO_new_NDEF               │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0215                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0286    │          │              │                   │                  │ openssl: X.400 address type confusion in X.509 GeneralName   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0286                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0464    │          │              │                   │ 1.1.1n-0+deb11u5 │ openssl: Denial of service by excessive resource usage in    │
│           │                  │          │              │                   │                  │ verifying X509 policy...                                     │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0464                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2021-4160    │ MEDIUM   │              │                   │ 1.1.1k-1+deb11u2 │ openssl: Carry propagation bug in the MIPS32 and MIPS64      │
│           │                  │          │              │                   │                  │ squaring procedure                                           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-4160                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-2097    │          │              │                   │ 1.1.1n-0+deb11u4 │ openssl: AES OCB fails to encrypt some bytes                 │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2097                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2022-4304    │          │              │                   │                  │ openssl: timing attack in RSA Decryption implementation      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4304                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0465    │          │              │                   │ 1.1.1n-0+deb11u5 │ openssl: Invalid certificate policies in leaf certificates   │
│           │                  │          │              │                   │                  │ are silently ignored                                         │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0465                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-0466    │          │              │                   │                  │ openssl: Certificate policy check not enabled                │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0466                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-2650    │          │              │                   │                  │ openssl: Possible DoS translating ASN.1 object identifiers   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-3446    │          │              │                   │ 1.1.1v-0~deb11u1 │ openssl: Excessive time spent checking DH keys and           │
│           │                  │          │              │                   │                  │ parameters                                                   │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                    │
│           ├──────────────────┤          │              │                   │                  ├──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-3817    │          │              │                   │                  │ OpenSSL: Excessive time spent checking DH q parameter value  │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2023-5678    │          │ affected     │                   │                  │ openssl: Generating excessively long X9.42 DH keys or        │
│           │                  │          │              │                   │                  │ checking excessively long X9.42...                           │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                    │
│           ├──────────────────┤          │              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-0727    │          │              │                   │                  │ openssl: denial of service via null dereference              │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                    │
│           ├──────────────────┤          ├──────────────┤                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-4741    │          │ fix_deferred │                   │                  │ openssl: Use After Free with SSL_free_buffers                │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                    │
│           ├──────────────────┼──────────┤              │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│           │ CVE-2024-2511    │ LOW      │              │                   │                  │ openssl: Unbounded memory growth with session handling in    │
│           │                  │          │              │                   │                  │ TLSv1.3                                                      │
│           │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                    │
└───────────┴──────────────────┴──────────┴──────────────┴───────────────────┴──────────────────┴──────────────────────────────────────────────────────────────┘




# SCION code

## Router
- router/control/conf.go *ConfigDataplane* line 125
  - checks if key is not zero (not empty key) -> if empty then MAC is never set and gets used later
  - keys saved on anapaya machine in: /etc/scion/router/64-2_0_2b/keys/
  - this key is also saved in config json (on appliance) and (I assume) gets created on the file system (like the other config files)
  - Otherwise MAC algo is always the same: SCION cypto (scrypto) -> scrypto.MAC
    - pbkdf(masterkey) (SHA256, 1000 iterations) -> 16B key -> AES_128(key) -> 16B block -> CMAC (again AES_128(key) with some additional shifting) -> final MAC value
    - CMAC Reference: https://github.com/dchest/cmac/blob/v1.0.0/cmac.go
      - New() -> sets key
      - Write(data) -> actual MAC computation on given data
      - Sum() -> returns MAC value / digest


# Notation
- Path: "64-2:0:2b#0,1 64-559#24,31 64-2:0:13#31,29 64-15623#11,12 64-3303#20,25 64-2:0:2c#2,0"
  - IA#ingress,egress interface (0 means start/end of segment)

# Manual investigation
SCION version: 0.35.4

Known open ports:
- SCION: 30041 (dispatcher) and 50000 (source: https://scion-architecture.net/pages/faq/ -> NOT anapaya)
- default port range we use for SCION interfaces is 30100 - 39999 (https://docs.anapaya.net/en/release-v0.35/resources/ports/)

Thun:
- No special Firewall configured -> easier for SYN Attack or DDos?


Password Policy
- min Len = 6
- no entropy check or history

Syn Flood:
- Can trigger 1 CPU core to 100% -> on port 443, 30252, 42001 (not port 22, 80)
- only in ZH, not in THUN (other machine, double the cores / half the memory)

Path extension:
- works: prepend path, set CurrHF to right index
- packet arrives at destination, which uses the same invalid path to repy
- reply packet is dropped by the router at the end of the valid path / start of prepended path
- this router sends SCMP Parameter Problem back to original destination (but only on smaller packets)
- Total path length has to be max 64 hops (all segments)
- ZH -> THUN: 2, 4, 2 hops normally
  Details
  - 12 bytes more for every additional hop
  - Error message size is = same header as original packet (which is total size - payload size) + size of original packet
  - if error message size is > 1232B -> remove payload bytes until it fits
  - BUT if not enough payload bytes to remove -> NO error message is sent

Spoofing:
- Swisscom, Sunrise AS sends path expired message back but 30 seconds before actual expiration (All BR do that, checked with up segments as well)
- Source ISD / AS / Address can be changed and is not validated of AS

Daemon:
- disabled segment verification (due to control service in same trust zone, no need to verify segments again)

Caddy not reported by Nessus

System resources -> no limits set

## SSH

python3 ssh-audit.py 192.168.110.1               
# general
(gen) banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
(gen) software: OpenSSH 8.9p1
(gen) compatibility: OpenSSH 8.5+, Dropbear SSH 2020.79+
(gen) compression: enabled (zlib@openssh.com)

# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4, Dropbear SSH 2018.76
                                            `- [info] default key exchange from OpenSSH 7.4 to 8.9
(kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.4, Dropbear SSH 2013.62
                                            `- [info] default key exchange from OpenSSH 6.5 to 7.3
(kex) ecdh-sha2-nistp256                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp384                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp521                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) sntrup761x25519-sha512@openssh.com    -- [info] available since OpenSSH 8.5
                                            `- [info] default key exchange since OpenSSH 9.0
(kex) diffie-hellman-group-exchange-sha256 (3072-bit) -- [info] available since OpenSSH 4.4
                                                      `- [info] OpenSSH's GEX fallback mechanism was triggered during testing. Very old SSH clients will still be able to create connections using a 2048-bit modulus, though modern clients will use 3072. This can only be disabled by recompiling the code (see https://github.com/openssh/openssh-                                                                        portable/blob/V_9_4/dh.c#L477).                                                                                                                                                                                                                    
(kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73
(kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3
(kex) diffie-hellman-group14-sha256         -- [warn] 2048-bit modulus only provides 112-bits of symmetric strength
                                            `- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73

# host-key algorithms
(key) rsa-sha2-512 (3072-bit)               -- [info] available since OpenSSH 7.2
(key) rsa-sha2-256 (3072-bit)               -- [info] available since OpenSSH 7.2, Dropbear SSH 2020.79
(key) ecdsa-sha2-nistp256                   -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency
                                            `- [warn] using weak random number generator could reveal the key
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79

# encryption algorithms (ciphers)
(enc) chacha20-poly1305@openssh.com         -- [warn] vulnerable to the Terrapin attack (CVE-2023-48795), allowing message prefix truncation
                                            `- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79
                                            `- [info] default cipher since OpenSSH 6.9
(enc) aes128-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52
(enc) aes192-ctr                            -- [info] available since OpenSSH 3.7
(enc) aes256-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52
(enc) aes128-gcm@openssh.com                -- [info] available since OpenSSH 6.2
(enc) aes256-gcm@openssh.com                -- [info] available since OpenSSH 6.2

# message authentication code algorithms
(mac) umac-64-etm@openssh.com               -- [warn] using small 64-bit tag size
                                            `- [info] available since OpenSSH 6.2
(mac) umac-128-etm@openssh.com              -- [info] available since OpenSSH 6.2
(mac) hmac-sha2-256-etm@openssh.com         -- [info] available since OpenSSH 6.2
(mac) hmac-sha2-512-etm@openssh.com         -- [info] available since OpenSSH 6.2
(mac) hmac-sha1-etm@openssh.com             -- [fail] using broken SHA-1 hash algorithm
                                            `- [info] available since OpenSSH 6.2
(mac) umac-64@openssh.com                   -- [warn] using encrypt-and-MAC mode
                                            `- [warn] using small 64-bit tag size
                                            `- [info] available since OpenSSH 4.7
(mac) umac-128@openssh.com                  -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 6.2
(mac) hmac-sha2-256                         -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
(mac) hmac-sha2-512                         -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
(mac) hmac-sha1                             -- [fail] using broken SHA-1 hash algorithm
                                            `- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 2.1.0, Dropbear SSH 0.28

# fingerprints
(fin) ssh-ed25519: SHA256:vZuHE5Qnl676zUm1OzrrHcuzCCAS57yI8VgojVVYRFc
(fin) ssh-rsa: SHA256:hUh6yD//Vdyrz9lCdy92jOeAMR1G11apEoo3GbbV/Co

# algorithm recommendations (for OpenSSH 8.9)
(rec) -ecdh-sha2-nistp256                   -- kex algorithm to remove 
(rec) -ecdh-sha2-nistp384                   -- kex algorithm to remove 
(rec) -ecdh-sha2-nistp521                   -- kex algorithm to remove 
(rec) -ecdsa-sha2-nistp256                  -- key algorithm to remove 
(rec) -hmac-sha1                            -- mac algorithm to remove 
(rec) -hmac-sha1-etm@openssh.com            -- mac algorithm to remove 
(rec) -chacha20-poly1305@openssh.com        -- enc algorithm to remove 
(rec) -diffie-hellman-group14-sha256        -- kex algorithm to remove 
(rec) -hmac-sha2-256                        -- mac algorithm to remove 
(rec) -hmac-sha2-512                        -- mac algorithm to remove 
(rec) -umac-128@openssh.com                 -- mac algorithm to remove 
(rec) -umac-64-etm@openssh.com              -- mac algorithm to remove 
(rec) -umac-64@openssh.com                  -- mac algorithm to remove 

# additional info
(nfo) For hardening guides on common OSes, please see: <https://www.ssh-audit.com/hardening_guides.html>
(nfo) Potentially insufficient connection throttling detected, resulting in possible vulnerability to the DHEat DoS attack (CVE-2002-20001).  38 connections were created in 0.436 seconds, or 87.2 conns/sec; server must respond with a rate less than 20.0 conns/sec per IPv4/IPv6 source address to be considered safe.  For rate-throttling options, please see <https://www.ssh-audit.com/hardening_guides.html>.  Be aware that using 'PerSourceMaxStartups 1' properly protects the server from this attack, but will cause this test to yield a false positive.  Suppress this test and message with the --skip-rate-test option.    




# SCION Docker

Still no live restore enabled
https://docs.docker.com/config/containers/live-restore/
-> alredy proposed by Maurer


## Image
  - distroless built: https://github.com/GoogleContainerTools/distroless
  - use debian 11 base (contains glibc, libssl, openssl)
  - OpenSSL / LibSSL
    - openssl binary + library are outdated + vulnerable (CVE-2022-1292 -> command injection possible) (not being used by scion-all binary)
    - version is end of life (no security updates)
  - https://www.form3.tech/blog/engineering/exploiting-distroless-images

## SCION-ALL binary
- file scion-all
  scion-all: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.9.0, Go BuildID=redacted, stripped

- ldd scion-all (which libs are loaded  )
  linux-vdso.so.1 (0x00007ffeff3cb000)
  libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f05e80f0000)
  libresolv.so.2 => /lib/x86_64-linux-gnu/libresolv.so.2 (0x00007f05e80df000)
  libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f05e80da000)
  libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f05e80d5000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f05e501b000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f05e81ec000)

=> CGO_ENABLED=1

## Appliance binary
- file appliance
  appliance: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.9.0, Go BuildID=redacted, stripped

- ldd appliance
  linux-vdso.so.1 (0x00007ffe477d9000)
  libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f7e1731e000)
  libresolv.so.2 => /lib/x86_64-linux-gnu/libresolv.so.2 (0x00007f7e1cd6e000)
  libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f7e1cd69000)
  libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f7e1cd64000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7e17139000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f7e1cd9a000)


## VPP binary
- file vpp
  vpp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=de14d3d8f7ff3e5b3c097d42023f944c5012a88c, for GNU/Linux 3.2.0, with debug_info, not stripped

- ldd vpp
  linux-vdso.so.1 (0x00007fff631cc000)
  libvlibmemory.so.23.10.0 => not found
  libvnet.so.23.10.0 => not found
  libvlibapi.so.23.10.0 => not found
  libvlib.so.23.10.0 => not found
  libsvm.so.23.10.0 => not found
  libvppinfra.so.23.10.0 => not found
  libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f35577ca000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f35575e5000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f35578e4000)



# Perrig (Meeting 25.06.2024):
- MAC secret value should change every day (control service should to it?) -> write in report + anapaya