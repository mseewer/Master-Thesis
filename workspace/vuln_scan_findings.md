# Nessus 10.06.2024 on all devices:


Docker container scion + appliance
  - distroless built: https://github.com/GoogleContainerTools/distroless
  - openssl binary + library are outdated + vulnerable (unknown when its used)
  - version is end of life (no security updates)
  - https://www.form3.tech/blog/engineering/exploiting-distroless-images


- 'less' vulnerable to command injection CVE-2024-32487 (https://www.openwall.com/lists/oss-security/2024/04/12/5) => hard to exploit

- Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30 may allow an unauthenticated user to potentially enable escalation of privilege via network access.
(CVE-2023-25775)

- Terrapin attack (SSH, bypass integriy checksCVE-2023-48795) -> only in Thun
  - nmap --script ssh2-enum-algos -sV -p 22 192.168.110.1
  - can update SSH -> but attack still works if client is vulnerable
  - safe: disable vulnerable cipher suites (disable chacha20-poly and *-etm@openssh.com)

- git submodules/symlinks -> RCE (CVE-2024-32002, CVE-2024-32004) -> only in Thun