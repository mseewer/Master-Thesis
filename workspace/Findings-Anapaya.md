# SCION

## MAC
- Good: Same MAC algo in use as open source implementation (AES-CMAC)
- Bad:  MAC secret (forwarding key) is not changed every day

## Source authentication / DRKey
- No DRKey, no SPAO possible
- unauthenticated SCMP error messages can be sent
- off-path attacker can possibly force retransmission on other path (send External interface down SCMP error message)

## Spoofing
- ISD-AS + IP address spoofing possible (no outbound filtering)
- If path lookup is done at destination (plausible: due to path policies) -> reflection attack possible
- Can not force path lookup at destination with about-to-expire paths (when response comes back within 30s)
- Source authentication based on DRKey not a possible solution (no DRKey)

## Path Extension
- Prepend path with additional hop fields is possible
- Can spoof AS which originated connection
- Solution/Detection:
  - Hop Field should be 0 for packet which originated from local AS (does not protect against malicious AS)
  - Source authentication, but there is no DRKey/SPAO

## Modification of Path Header
- Can change path information (on-path attacker) and reroute on different path
- Solution:
  - SCIONs Source authentication, but there is no DRKey
  - End hosts have to implement their own solutions (e.g. path comparison)



# Router

## Web server
- Caddy version 2.6.4: Vulnerable to Rapid Reset Attack
  - Attacker can crash local BR or remote BR when reachable via SIG.
  - Resource (Memory) exhaustion attack, which makes whole router unresponsive within seconds.
  - Solution: Limit resources of Caddy process OR update Caddy to version 2.7.5 or later.
  - Question: Caddy runs on host, what about to run Caddy in Docker container?

## Docker
- Image: Google's Distroless Debian image, version 11.1.
  - Minor: Can update to Debian version 12 (new kernel).
  - Image contains glibc, openssl, libssl (all have critical vulnerabilities).
    SSL is not being used by VPP/SCION services -> can be removed (there exists distroless image without SSL).
- Live Restore: Not enabled -> if the Docker daemon crashes, the SCION services will also be down.
- No limit on system resources set for containers.

## Appliance
- No default authentication to Appliance web interface.
- AS local / SIG user: Can modify whole SCION config

## Ubuntu Compliance
- No password policy set for users (no password complexity, password reuse is not restricted, etc.).
- No Shell timeout configured, which logs out an inactive user after certain time.
- Only CYD? no password prompt for re-authentication -> automatically escalate privileges to root possible
- Shared memory can contain executable binaries
- No separate partitions in use (/home, /var) -> world writable directories (/tmp): can fill up disk
- No login warning banner (Legal: Remove all privacy of users, when monitoring them)
- Cron directories have wrong permissions (world readable): Could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls
- USB access is not restricted
- Password hashing algorithm is SHA512 -> maybe change to memory hard function
- SSH grace period is set to 2 min -> should be 1 min or less
- SSH root login is allowed

## Systemd-Analyze Security
- Scoring of security related settings of systemd services
- A more tight sandboxing can be applied to some services
  - Rootless containers (docker)
  - Appliance services (limit capabilities)
  - ...
- Can disable unused services

```bash
$ systemd-analyze security
UNIT                                  EXPOSURE PREDICATE HAPPY
ModemManager.service                       6.3 MEDIUM    😐
appliance-controller.service               9.6 UNSAFE    😨
appliance-installer.service                9.6 UNSAFE    😨
apport.service                             9.6 UNSAFE    😨
caddy.service                              8.8 EXPOSED   🙁
cloud-init-hotplugd.service                9.6 UNSAFE    😨
containerd.service                         9.6 UNSAFE    😨
cron.service                               9.6 UNSAFE    😨
dbus.service                               9.5 UNSAFE    😨
dm-event.service                           9.5 UNSAFE    😨
dmesg.service                              9.6 UNSAFE    😨
docker.service                             9.6 UNSAFE    😨
emergency.service                          9.5 UNSAFE    😨
getty@tty1.service                         9.6 UNSAFE    😨
irqbalance.service                         6.2 MEDIUM    😐
iscsid.service                             9.5 UNSAFE    😨
lvm2-lvmpolld.service                      9.5 UNSAFE    😨
lxd-agent.service                          9.5 UNSAFE    😨
multipathd.service                         9.5 UNSAFE    😨
networkd-dispatcher.service                9.6 UNSAFE    😨
open-vm-tools.service                      9.5 UNSAFE    😨
packagekit.service                         9.6 UNSAFE    😨
plymouth-start.service                     9.5 UNSAFE    😨
polkit.service                             9.6 UNSAFE    😨
rc-local.service                           9.6 UNSAFE    😨
rescue.service                             9.5 UNSAFE    😨
resolvconf.service                         9.5 UNSAFE    😨
rsyslog.service                            9.6 UNSAFE    😨
serial-getty@ttyS0.service                 9.6 UNSAFE    😨
snap.lxd.daemon.service                    9.6 UNSAFE    😨
snap.lxd.user-daemon.service               9.6 UNSAFE    😨
snapd.aa-prompt-listener.service           9.6 UNSAFE    😨
snapd.service                              9.6 UNSAFE    😨
ssh.service                                9.6 UNSAFE    😨
systemd-ask-password-console.service       9.4 UNSAFE    😨
systemd-ask-password-plymouth.service      9.5 UNSAFE    😨
systemd-ask-password-wall.service          9.4 UNSAFE    😨
systemd-fsckd.service                      9.5 UNSAFE    😨
systemd-initctl.service                    9.4 UNSAFE    😨
systemd-journald.service                   4.3 OK        🙂
systemd-logind.service                     2.8 OK        🙂
systemd-networkd.service                   2.9 OK        🙂
systemd-resolved.service                   2.1 OK        🙂
systemd-rfkill.service                     9.4 UNSAFE    😨
systemd-timesyncd.service                  2.1 OK        🙂
systemd-udevd.service                      6.9 MEDIUM    😐
thermald.service                           9.6 UNSAFE    😨
ubuntu-advantage.service                   9.6 UNSAFE    😨
udisks2.service                            9.6 UNSAFE    😨
upower.service                             2.4 OK        🙂
user@1000.service                          9.4 UNSAFE    😨
uuidd.service                              4.6 OK        🙂
vgauth.service                             9.5 UNSAFE    😨
```

## SSH
- vulnerable / weak ciphers are enabled
- chacha20-poly1305@openssh.com -> Terrapin attack (allows message prefix truncation)
- SHA1 enabled for MACs
- diffie-hellman-group14-sha256: 2048-bit modulus only provides 112-bits of symmetric strength
- not always EtM enforced
- small tag size (64 bit)
- nist p-curves: suspected being backdoored by the NSA
- Recommendations:
  - -ecdh-sha2-nistp256                   -- kex algorithm to remove
  - -ecdh-sha2-nistp384                   -- kex algorithm to remove
  - -ecdh-sha2-nistp521                   -- kex algorithm to remove
  - -ecdsa-sha2-nistp256                  -- key algorithm to remove
  - -hmac-sha1                            -- mac algorithm to remove
  - -hmac-sha1-etm@openssh.com            -- mac algorithm to remove
  - -chacha20-poly1305@openssh.com        -- enc algorithm to remove
  - -diffie-hellman-group14-sha256        -- kex algorithm to remove
  - -hmac-sha2-256                        -- mac algorithm to remove
  - -hmac-sha2-512                        -- mac algorithm to remove
  - -umac-128@openssh.com                 -- mac algorithm to remove
  - -umac-64-etm@openssh.com              -- mac algorithm to remove
  - -umac-64@openssh.com                  -- mac algorithm to remove
- DHEat DoS attack possible:
  - No/insufficient connection throttling -> all CPU resources can be used up by attacker with little resources
  - no/little impact on SCION
  - SSH logins will sometimes not work


## Vulnerabilities
- Most of them need local access to exploit
  - Vulnerable versions of: bash, vim, less, perl, git, tar, Intel Microcode, glibc, libarchive
  - Kernel vulnerabilities (some of them need local privileged attacker, CAP_NET_ADMIN)
- (CVE-2023-25775) Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30 may allow an unauthenticated user to potentially enable escalation of privilege via network access.
- (CVE-2023-45871) An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel before 6.5.3. A buffer size may not be adequate for frames larger than the MTU.
- Various nghttp2 vulnerabilities (not directly in use? -> Caddy has its own implementation)
- Vulnerable version (1.1.1f) of OpenSSL is installed
- libTIFF (CVE-2022-3970): remotely triggerable buffer overflow (but libTIFF not used)
