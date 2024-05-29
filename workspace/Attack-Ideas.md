# Ideas

- remove master keys from file system (MAC algo needs it, but not checking if it's there / if its even defined)
- path lookup
  - check MAC there
  - can you get hidden paths
  - check combination of segments
    - Hop field index: use index of other segment?
- PCB (chapter 4.1)
  - what if Timestamp in InfoField is wrong or in the future

- SCMP
  - error message MUST not exceed 1232 bytes (https://docs.scion.org/en/latest/protocols/scmp.html#processing-rules)
  - router has to reverse path (expensive?)

Computational DoS:
- fetch keys from control service


Dataplane:
- See format: https://datatracker.ietf.org/doc/draft-dekater-scion-dataplane/
- Path type, change to experimental path types (e.g. EPIC/Colibri) -> probably not supported by Anapaya
- Current Infofield (has to be between 0-2 -> representing up/core/down segment) -> set it to 3
- Mix wrong info/hop fields into final path -> detected by router checking MAC
- set Construction direction flag wrongly
- On path attacker:
  - modify path to destination with valid path segments (revert back to original path on reply)

Docker:
- flaw in docker -> get root access

Compliance Results:
- No SYN cookies -> SYN flood or slowloris?
  - Open TCP ports: 22, 80, 443, 30252 (CS), 42001 (telemetry)
