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
