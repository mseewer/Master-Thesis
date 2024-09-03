#!/bin/bash
## nslookup an entire subnet

## It's possible to add more networks separated with space



NETS=(198.18 198.19)  ## edit this line to match the scanned network
IPRange="1 254"
SUBRange="0 255"
for NET in "${NETS[@]}"; do
    for x in $(seq $SUBRange); do
        for n in $(seq $IPRange); do
            ADDR=${NET}.${x}.${n}
            DOM=$(nslookup ${ADDR} | awk -F "=" '{ print $2 }'|sed 's/^[ t]*//' | sed '/^$/d' | sed 's/.$//')
            if [ -n "$DOM" ]; then
                echo "$ADDR, $DOM"
            fi
        done
    done
done
exit 0
