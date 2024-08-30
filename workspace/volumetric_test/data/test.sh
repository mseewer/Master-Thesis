

# for i in {1..3}
# do
    echo "Start ping $i at" $(date)
    scion ping 64-2:0:2b,192.168.111.25 --sequence "64-2:0:2c#0,1 64-3303#21,1 64-559#17,24 64-2:0:2b#1,0"

    echo "Start bwtest $i at" $(date)
    scion-bwtestclient -s 64-2:0:2b,[192.168.111.25]:40002 -cs 10,1300,?,1Gbps -sc 1,0,?,0bps --sequence "64-2:0:2c#0,1 64-3303#21,1 64-559#17,24 64-2:0:2b#1,0"

#     sleep 3
# done