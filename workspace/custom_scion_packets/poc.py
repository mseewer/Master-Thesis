import pprint
import sys
sys.path.append("./scapy-scion-int")
from scapy_scion.utils import capture_path
# import scapy
# from scapy import bind_layers, UDP
from scapy.all import bind_layers, sniff, sr1, conf, L3RawSocket, IP, Ether, sr, srp, srp1
from scapy_scion.layers.scion import SCION, UDP
from scapy_scion.layers.scmp import SCMP, EchoRequest
from scapy_scion.utils import capture_path
import subprocess
import json
from typing import List


br_port = 30042
br_addr = "192.168.111.1"
br_iface = "eth1" # interface to borderrouter

def get_all_paths(scion_cmd: str, dst_IA: str, extra_args: List[str] = [], capture_output: bool = True, max_paths: int = 1):
    args = {}
    if capture_output:
        args = {'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
    paths_process = subprocess.Popen([scion_cmd, "showpaths", dst_IA, "--maxpaths", f"{max_paths}", "--format", "json"] + extra_args, **args)
    output, _ = paths_process.communicate()
    print(output, type(output))
    
    paths = json.loads(output)
    return paths

def main():
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    pkts = sniff(iface=br_iface,
        filter=f"host {br_addr} and port {br_port}",
        lfilter=lambda pkt: pkt.haslayer(SCMP) and pkt[SCMP].Type==128,
        count=1)

    p = pkts[0]
    print(p)
    p.show()
    p = pkts[0][IP]
    p[SCION].remove_payload()
    del p[IP].len
    del p[IP].chksum
    del p[UDP].len
    del p[UDP].chksum
    del p[SCION].NextHdr
    del p[SCION].HdrLen
    del p[SCION].PayloadLen

    print("--------------------")

    req = p/SCMP(Message=EchoRequest(Identifier=0xabcd, Data=b"Hello!"))
    req[SCION].DstHostAddr = "192.168.110.1"
    # conf.L3socket = L3RawSocket
    resp = sr1(req, iface=br_iface, timeout=1)
    resp.show()

def test():
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    myIP = IP()
    myIP.src = "192.168.111.25"
    myIP.dst = "192.168.110.1"
    myIP.flags = "DF"

    myUDP = UDP()
    myUDP.sport = 30041
    myUDP.dport = br_port
    
    dstISD = 64
    dstAS = "2:0:2c"
    dst_IA = f"{dstISD}-{dstAS}"
    dstAddr = "192.168.110.1"
    mySCION = SCION(DstISD=64, SrcISD=64, DstAS=dstAS, SrcAS="2:0:2b")
    mySCION.PathType = 1
    mySCION.DstHostAddr = dstAddr
    mySCION.SrcHostAddr = "192.168.111.25"
    
    # path = capture_path(scion="scion", src_br=f"{br_addr}:{br_port}", sciond="127.0.0.1:30255", dest=f"{dstISD}-{dstAS},{dstAddr}", timeout=3)
    
    paths = get_all_paths("scion", dst_IA)
    with open("paths.json", "w") as f:
        json.dump(paths, f)
    
    
    mySCMP = SCMP(Message=EchoRequest(Identifier=0xabcd, Data=b"Hello!"))
    

    p = myIP/myUDP/mySCION/mySCMP
    
    del p[IP].len
    del p[IP].chksum
    del p[UDP].len
    del p[UDP].chksum
    del p[SCION].NextHdr
    del p[SCION].HdrLen
    del p[SCION].PayloadLen
    p.show2()

    resp = sr1(p, iface=br_iface, timeout=1)
    resp.show()
    # for r in resp:
    #     r.show()
    #     print("----")


if __name__ == "__main__":
    # main()
    test()




# ###[ IP ]###
#   version   = 4
#   ihl       = 5
#   tos       = 0x0
#   len       = 202
#   id        = 0
#   flags     = DF
#   frag      = 0
#   ttl       = 64
#   proto     = udp
#   chksum    = 0xdab7
#   src       = 192.168.111.1
#   dst       = 192.168.111.25
#   \options   \
# ###[ UDP ]###
#      sport     = 30042
#      dport     = 30041
#      len       = 182
#      chksum    = 0x23f1
# ###[ SCION ]###
#         Version   = 0
#         QoS       = 0x0
#         FlowID    = 0x1
#         NextHdr   = SCMP
#         HdrLen    = 160 bytes
#         PayloadLen= 14
#         PathType  = SCION
#         DT        = IP
#         DL        = 4 bytes
#         ST        = IP
#         SL        = 4 bytes
#         RSV       = 0
#         DstISD    = 64
#         DstAS     = 2:0:2b
#         SrcISD    = 64
#         SrcAS     = 2:0:2c
#         DstHostAddr= 192.168.111.25
#         SrcHostAddr= 192.168.110.1
#         \Path      \
#          |###[ SCION Path ]###
#          |  CurrINF   = 2
#          |  CurrHF    = 7
#          |  RSV       = 0
#          |  Seg0Len   = 2
#          |  Seg1Len   = 4
#          |  Seg2Len   = 2
#          |  \InfoFields\
#          |   |###[ Info Field ]###
#          |   |  Flags     = 
#          |   |  RSV       = 0
#          |   |  SegID     = 0x3131
#          |   |  Timestamp = 2024-04-11 10:52:36
#          |   |###[ Info Field ]###
#          |   |  Flags     = C
#          |   |  RSV       = 0
#          |   |  SegID     = 0x947d
#          |   |  Timestamp = 2024-04-11 10:57:01
#          |   |###[ Info Field ]###
#          |   |  Flags     = C
#          |   |  RSV       = 0
#          |   |  SegID     = 0x4da2
#          |   |  Timestamp = 2024-04-11 10:52:51
#          |  \HopFields \
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 1
#          |   |  ConsEgress= 0
#          |   |  MAC       = 0x6be12b5e24f9
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 0
#          |   |  ConsEgress= 21
#          |   |  MAC       = 0x1a6b725fbdd8
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 0
#          |   |  ConsEgress= 4
#          |   |  MAC       = 0x464a6e8212c1
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 18
#          |   |  ConsEgress= 11
#          |   |  MAC       = 0x8c2d31980974
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 3
#          |   |  ConsEgress= 9
#          |   |  MAC       = 0x558682cb4d5
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 15
#          |   |  ConsEgress= 0
#          |   |  MAC       = 0x887987a6d3bb
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 0
#          |   |  ConsEgress= 24
#          |   |  MAC       = 0x8a561c8056be
#          |   |###[ Hop field ]###
#          |   |  Flags     = 
#          |   |  ExpTime   = Relative: 21600.0 seconds
#          |   |  ConsIngress= 1
#          |   |  ConsEgress= 0
#          |   |  MAC       = 0x417729eadfae
# ###[ SCMP ]###
#            Type      = Echo Reply
#            Code      = 0
#            Checksum  = 0x4f1f
#            \Message   \
#             |###[ Echo Reply ]###
#             |  Identifier= 43981
#             |  SequenceNumber= 0
#             |  Data      = 48656c6c6f21