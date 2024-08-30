# from trex_stl_lib.api import *
import sys
sys.path.append("/home/mseewer/scapy-scion-int")
from scapy_scion.layers.scion import SCION, UDP
from scapy_scion.layers.scmp import SCMP, EchoRequest
import json, pathlib, subprocess, signal
from typing import List,  Optional, Tuple, Union
from scapy.all import bind_layers, sniff, send, IP, wrpcap

br_port = 30042
br_addr = "192.168.53.20"
br_iface= "enp24s0"


def get_all_paths(scion_cmd, dst_IA, extra_args= [], capture_output=True, max_paths=1000):
    args = {}
    if capture_output:
        args = {'stdout': subprocess.PIPE,
                'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
    paths_process = subprocess.Popen(
        [scion_cmd, "showpaths", dst_IA, "--maxpaths", str(max_paths), "--format", "json"] + extra_args, **args)
    output, _ = paths_process.communicate()
    paths = json.loads(output)
    return paths


def fetch_paths(dst_IA):
    paths = get_all_paths("/home/mseewer/scion/bin/scion", dst_IA, extra_args=["--refresh"])
    pathlib.Path("output").mkdir(parents=True, exist_ok=True)
    with open("output/paths.json", "w") as f:
        json.dump(paths, f, indent=4)
    # change permissions to allow reading by other users
    subprocess.run(["chmod", "o+rw", "output/paths.json"])
    return paths

ping = None
def capture_path(scion, src_br, sciond, dest, timeout = 1,
                 extra_args= [], capture_output= False, interface= 'lo'):
    # Capture an echo request
    # ping = None

    def ping_cb():
        global ping
        args = {}
        if capture_output:
            args = {'stdout': subprocess.PIPE,
                    'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
        ping = subprocess.Popen(
            [scion, "ping", dest] + extra_args, **args)

    br = src_br.split(":")
    print("br = ", br)
    print("interface = ", interface)
    print()
    
    cap = sniff(iface=interface, count=1, timeout=timeout,
                filter="dst " +br[0]+" and port "+br[1],
                lfilter=lambda pkt: pkt.haslayer(
                    SCMP) and pkt[SCMP].Type == 128,
                started_callback=ping_cb)

    ping.send_signal(signal.SIGINT)

    # Extract SCION header
    p = cap[0][SCION]
    p.remove_payload()
    del p.NextHdr
    del p.HdrLen
    del p.PayloadLen

    if capture_output:
        return (p, ping.stdout.read() if ping.stdout else None)
    else:
        return p

def choose_path(dst_IA, paths, index= None, sequence = None, br_addr= br_addr):

    dstISD, dstAS = dst_IA.split("-")
    if index:
        # Ignore sequence if index is provided
        chosen_path = paths[index]
        sequence = chosen_path["sequence"]
    if not sequence:
        # No index and no sequence provided
        chosen_path = paths[0]
        sequence = chosen_path["sequence"]
    # print("Chosen path = ", sequence)

    dstAddr = "192.168.111.25" # anything, not important as we just capture the created SCION packet with the path
    src_br = str(br_addr) + ":" + str(br_port)
    dest = str(dstISD) + "-" + str(dstAS) + "," + dstAddr
    path, _ = capture_path(scion="/home/mseewer/scion/bin/scion", src_br=src_br,
                        sciond="127.0.0.1:30255", dest=dest,  extra_args=["--sequence", str(sequence)], interface=br_iface, capture_output=True)
    return path

class STLS1(object):

    def create_stream (self):
        dst_IA = "64-2:0:2b"
        dstAddr = "192.168.111.25"
        srcAddr = "129.132.105.30"
        srcAddr = "129.132.55.211"

        paths = fetch_paths(dst_IA)
        # only take paths that have status != "timeout"
        paths = [path for path in paths["paths"] if path["status"] != "timeout"]
        print("paths = ", paths)
        SCION_path1 = choose_path(dst_IA, paths, sequence=None)
        bind_layers(UDP, SCION, dport=br_port)
        bind_layers(UDP, SCION, sport=br_port)
        
        mySCION = SCION_path1
        mySCION.SrcISD = 64
        mySCION.SrcAS = "2:0:9"
        mySCION.PathType = 1
        mySCION.DstHostAddr = dstAddr
        mySCION.SrcHostAddr = srcAddr
        
        payload = b"B"*1300
        
        mySCMP = SCMP(Message=EchoRequest(Identifier=0xabcd, Data=b"A"*13))
        
        p = IP(src=srcAddr,dst=br_addr)/UDP(dport=br_port,sport=30041)/mySCION/payload

        del p[IP].len
        del p[IP].chksum
        del p[UDP].len
        del p[UDP].chksum
        del p[SCION].NextHdr
        del p[SCION].HdrLen
        del p[SCION].PayloadLen
        
        # p.show2()
        # wrpcap("marco.pcap", p)
        # return p
        print("returning packet")
        return p
        
        return STLStream( 
            packet = 
                    STLPktBuilder(
                        pkt = p
                    ),
             mode = STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        return [ self.create_stream() ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()


def main():
    s1 = STLS1()
    packet = s1.create_stream()
    for i in range(10):
        send(packet)
        wrpcap("marco.pcap", packet)
        input("Press Enter to continue...")
    
    
if __name__ == "__main__":
    main()