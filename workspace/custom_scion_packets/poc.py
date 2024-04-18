import sys
sys.path.append("./scapy-scion-int")
from typing import List, Optional, Tuple, Union
import signal
import json
import subprocess
from scapy_scion.layers.scmp import SCMP, EchoRequest
from scapy_scion.layers.scion import SCION, UDP, SCIONPath
from scapy.all import bind_layers, sniff, sr1, conf, L3RawSocket, IP, Ether, sr, srp, srp1
from scapy_scion.utils import capture_path
import pathlib
import pprint
# import scapy
# from scapy import bind_layers, UDP

br_port = 30042
br_addr = "192.168.111.1"
br_iface = "eth1"  # interface to borderrouter


def capture_path(scion: str, src_br: str, sciond: str, dest: str, timeout: Optional[int] = 1,
                 extra_args: List[str] = [], capture_output: bool = False, interface: str = 'lo') -> Union[SCION, Tuple[SCION, str]]:
    """Ping an AS and capture to echo request to extract the path from it.
    :param scion: "scion" command to use for the ping.
    :param src_br: Internal interface of a border router in the source AS.
                   Example: "127.0.0.33:31010"
    :param sciond: Address of sciond in the source AS.
                   Example: "127.0.0.35:30255"
    :param dest: Destination host in the format expected by "scion ping".
                 Example: "3-ff00:0:7,127.0.0.1"
    :param timeout: How long to wait before giving up if no packet is captured, e.g., because the
                    ping failed. The value is in seconds. None disables the timeout.
    :param extra_args: Additional command line arguments passed to 'scion ping'.
    :param capture_output: Capture the output of the 'scion ping' command and return it. If False,
                           the command's output will be written to stdout and stderr as usual.
    :returns: Captured SCION header with payload removed. If capture_output was True, a pair of the
              captures SCION header and the output of the ping command.
    """
    # Capture an echo request
    ping = None

    def ping_cb():
        nonlocal ping
        args = {}
        if capture_output:
            args = {'stdout': subprocess.PIPE,
                    'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
        ping = subprocess.Popen(
            [scion, "ping", "--sciond", sciond, dest] + extra_args, **args)

    br = src_br.split(":")
    cap = sniff(iface=interface, count=1, timeout=timeout,
                filter=f"dst {br[0]} and port {br[1]}",
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


def get_all_paths(scion_cmd: str, dst_IA: str, extra_args: List[str] = [], capture_output: bool = True, max_paths: int = 1000):
    args = {}
    if capture_output:
        args = {'stdout': subprocess.PIPE,
                'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
    paths_process = subprocess.Popen(
        [scion_cmd, "showpaths", dst_IA, "--maxpaths", f"{max_paths}", "--format", "json"] + extra_args, **args)
    output, _ = paths_process.communicate()
    paths = json.loads(output)
    return paths


def test():
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    pkts = sniff(iface=br_iface,
                 filter=f"host {br_addr} and port {br_port}",
                 lfilter=lambda pkt: pkt.haslayer(
                     SCMP) and pkt[SCMP].Type == 128,
                 count=1)

    p = pkts[0]
    print(p)
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
    req.show()
    req.show2()
    print("--------------------")
    # conf.L3socket = L3RawSocket
    resp = sr1(req, iface=br_iface, timeout=1)
    resp.show()


def choose_path(dst_IA: str) -> Union[SCION, Tuple[SCION, str]]:
    dstISD, dstAS = dst_IA.split("-")
    paths = get_all_paths("scion", dst_IA)
    pathlib.Path("output").mkdir(parents=True, exist_ok=True)
    with open("output/paths.json", "w") as f:
        json.dump(paths, f, indent=4)

    chosen_path = paths["paths"][-1]
    pprint.pprint(chosen_path)
    sequence = chosen_path["sequence"]

    dstAddr = "127.0.0.1" # anything, not important as we just capture the created SCION packet with the path
    path = capture_path(scion="scion", src_br=f"{br_addr}:{br_port}",
                        sciond="127.0.0.1:30255", dest=f"{dstISD}-{dstAS},{dstAddr}",  extra_args=["--sequence", f"{sequence}"], interface=br_iface)
    return path

def main():
    dstISD = 64
    dstAS = "2:0:2c"
    dst_IA = f"{dstISD}-{dstAS}"
    
    SCION_path = choose_path(dst_IA)
    
    dstAddr = "192.168.110.1"
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    myIP = IP()
    myIP.src = "192.168.111.25"
    myIP.dst = br_addr # address of border router (NOT! actual destination address)
    myIP.flags = "DF" # Don't fragment (less important?)

    myUDP = UDP()
    myUDP.sport = 30041
    myUDP.dport = br_port


    mySCION = SCION_path
    mySCION.DstISD = dstISD
    mySCION.DstAS = dstAS
    mySCION.SrcISD = 64
    mySCION.SrcAS = "2:0:2b"
    mySCION.PathType = 1
    mySCION.DstHostAddr = dstAddr
    mySCION.SrcHostAddr = "192.168.111.25"

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
    p.pdfdump("output/sent_packet.pdf")
    
    resp = sr1(p, iface=br_iface, timeout=1)
    resp.show()
    resp.pdfdump("output/received_packet.pdf")


if __name__ == "__main__":
    # test()
    main()