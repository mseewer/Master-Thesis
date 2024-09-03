from scapy.all import *
import sys
sys.path.append("./scapy-scion-int")
from scapy_scion.layers.scion import SCION, UDP
from scapy_scion.layers.scmp import SCMP
import numpy as np

pcap_file = "latency_extended_path.pcap"
filtered_pcap = "filtered_latency_extended_path.pcap"

kali_ip = "192.168.111.25"

def filter_pkts():
    pkts = rdpcap(pcap_file)
    filtered = (pkt for pkt in pkts if
                SCION in pkt and
                (pkt[SCION].SrcHostAddr == kali_ip or pkt[SCION].DstHostAddr == kali_ip))
    wrpcap(filtered_pcap, filtered)
    print(f"Filtered packets saved to {filtered_pcap}")
    

def main():
    req_packet = None
    big_pkt_times = []
    small_pkt_times = []
    for packet in PcapReader(filtered_pcap):
        if SCMP in packet:
            srcIP = packet[SCION].SrcHostAddr
            dstIP = packet[SCION].DstHostAddr
            
            if srcIP == kali_ip:
                if req_packet is not None:
                    print("No response received")
                if packet[SCMP].Type != 128:
                    print("Not an echo request")
                req_packet = packet
            if dstIP == kali_ip:
                if req_packet is None:
                    print("No request received")
                else:
                    if packet[SCMP].Type != 129:
                        print("Not an echo reply")
                    processing_time = float(packet.time - req_packet.time)
                    size = len(packet)
                    if size > 500: # 897 vs 225 bytes
                        big_pkt_times.append(processing_time)
                    else:
                        small_pkt_times.append(processing_time)
                    # size:
                    req_packet = None
    print("len big_pkt_times", len(big_pkt_times))
    print("len small_pkt_times", len(small_pkt_times))
    big_pkt_times = np.array(big_pkt_times) * 1000
    small_pkt_times = np.array(small_pkt_times) * 1000
    big_mean = np.mean(big_pkt_times)
    small_mean = np.mean(small_pkt_times)
    big_std = np.std(big_pkt_times)
    small_std = np.std(small_pkt_times)
    print(f"Big packet mean: {big_mean}, std: {big_std}")
    print(f"Small packet mean: {small_mean}, std: {small_std}")
    
    # plot mean and std
    import matplotlib.pyplot as plt
    plt.figure(figsize=(5, 4))
    plt.grid(axis="y")
    plt.bar(["Normal", "Max"], [small_mean, big_mean], yerr=[small_std, big_std], capsize=5, alpha=0.5)
    plt.ylabel("Processing time [ms]")
    # plt.title("Processing times of different path lengths")
    plt.tight_layout()
    plt.savefig("latency.png")


if __name__ == "__main__":
    # filter_pkts()
    main()