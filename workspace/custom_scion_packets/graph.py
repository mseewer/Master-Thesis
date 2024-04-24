import networkx as nx
import matplotlib.pyplot as plt
import json

def add_hop_sequence(G, hop_sequence):
    hops = hop_sequence.split()
    edges = []
    for hop in hops:
        parts = hop.split("#")
        as_name = parts[0]
        interfaces = parts[1].split(",")
        ingress_interface = interfaces[0]
        egress_interface = interfaces[1]
        edges.append((as_name, ingress_interface, egress_interface))
        G.add_node(as_name)
        # G.add_edge(ingress_interface, egress_interface, label=as_name)
    prev = edges[0]
    for edge in edges[1:]:
        G.add_edge(prev[0], edge[0], label=f"{prev[2]}->{edge[1]}")
        prev = edge
    return G

def draw_hop_sequence_graph(G):
    pos = nx.circular_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_weight="bold")
    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.show()

all_seq = []

with open("output/paths.json", "r") as f:
    paths_dict = json.load(f)
all_paths = paths_dict["paths"]
for path in all_paths:
    all_seq.append(path["sequence"])

# all_seq = [
#     "64-2:0:2b#0,1 64-559#24,25 64-12350#3,7 64-3303#22,21 64-2:0:2c#1,0"
# ]

G = nx.DiGraph()
for hop_sequence in all_seq:
    G = add_hop_sequence(G, hop_sequence)
draw_hop_sequence_graph(G)