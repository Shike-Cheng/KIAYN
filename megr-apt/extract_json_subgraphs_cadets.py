import networkx as nx
from networkx.readwrite import json_graph
import json
from statistics import mean
import pandas as pd
import random
from random import randrange
import time
import dgl
import pickle
import glob
import argparse
import os
import io
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
import resource
import copy
import dask
from dask.distributed import Client, LocalCluster
import dask.bag as db
# import stardog
import os, psutil
import gc
import ctypes
import sys
import re
current_dir = os.getcwd()
sys.path.append(current_dir+"/src")
# from dataset_config import get_stardog_cred
# from ..dataset_config import get_stardog_cred
process = psutil.Process(os.getpid())
import multiprocessing
from resource import *

parser = argparse.ArgumentParser()
parser.add_argument('--min-nodes', type=int, help='Minimum number of nodes for subgraphs', default=3)
parser.add_argument('--max-nodes-mult-qg', type=int, help='Maximum number of nodes for subgraphs', default=10)
parser.add_argument('--max-nodes-training', type=int, help='Maximum number of nodes for subgraphs', default=200)
parser.add_argument('--max-edges-mult-qg', type=int, help='Maximum number of edges for subgraphs', default=25)
parser.add_argument('--max-edges-training', type=int, help='Maximum number of edges for subgraphs', default=1000)
parser.add_argument('--min-iocs', type=int, help='Minimum number of Query Graph IOCs to accept subgraph', default=1)
parser.add_argument('--output-prx', type=str, help='output file prefix ', default=None)
parser.add_argument('--parallel', help='Encode Subgraphs in parallel', action="store_true", default=False)
parser.add_argument('--query-graphs-folder', nargs="?", help='Path of Query Graph folder', default="/root/MEGR-APT/dataset/darpa_cadets/query_graphs/")
parser.add_argument('--ioc-file', nargs="?", help='Path of Query Graph IOCs file', default="/root/MEGR-APT/dataset/darpa_cadets/query_graphs_IOCs.json")
parser.add_argument('--dataset', nargs="?", help='Dataset name', default="darpa_cadets")
parser.add_argument('--training', help='Prepare training set', action="store_true", default=False)
parser.add_argument('--n-subgraphs', type=int, help='Number of Subgraph', default=None)
parser.add_argument('--traverse-with-time', help='Consider timestamp while traversing', action="store_false", default=True)
parser.add_argument('--extract-with-one-query', help='Extract with one complex query', action="store_true",default=False)
parser.add_argument("--test-a-qg",type=str,default=None,help="The name of the tested query graph.")
parser.add_argument("--pg-name",type=str,default=None,help="The nae of the tested provenance graph.")
# parser.add_argument('--database-name', type=str, help='Stardog database name', default='tc3-cadets')
# parser.add_argument('--explain-query', help='Explain queries', action="store_true",default=False)
args = parser.parse_args()


def print_memory_cpu_usage(message=None):
    print(message)
    print("Memory usage (ru_maxrss) : ",getrusage(RUSAGE_SELF).ru_maxrss/1024," MB")
    print("Memory usage (psutil) : ", psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2), "MB")
    print('The CPU usage is (per process): ', psutil.Process(os.getpid()).cpu_percent(4))
    load1, load5, load15 = psutil.getloadavg()
    cpu_usage = (load15 / os.cpu_count()) * 100
    print("The CPU usage is : ", cpu_usage)
    print('used virtual memory GB:', psutil.virtual_memory().used / (1024.0 ** 3), " percent",
          psutil.virtual_memory().percent)
def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def checkpoint(data, file_path):
    ensure_dir(file_path)
    torch.save(data, file_path)

def load_checkpoint(file_path):
    with open(file_path, 'rb') as f:
        data = torch.load(f)
    return data

# database_name, connection_details = get_stardog_cred(args.database_name)
# conn = stardog.Connection(database_name, **connection_details)


def explore_graph(g):
    print("Number of nodes: ", g.number_of_nodes())
    print("Number of edges: ", g.number_of_edges())
    x = list(g.nodes.data("type"))
    unique_nodes_types = list(set([y[1] for y in x]))
    print("\nUnique nodes type:", unique_nodes_types)
    for i in unique_nodes_types:
        print(i, ": ", len([node_id for node_id, node_type in g.nodes.data("type") if node_type == i]))
    x = list(g.edges.data("type"))
    unique_edges_types = list(set([y[2] for y in x]))
    print("\nUnique edges type:", unique_edges_types)
    for i in unique_edges_types:
        print(i, ": ", len([node_id for node_id, _, node_type in g.edges.data("type") if node_type == i]))



def label_candidate_nodes(query_graph_name, provenance_graph):
    start_mem = getrusage(RUSAGE_SELF).ru_maxrss
    # conn = stardog.Connection(database_name, **connection_details)
    start_time = time.time()
    with open(args.ioc_file) as f:
        query_graphs_IOCs = json.load(f)
    try:
        ioc_ips = query_graphs_IOCs[query_graph_name]["ip"]
        ioc_files = query_graphs_IOCs[query_graph_name]["file"]
    except:
        print("No IOCs file",query_graphs_IOCs)
    suspicious_nodes = {}

    for ioc in ioc_files:
        pattern = re.compile(rf"(?:.*=>)?{re.escape(ioc)}(?:=>.*)?", re.IGNORECASE)
        matching_nodes = []

        for node_id, attrs in provenance_graph.nodes(data=True):
            object_paths = attrs.get("object_paths", "")
            if object_paths and pattern.match(object_paths):
                matching_nodes.append(node_id)

        suspicious_nodes[ioc] = matching_nodes

    for ioc, nodes in suspicious_nodes.items():
        print(f"IOC {ioc}: matched {len(nodes)} nodes")

    # for ioc in ioc_files:
    #     ioc_pattern = "\"^(.*=>)?" + ioc + "(=>.*)?$\""
    #     csv_results = conn.select(graph_sparql_queries['Query_Suspicious_Files'], content_type='text/csv',bindings={'IOC': ioc_pattern}, timeout=900000)
    #     suspicious_nodes[ioc] = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
    
    for ip in ioc_ips:
        suspicious_nodes[ip] = []

    for node_id, attrs in provenance_graph.nodes(data=True):
        node_type = attrs.get("type", "").lower()
        if node_type != "flow":  # 只匹配 type 为 "flow" 的节点
            continue

        remote_ip = attrs.get("remote_ip", None)
        if remote_ip and remote_ip in ioc_ips:
            suspicious_nodes[remote_ip].append(node_id)

    # 查看结果
    for ip, nodes in suspicious_nodes.items():
        print(f"IOC IP {ip}: matched {len(nodes)} nodes")

    # ioc_ips_string = str('( \"' + "\", \"".join(ioc_ips) + '\" )')
    # graph_sparql_queries['Query_Suspicious_IP'] = graph_sparql_queries['Query_Suspicious_IP'].replace("<IOC_IP_LIST>",ioc_ips_string)
    # csv_results = conn.select(graph_sparql_queries['Query_Suspicious_IP'], content_type='text/csv', timeout=1200000)
    # df_suspicious_ip = pd.read_csv(io.BytesIO(csv_results))
    # for _, row in df_suspicious_ip.iterrows():
    #     suspicious_nodes[row["ip"]].append(row["uuid"])


    # 截止到这里，suspicious_nodes存储的是{ioc:[id1, id2, ...], ioc[]}
    # 计算个数
    count_suspicious_nodes = {}
    for n in suspicious_nodes:
        count_suspicious_nodes[n] = len(suspicious_nodes[n])
    all_suspicious_nodes = set([item for sublist in suspicious_nodes.values() for item in sublist])
    
    print("\nTotal number of matched nodes:", len(all_suspicious_nodes))
    print(count_suspicious_nodes)
    
    # all_suspicious_nodes_string = str('( \"' + "\", \"".join(all_suspicious_nodes) + '\" )')
    # Label_Suspicious_Nodes = graph_sparql_queries['Label_Suspicious_Nodes'].replace("<SUSPICIOUS_LIST>",
    #                                                                                 all_suspicious_nodes_string)
    # conn.update(Label_Suspicious_Nodes)
    # print("labelling Suspicious nodes in: --- %s seconds ---" % (time.time() - start_time))
    # print("Memory usage : ", process.memory_info().rss / (1024 ** 2), "MB")
    # print_memory_cpu_usage("Labelling candidate nodes")
    # conn.close()
    
    if args.training:
        return
    return suspicious_nodes, all_suspicious_nodes

def isint(val):
    try:
        int(val)
        result = True
    except ValueError:
        result = False
    return bool(result)

def isfloat(val):
    try:
        float(val)
        result = True
    except ValueError:
        result = False
    return bool(result) and not isint(val)
def is_number(val):
    return isint(val) or isfloat(val)
def parse_profiled_query(explain_query):
    lines = explain_query.split('\n')
    query_IO_time = [float(number) for number in lines[1].split() if is_number(number)]
    if len(query_IO_time) == 2:
        query_IO = query_IO_time[1]
    else:
        print("Unable to parse", lines[1])
        query_IO = None
    query_memory = lines[2].split()[-1]
    if (query_memory[-1].upper() == 'M') and is_number(query_memory[:-1]):
        query_memory_M = float(query_memory[:-1])
    elif (query_memory[-2:] == 'M,') and is_number(query_memory[:-2]):
        query_memory_M = float(query_memory[:-2])
    elif (query_memory[-1].upper() == 'K') and is_number(query_memory[:-1]):
        query_memory_M = float(query_memory[:-1]) / 1000
    elif (query_memory[-1].upper() == 'B') and is_number(query_memory[:-1]):
        query_memory_M = float(query_memory[:-1]) / 1000000
    elif (query_memory[-1].upper() == 'G') and is_number(query_memory[:-1]):
        query_memory_M = float(query_memory[:-1]) * 1000
    else:
        print("Unable to parse", lines[2])
        query_memory_M = None
    return query_memory_M, query_IO


def Traverse_json_sus(provenance_graph, seed_node, sus_nodes, traverse_with_time=True):

    traverse_time = time.time()
    edges_list = []
    visited = set([seed_node])
    frontier = [(seed_node, 0)]

    print(f"Seed node: {seed_node}")

    while frontier and len(edges_list) < max_edges:
        current, depth = frontier.pop()
        if depth >= n_hops:
            continue

        neighbors = list(provenance_graph.successors(current)) + list(provenance_graph.predecessors(current))
        random.shuffle(neighbors)

        for nbr in neighbors:
            edge_data_all = provenance_graph.get_edge_data(current, nbr) or provenance_graph.get_edge_data(nbr, current)
            if not edge_data_all:
                continue

            nbr_type = provenance_graph.nodes[nbr].get("type", "").lower()
            if nbr in sus_nodes or nbr_type == "process":
                for key, edge_data in edge_data_all.items():
                    if current in provenance_graph.successors(nbr):
                        subj, obj = nbr, current
                    else:  # current -> nbr
                        subj, obj = current, nbr

                    if traverse_with_time:
                        edges_list.append({
                            "subject_uuid": subj,
                            "object_uuid": obj,
                            "type": edge_data.get("type"),
                            "timestamp": edge_data.get("timestamp", 0)
                        })
                    else:
                        edges_list.append({
                            "subject_uuid": subj,
                            "object_uuid": obj,
                            "type": edge_data.get("type")
                        })

                if nbr not in visited:
                    visited.add(nbr)
                    frontier.append((nbr, depth + 1))

            if len(edges_list) >= max_edges:
                break

    if not edges_list:
        return None, None, None, None

    subgraphTriples = pd.DataFrame(edges_list).drop_duplicates()
    if subgraphTriples.empty:
        return None, None, None, None

    if traverse_with_time:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type", "timestamp"],
            create_using=nx.MultiDiGraph()
        )
    else:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type"],
            create_using=nx.MultiDiGraph()
        )

    for node in subgraph.nodes():
        if node in provenance_graph.nodes:
            subgraph.nodes[node].update(provenance_graph.nodes[node])

    if subgraph.number_of_nodes() < 2 or subgraph.number_of_nodes() > max_nodes:
        print(f"Subgraph not within range {subgraph.number_of_nodes()} nodes")
        print("Traversed in ", time.time() - traverse_time, "seconds")
        return None, None, None, None
    if subgraph.number_of_edges() > max_edges:
        print(f"Subgraph not within range {subgraph.number_of_edges()} edges")
        return None, None, None, None

    print(f"Extracted a subgraph with {subgraph.number_of_nodes()} nodes, "
          f"{subgraph.number_of_edges()} edges")
    print("Traversed in ", time.time() - traverse_time, "seconds")

    return seed_node, subgraph, None, None


def Traverse_json_ben(provenance_graph, seed_node, traverse_with_time=True):

    traverse_time = time.time()
    edges_list = []
    visited = set([seed_node])
    frontier = [(seed_node, 0)]

    print(f"Seed node: {seed_node}")

    while frontier and len(edges_list) < max_edges:
        current, depth = frontier.pop()
        if depth >= n_hops:
            continue

        neighbors = list(provenance_graph.successors(current)) + list(provenance_graph.predecessors(current))
        random.shuffle(neighbors)

        for nbr in neighbors:
            edge_data_all = provenance_graph.get_edge_data(current, nbr) or provenance_graph.get_edge_data(nbr, current)
            if not edge_data_all:
                continue


            nbr_type = provenance_graph.nodes[nbr].get("type", "").lower()
            if nbr_type == "process":
                for key, edge_data in edge_data_all.items():
                    if current in provenance_graph.successors(nbr):
                        subj, obj = nbr, current
                    else:
                        subj, obj = current, nbr

                    if traverse_with_time:
                        edges_list.append({
                            "subject_uuid": subj,
                            "object_uuid": obj,
                            "type": edge_data.get("type"),
                            "timestamp": edge_data.get("timestamp", 0)
                        })
                    else:
                        edges_list.append({
                            "subject_uuid": subj,
                            "object_uuid": obj,
                            "type": edge_data.get("type")
                        })

                if nbr not in visited:
                    visited.add(nbr)
                    frontier.append((nbr, depth + 1))

            if len(edges_list) >= max_edges:
                break

    if not edges_list:
        return None, None, None, None


    subgraphTriples = pd.DataFrame(edges_list).drop_duplicates()
    if subgraphTriples.empty:
        return None, None, None, None


    if traverse_with_time:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type", "timestamp"],
            create_using=nx.MultiDiGraph()
        )
    else:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type"],
            create_using=nx.MultiDiGraph()
        )


    for node in subgraph.nodes():
        if node in provenance_graph.nodes:
            subgraph.nodes[node].update(provenance_graph.nodes[node])


    if subgraph.number_of_nodes() < 2 or subgraph.number_of_nodes() > max_nodes:
        print(f"Subgraph not within range {subgraph.number_of_nodes()} nodes")
        print("Traversed in ", time.time() - traverse_time, "seconds")
        return None, None, None, None
    if subgraph.number_of_edges() > max_edges:
        print(f"Subgraph not within range {subgraph.number_of_edges()} edges")
        return None, None, None, None

    print(f"Extracted a subgraph with {subgraph.number_of_nodes()} nodes, "
          f"{subgraph.number_of_edges()} edges")
    print("Traversed in ", time.time() - traverse_time, "seconds")

    return seed_node, subgraph, None, None


def Traverse_json(provenance_graph, seed_node, traverse_with_time=True):

    traverse_time = time.time()

    visited = set([seed_node])
    edges_list = []
    frontier = [seed_node]
    print("seed_node: ", seed_node)

    while frontier and len(edges_list) < max_edges:
        current = frontier.pop()
        print("current: ", current)
        print(current in provenance_graph.nodes())

        successors_neighbors = list(provenance_graph.successors(current)) + list(provenance_graph.predecessors(current))
        predecessors_neighbors = list(provenance_graph.predecessors(current))
        print("neighbors: ", predecessors_neighbors + successors_neighbors)
        random.shuffle(successors_neighbors)
        random.shuffle(predecessors_neighbors)

        print("successors_neighbors: ", successors_neighbors)
        print("predecessors_neighbors: ", predecessors_neighbors)

        # successors: current -> nbr
        for nbr in provenance_graph.successors(current):
            edge_data_all = provenance_graph.get_edge_data(current, nbr)
            for key, edge_data in edge_data_all.items():
                if traverse_with_time:
                    edges_list.append({
                        "subject_uuid": current,
                        "object_uuid": nbr,
                        "type": edge_data.get("type"),
                        "timestamp": edge_data.get("timestamp", 0)
                    })
                else:
                    edges_list.append({
                        "subject_uuid": current,
                        "object_uuid": nbr,
                        "type": edge_data.get("type")
                    })
            visited.add(nbr)
            frontier.append(nbr)

            if len(edges_list) >= max_edges:
                break

        # predecessors: nbr -> current
        for nbr in provenance_graph.predecessors(current):
            edge_data_all = provenance_graph.get_edge_data(nbr, current)
            for key, edge_data in edge_data_all.items():
                if traverse_with_time:
                    edges_list.append({
                        "subject_uuid": nbr,
                        "object_uuid": current,
                        "type": edge_data.get("type"),
                        "timestamp": edge_data.get("timestamp", 0)
                    })
                else:
                    edges_list.append({
                        "subject_uuid": current,
                        "object_uuid": nbr,
                        "type": edge_data.get("type")
                    })
            visited.add(nbr)
            frontier.append(nbr)

            if len(edges_list) >= max_edges:
                break

    if not edges_list:
        return None, None, None, None

    subgraphTriples = pd.DataFrame(edges_list)
    if subgraphTriples.empty:
        return None, None, None, None


    if traverse_with_time:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type","timestamp"],
            create_using=nx.MultiDiGraph()
        )
    else:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type"],
            create_using=nx.MultiDiGraph()
        )


    for node in subgraph.nodes():
        if node in provenance_graph.nodes:
            subgraph.nodes[node].update(provenance_graph.nodes[node])


    if subgraph.number_of_nodes() < min_nodes or subgraph.number_of_nodes() > max_nodes:
        print(f"Subgraph not within range {subgraph.number_of_nodes()} nodes")
        print("Traversed in ", time.time() - traverse_time, "seconds")
        return None, None, None, None

    print(f"Extracted a subgraph with {subgraph.number_of_nodes()} nodes, "
          f"{subgraph.number_of_edges()} edges")
    print("Traversed in ", time.time() - traverse_time, "seconds")

    return seed_node, subgraph, None, None


def extract_suspGraphs_depth(provenance_graph, suspicious_nodes, all_suspicious_nodes):
    global query_memory_M_lst, query_IO_lst
    start_time = time.time()
    start_mem = getrusage(RUSAGE_SELF).ru_maxrss
    suspGraphs = []
    # suspGraphs_iterations = {}
    considered_per_ioc = {}
    represented_nodes_per_ioc = {}
    represented_ioc = set()
    matched_ioc_mask = copy.deepcopy(suspicious_nodes)

    for ioc in matched_ioc_mask:
        considered_per_ioc[ioc] = 0
    for ioc in matched_ioc_mask:
        represented_nodes_per_ioc[ioc] = 0

    sus_nodes = set()
    for v in matched_ioc_mask.values():
        sus_nodes.update(v)

    for ioc, nodes in matched_ioc_mask.items():
        if len(nodes) > 0:
            for node in nodes:
                tmp_suspGraphs = Traverse_json_sus(provenance_graph, node, sus_nodes)
                if tmp_suspGraphs:
                    _, subgraph, query_memory_M, query_IO = tmp_suspGraphs
                    if subgraph:
                        suspGraphs.append(subgraph.copy())

                        considered_per_ioc[ioc] += 1
                        subgraph.clear()

    # clear Suspicious Nodes Labels
    # conn = stardog.Connection(database_name, **connection_details)
    # conn.update(graph_sparql_queries['Delete_Suspicious_Labels'])
    # conn.close()
   # Add ioc attributes
    revert_suspicious_nodes = dict((node, ioc) for ioc, list_nodes in suspicious_nodes.items() for node in list_nodes)
    for subgraph in suspGraphs:
        for node_id, node_attr in list(subgraph.nodes.data()):
            subgraph.nodes[node_id]["candidate"] = False
            if node_id in all_suspicious_nodes:
                subgraph.nodes[node_id]["candidate"] = True
                subgraph.nodes[node_id]["ioc"] = revert_suspicious_nodes[node_id]
                represented_ioc.add(revert_suspicious_nodes[node_id])
                represented_nodes_per_ioc[revert_suspicious_nodes[node_id]] += 1
    suspicious_nodes, all_suspicious_nodes, revert_suspicious_nodes = None, None, None

    print("Number of subgraphs:", len(suspGraphs))
    print("Number of extracted subgraph per IOC:\n", considered_per_ioc)
    print("Total extracted subgraphs represent",len(represented_ioc),"IOCs out of",len(matched_ioc_mask.keys()))
    print("Number of represented nodes per IOC in all extracted subgraphs:\n",represented_nodes_per_ioc)
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",
              round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",
              round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))
    print("Extract suspicious subgraphs in --- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    print_memory_cpu_usage()
    return suspGraphs


def Extract_Random_Benign_Subgraphs(n_subgraphs, sum_suspicious_nodes, provenance_graph):
    start_time = time.time()
    # conn = stardog.Connection(database_name, **connection_details)
    global query_memory_M_lst, query_IO_lst
    benignSubGraphs = []
    
    # if args.parallel:
    #     # Query with DASK
    #     # cores = multiprocessing.cpu_count() - 2
    #     # seed_number = n_subgraphs
    #     while len(benignSubGraphs) < n_subgraphs:
    #         benign_candidates = [
    #             node for node, attrs in provenance_graph.nodes(data=True)
    #             if node not in sum_suspicious_nodes and random.random() < 0.5]
    #         random.shuffle(benign_candidates)

    #         tmp_benignSubGraphs = Traverse_json(provenance_graph, benign_candidates)
    #         tmp_benignSubGraphs = [benignSubGraphs for benignSubGraphs in tmp_benignSubGraphs if benignSubGraphs is not None]
    #         for _, subgraph in tmp_benignSubGraphs:
    #             if subgraph:
    #                 if subgraph.number_of_nodes() >= args.min_nodes and subgraph.number_of_nodes() <= args.max_nodes:
    #                     benignSubGraphs.append(subgraph.copy())
    #                 subgraph.clear()
        
    # else:
        # Query Sequentially

    benign_candidates = [
            node for node, attrs in provenance_graph.nodes(data=True)
            if node not in sum_suspicious_nodes and random.random() < 0.5]
    random.shuffle(benign_candidates)
    print("Number of Random Benign Seed Nodes:", len(benign_nodes))

    for node in benign_nodes:
        tmp_benignSubGraph = Traverse_json_ben(provenance_graph, node)
        if tmp_benignSubGraph:
            _, subgraph, query_memory_M, query_IO = tmp_benignSubGraph
            if subgraph:
                if subgraph.number_of_nodes() >= args.min_nodes and subgraph.number_of_nodes() <= args.max_nodes:
                    benignSubGraphs.append(subgraph.copy())
                subgraph.clear()
            if len(benignSubGraphs) >= n_subgraphs:
                break

    print("Number of benign subgraphs:", len(benignSubGraphs))
    print("Max number of nodes in benign subgraphs:", max([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Min number of nodes in benign subgraphs:", min([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Average number of nodes in benign subgraphs:",
          round(mean([supgraph.number_of_nodes() for supgraph in benignSubGraphs])))
    print("Max number of edges in benign subgraphs:", max([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Min number of edges in benign subgraphs:", min([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Average number of edges in benign subgraphs:",
          round(mean([supgraph.number_of_edges() for supgraph in benignSubGraphs])))
    print("--- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    print_memory_cpu_usage()
    benign_nodes = None
    conn.close()
    return benignSubGraphs



def subgraph_quality_check_per_query(subgraphs, suspicious_nodes, min_iocs):
    covered_attacks = {}
    accepted_subgraphs = []
    for i, g in enumerate(subgraphs):
        covered_ioc = set([nodes[1]["ioc"] for nodes in g.nodes.data() if nodes[1]["candidate"]])
        covered_ioc_per_query = []
        accepted = False
        for ioc in suspicious_nodes:
            if ioc.lower() in covered_ioc:
                covered_ioc_per_query.append(ioc.lower())
        if len(covered_ioc_per_query) >= min_iocs:
            accepted = True
        if accepted:
            accepted_subgraphs.append(g)
    if len(subgraphs) == 0:
        print("No Subgraphs")
    else:
        print("Accepted", len(accepted_subgraphs), " out of ", len(subgraphs))
        print("Acceptance rate is: ", len(accepted_subgraphs) / len(subgraphs))
    if min_iocs == args.min_iocs:
        return accepted_subgraphs
    else:
        return


def encode_for_RGCN(g):
#     print("Encoding a subgraph with",g.number_of_nodes(),g.number_of_edges())
    types = ['PROCESS', 'FILE', 'FLOW','memory']
    mapping = {name: j for j, name in enumerate(g.nodes())}
    g = nx.relabel_nodes(g, mapping)
    x = torch.zeros(g.number_of_nodes(), dtype=torch.long)
    tmp_g = copy.deepcopy(g)
    for node, info in g.nodes(data=True):
        try:
            x[int(node)] = types.index(info['type'].upper())
        except Exception as e:
            print("Undefined node type. The error", e, "The nodes attributes", info)
            g.remove_node(node)
            continue
    g = copy.deepcopy(tmp_g)
    x = F.one_hot(x, num_classes=len(types)).to(torch.float)
    for node in g.nodes():
        g.nodes[node]["label"] = x[node]
    edge_types = ['ACCEPT', 'ADD_OBJECT_ATTRIBUTE', 'BIND', 'CHANGE_PRINCIPAL', 'CLOSE', 'CONNECT', 'CREATE_OBJECT', 'EXECUTE', 'EXIT', 'FCNTL', 'FLOWS_TO', 'FORK', 'LINK', 'LOGIN', 'LSEEK', 'MMAP', 'MODIFY_FILE_ATTRIBUTES', 'MODIFY_PROCESS', 'MPROTECT', 'OPEN', 'OTHER', 'READ', 'RECVFROM', 'RECVMSG', 'RENAME', 'SENDMSG', 'SENDTO', 'SIGNAL', 'TRUNCATE', 'UNLINK', 'WRITE']
    for n1, n2, info in g.edges(data=True):
        for k, info in g.get_edge_data(n1, n2).items():
            try:
                g.edges[n1, n2, k]["edge_label"] = edge_types.index(info['type'].upper())
            except Exception as e:
                print("Undefined edge type. The error", e, "The nodes attributes", info)
    dgl_graph = dgl.from_networkx(g, node_attrs=["label"], edge_attrs=["edge_label"])
    g.clear()
    x = None
    return dgl_graph


def convert_prediction_to_torch_data(prediction_graphs_dgl, g_name):
    prediction_data_list = []
    for i, g in enumerate(prediction_graphs_dgl):
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, g_name=g_name, i=str(i))
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        prediction_data_list.append(data)
    return prediction_data_list


def convert_query_to_torch_data(query_graphs_dgl):
    query_data_list = []
    for g_name, g in query_graphs_dgl.items():
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, g_name=g_name)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        query_data_list.append(data)
    return query_data_list


def convert_to_torch_data(training_graphs, testing_graphs):
    training_data_list = []
    testing_data_list = []
    ids = 0
    for g in training_graphs:
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, i=ids)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        training_data_list.append(data)
        ids += 1
    for g in testing_graphs:
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, i=ids)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        testing_data_list.append(data)
        ids += 1
    return training_data_list, testing_data_list


def process_one_graph(pg_name, query_graph_name):
    start_mem = getrusage(RUSAGE_SELF).ru_maxrss
    one_graph_time = time.time()
    global max_edges,max_node
    query_pattern = '\"' + query_graph_name + '\"'

    graph_file = "./provenance_graphs/" + pg_name + ".json"
    provenance_graph = read_json_graph(graph_file)

    # GRAPH_NAME = str(GRAPH_IRI.split("/")[-2])
    print("\nprocessing ", pg_name, "with", query_graph_name)
    print("Extract Subgraphs From", pg_name)

    # graph_sparql_queries = copy.deepcopy(sparql_queries)
    # for sparql_name, sparql_query in graph_sparql_queries.items():
    #     graph_sparql_queries[sparql_name] = sparql_query.replace("<Query>", query_pattern).replace("<GRAPH_NAME>",GRAPH_NAME).replace("<MAX_EDGES>", str(max_edges+10))
    
    suspicious_nodes, all_suspicious_nodes = label_candidate_nodes(query_graph_name, provenance_graph)
    # print(suspicious_nodes)
    # print(all_suspicious_nodes)
    if len(all_suspicious_nodes) == 0:
        print("No suspicious Nodes in ", pg_name, "with", query_graph_name)
        print("\nprocessed", pg_name, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        print_memory_cpu_usage("Extraction")
        return

    suspSubGraphs = extract_suspGraphs_depth(provenance_graph, suspicious_nodes, all_suspicious_nodes)   # 需要改写
    
    
    if len(suspSubGraphs) == 0:
        print("No suspicious subgraphs in", pg_name, "with", query_graph_name)
        print("\nprocessed", pg_name, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        print_memory_cpu_usage("Extraction")
        return
    
    checkpoint(suspSubGraphs,
               ("/root/MEGR-APT/dataset/darpa_cadets/experiments/" + "/predict/nx_suspicious_" + query_graph_name + "_in_" + pg_name + ".pt"))

    for i in range(1, 4):
        print("\nCheck Quality for", i, " IOCs of corresponding query graph")
        if i == args.min_iocs:
            accepted_suspSubGraphs = subgraph_quality_check_per_query(suspSubGraphs, suspicious_nodes, min_iocs=i)
            print("\nAccepted Subgraphs with ", args.min_iocs, " IOCs of corresponding query graph")
            print("Number of accepted subgraph:", len(accepted_suspSubGraphs))
            if accepted_suspSubGraphs == 0:
                print("No accepted subgraphs for", pg_name, "with", query_graph_name)
                return
            checkpoint(accepted_suspSubGraphs, (
                        "/root/MEGR-APT/dataset/darpa_cadets/experiments/" + "/predict/nx_accepted_suspSubGraphs_" + query_graph_name + "_in_" + pg_name + ".pt"))
            suspSubGraphs = accepted_suspSubGraphs
        else:
            subgraph_quality_check_per_query(suspSubGraphs, suspicious_nodes, min_iocs=i)

    if len(suspSubGraphs) == 0:
        print("No suspicious subgraphs in", pg_name, "with", query_graph_name)
        print("\nprocessed", pg_name, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        print_memory_cpu_usage("Extraction")
        return

    print("Encoding prediction subgraphs")
    # if args.parallel:
    #     cores = multiprocessing.cpu_count() - 2
    #     suspSubGraphs_dask = db.from_sequence(suspSubGraphs, npartitions=cores)
    #     prediction_graphs_dgl = suspSubGraphs_dask.map(lambda g: encode_for_RGCN(g)).compute()
    # else:
    #     prediction_graphs_dgl = [encode_for_RGCN(g) for g in suspSubGraphs]
    prediction_graphs_dgl = [encode_for_RGCN(g) for g in suspSubGraphs]
    sum_sus_nodes = set()
    for g in suspSubGraphs:
        for j, name in enumerate(g.nodes()):
            print("sus_node: ", name)
            sum_sus_nodes.add(name)
    print(query_graph_name)
    print(sum_sus_nodes)
    checkpoint(prediction_graphs_dgl,
               ("/root/MEGR-APT/dataset/darpa_cadets/experiments/" + "/predict/dgl_prediction_graphs_" + query_graph_name + "_in_" + pg_name + ".pt"))

    suspSubGraphs, suspicious_nodes, all_suspicious_nodes = None, None, None
    prediction_data_list_host = convert_prediction_to_torch_data(prediction_graphs_dgl, pg_name)
    prediction_graphs_dgl= None
    print("Number of prediction samples from host", pg_name, len(prediction_data_list_host))
    checkpoint(prediction_data_list_host, ("/root/MEGR-APT/dataset/darpa_cadets/experiments/" + "/raw/torch_prediction/" + query_graph_name + "_in_" + pg_name + ".pt"))

    prediction_data_list_host = None
    extraction_mem = getrusage(RUSAGE_SELF).ru_maxrss - start_mem
    print("\nprocessed", pg_name, "with", query_graph_name," in: --- %s seconds ---" % (time.time() - one_graph_time))
    print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
    print("\n Extraction Memory usage: ", extraction_mem / 1024, "MB (based on resource - ru_maxrss)")
    print_memory_cpu_usage("Extraction")
    return


def process_one_graph_training(attack_graph, sparql_queries, query_graphs, n_subgraphs=args.n_subgraphs):
    one_graph_time = time.time()
    current_mem = getrusage(RUSAGE_SELF).ru_maxrss
    global max_edges,max_node
    # GRAPH_NAME = GRAPH_IRI.split("/")[-2]
    # print("\nprocessing ", GRAPH_NAME)
    # graph_sparql_queries = copy.deepcopy(sparql_queries)
    # for sparql_name, sparql_query in graph_sparql_queries.items():
    #     graph_sparql_queries[sparql_name] = sparql_query.replace("<GRAPH_NAME>", GRAPH_NAME).replace("<MAX_EDGES>",str(max_edges + 10))

    graph_file = "./provenance_graphs/" + attack_graph + ".json"
    provenance_graph = read_json_graph(graph_file)
    sum_suspicious_nodes = []
    for query_graph_name in query_graphs:
        # query_pattern = '\"' + query_graph_name + '\"'
        # temp_graph_sparql_queries = copy.deepcopy(graph_sparql_queries)
        # temp_graph_sparql_queries["Label_Suspicious_Nodes"] = temp_graph_sparql_queries[
        #     "Label_Suspicious_Nodes"].replace("<Query>", query_pattern)
        print("Labelling", query_graph_name)

        suspicious_nodes, all_suspicious_nodes = label_candidate_nodes(query_graph_name, provenance_graph)
        for v in suspicious_nodes.values():
            sum_suspicious_nodes += v

    benignSubGraphs = Extract_Random_Benign_Subgraphs(n_subgraphs, sum_suspicious_nodes, provenance_graph)
    
    print("Encoding the random benign subgraphs")
    benignSubGraphs_dgl = [encode_for_RGCN(g) for g in benignSubGraphs]
    benignSubGraphs = None

    # clear suspicious labels
    # conn = stardog.Connection(database_name, **connection_details)
    # conn.update(graph_sparql_queries['Delete_Suspicious_Labels'])
    # conn.close()
    print("\nprocessed", GRAPH_NAME, " in: --- %s seconds ---" % (time.time() - one_graph_time))
    print_memory_cpu_usage()

    return benignSubGraphs_dgl



def trim_memory() -> int:
    libc = ctypes.CDLL("libc.so.6")
    return libc.malloc_trim(0)
def release_memory(client):
    client.restart()
    client.run(gc.collect)
    client.run(trim_memory)

def read_json_graph(json_file):

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return json_graph.node_link_graph(data, multigraph=True, directed=True)

def graph_depth(G):

    def dfs(node, visited):
        visited.add(node)
        max_depth = 0
        for _, nbr in G.out_edges(node):
            if nbr not in visited:
                max_depth = max(max_depth, 1 + dfs(nbr, visited))
        visited.remove(node)
        return max_depth

    depth = 0
    for node in G.nodes():
        depth = max(depth, dfs(node, set()))
    return depth

def main():
    print(args)
    global query_memory_M_lst, query_IO_lst
    query_memory_M_lst, query_IO_lst = [], []
    start_running_time = time.time()
    random.seed(123)
    global max_edges,max_nodes,min_nodes

    max_edges = args.max_edges_training
    max_nodes = args.max_nodes_training
    min_nodes = args.min_nodes

    if args.parallel:
        cores = multiprocessing.cpu_count() - 2
        print("Number of used cores is ", cores)
        cluster = LocalCluster(n_workers=cores)
        client = Client(cluster)
        client.run(gc.collect)
        release_memory(client)
    print("processing query graphs")
    query_graphs = {}
    sum_depth = 0
    for graph_name in glob.glob((args.query_graphs_folder + '*')):
        query_graphs[graph_name.replace(".json", "").split("/")[-1]] = read_json_graph(graph_name)
        sum_depth += graph_depth(read_json_graph(graph_name))
    
    query_graphs_dgl = {g_name: encode_for_RGCN(query_graphs[g_name]) for g_name in query_graphs}
    query_data_list = convert_query_to_torch_data(query_graphs_dgl)
    print("processed", len(query_data_list), "query graphs")
    
    checkpoint(query_data_list,
               ("/root/MEGR-APT/dataset/darpa_cadets/experiments/" + "/raw/torch_query_dataset.pt"))


    # 计算n-hop
    global n_hops
    n_hops = (sum_depth // len(query_graphs)) // 2


    if args.training:
        training_dataset = []
        testing_dataset = []
        attack_graph = "attack_BSD_3_4"
        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(attack_graph, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", attack_graph, " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/tmp_dgl_training_dataset.pt"))

       
        attack_graph = "attack_BSD_1"
        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_1/"

        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", attack_graph, " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/tmp_dgl_training_dataset.pt"))

        attack_graph = "attack_BSD_2"
        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_2/"

        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)
        print("Add ", attack_graph, " to training set.\n\n")

        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        print("Training Samples", len(training_dataset))

        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/dgl_training_dataset.pt"))

        print("Training Samples", len(training_dataset))



        # Don't use any of the testing (prediction) samples in training
        attack_graph = "benign_BSD"
        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/benign_BSD/"
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", attack_graph, " to testing set.\n\n")
        testing_dataset = testing_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None

        print("Testing Samples", len(testing_dataset))
        checkpoint(testing_dataset,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/dgl_testing_dataset.pt"))
        torch_training_set, torch_testing_set = convert_to_torch_data(training_dataset, testing_dataset)
        
        checkpoint(torch_training_set,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/torch_training_dataset.pt"))
        checkpoint(torch_testing_set,
                   ("./dataset/" + args.dataset + "/experiments/" + args.output_prx + "/raw/torch_testing_dataset.pt"))


    elif(args.test_a_qg):
        print("Extracting suspicious subgraphs for",args.test_a_qg,"in PG:",args.pg_name)
        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/" + args.pg_name +"/"
        max_nodes = query_graphs[args.test_a_qg].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[args.test_a_qg].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)

        process_one_graph(args.pg_name, args.test_a_qg)
        print("********************************************")
        print("********************************************")

    else:
        # print("processing Provenance Graphs prediction samples")
        # query_graph_name = "BSD_1"
        # pg_name = "attack_cadets_day_6"
        # # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_1/"
        # max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        # print("Max Nodes",max_nodes)
        # max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        # print("Max Edges",max_edges)
        # process_one_graph(pg_name, query_graph_name)

        # query_graph_name = "BSD_2"
        # pg_name = "cadets_day_6"
        # # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_2/"
        # max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        # print("Max Nodes",max_nodes)
        # max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        # print("Max Edges",max_edges)
        # process_one_graph(pg_name, query_graph_name)

        # query_graph_name = "BSD_4"
        # pg_name = "attack_cadets_day_13"
        # # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        # max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        # print("Max Nodes",max_nodes)
        # max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        # print("Max Edges",max_edges)
        # process_one_graph(pg_name, query_graph_name)

        # query_graph_name = "BSD_4"
        # pg_name = "attack_BSD_3_4"
        # # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        # max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        # print("Max Nodes",max_nodes)
        # max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        # print("Max Edges",max_edges)
        # process_one_graph(pg_name, query_graph_name)

        # GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/benign_BSD/"
        pg_name = "benign_cadets_day_11"
        for query_graph_name in query_graphs:
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes",max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges",max_edges)
            process_one_graph(pg_name, query_graph_name)

    print("---Total Running Time for", args.dataset, "host is: %s seconds ---" % (time.time() - start_running_time))
    io_counters = process.io_counters()
    program_IOPs = (io_counters[0] + io_counters[1]) / (time.time() - start_running_time)
    print("program IOPS (over total time): ", program_IOPs)
    print("I/O counters", io_counters)
    # print("Average IOPS by subgraph extraction queries:", mean(query_time_IOPS_lst))
    # if args.explain_query:
    #     print("Total IOPS (over total time, including extraction query IO ):",
    #           (io_counters[0] + io_counters[1] + sum(query_IO_lst)) / (time.time() - start_running_time))
    #     print("Total extraction query IO", sum(query_IO_lst))
    #     print("Total Disk I/O", io_counters[0] + io_counters[1] + sum(query_IO_lst))
    #     if len(query_memory_M_lst) > 0:
    #         print("Average occupied memory by subgraph extraction queries:", mean(query_memory_M_lst), "M")
    #         print("Max occupied memory by subgraph extraction queries:", max(query_memory_M_lst), "M")
    #         print("Min occupied memory by subgraph extraction queries:", min(query_memory_M_lst), "M")
    #     print("**************************************\nLogs:\nquery_memory_M_lst:", query_memory_M_lst)


if __name__ == "__main__":
    main()
