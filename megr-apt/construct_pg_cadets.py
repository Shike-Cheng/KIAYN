import networkx as nx 
import pandas as pd
import numpy as np
from datetime import datetime
import pytz
import time
import os
import json
from networkx.readwrite import json_graph
import resource
import os, psutil
from tqdm import tqdm
from time import mktime
from datetime import datetime
process = psutil.Process(os.getpid())


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


# username = "postgres"
# password = "postgres"
# dataset = "cadets_e3"
# db_url = 'postgresql+psycopg2://' + username + ':' + password + '@localhost/' + dataset

db_url = "postgresql://postgres:postgres@localhost:5432/cadets_e3"

#DARPA timezone
timezone = pytz.timezone("America/Nipigon")

edge_reversed = (
    'EVENT_EXECUTE',
    'EVENT_LSEEK',
    'EVENT_MMAP',
    'EVENT_OPEN',
    'EVENT_ACCEPT',
    'EVENT_READ',
    'EVENT_RECVFROM',
    'EVENT_RECVMSG',
    'EVENT_READ_SOCKET_PARAMS',
    'EVENT_CHECK_FILE_ATTRIBUTES'
)

# query_events = """
# SELECT src_node AS subject,
#        dst_node AS object,
#        event_uuid AS event,
#        operation AS type,
#        timestamp_rec AS timestamp
# FROM public.event_table
# WHERE timestamp_rec BETWEEN %(start_timestamp)s AND %(end_timestamp)s;
# """

query_events = f"""
SELECT 
    CASE 
        WHEN operation IN {edge_reversed} THEN dst_index_id
        ELSE src_index_id
    END AS subject,
    CASE 
        WHEN operation IN {edge_reversed} THEN src_index_id
        ELSE dst_index_id
    END AS object,
    event_uuid AS event,
    operation AS type,
    timestamp_rec AS timestamp
FROM public.event_table
WHERE timestamp_rec BETWEEN %(start_timestamp)s AND %(end_timestamp)s;
"""

query_subjects ="""
SELECT DISTINCT CAST(index_id AS TEXT) AS subject,
       'PROCESS' AS type,
       cmd AS command_line
FROM public.subject_node_table
WHERE index_id IS NOT NULL;
"""

query_files = """
SELECT CAST(index_id AS TEXT) AS object,
       'FILE' AS type,
       STRING_AGG(DISTINCT regexp_replace(path, '^.*/', ''), '=>') AS object_paths
FROM public.file_node_table
GROUP BY index_id;
"""


query_flows = """
SELECT DISTINCT CAST(index_id AS TEXT) AS object,
       'FLOW' AS type,
       dst_addr AS remote_ip,
       src_addr AS local_ip
FROM public.netflow_node_table
WHERE index_id IS NOT NULL;
"""

query_pipes = """
SELECT DISTINCT uuid as object, 'PIPE' as type 
FROM public."UnnamedPipeObject" 
WHERE uuid IS NOT NULL 
"""
query_sinks = """
SELECT DISTINCT uuid as object, 'SINK' as type 
FROM public."SrcSinkObject" 
WHERE uuid IS NOT NULL 
"""

def explore_graph(g):
    print("Number of nodes: ", g.number_of_nodes())
    print("Number of edges: ", g.number_of_edges())
    x  = list(g.nodes.data("type"))
    unique_nodes_types = list(set([y[1] for y in x]))
    print("\nUnique nodes type:",unique_nodes_types)
    for i in unique_nodes_types:
        print(i,": ", len([node_id for node_id, node_type in g.nodes.data("type") if node_type == i]) )
    x  = list(g.edges.data("type"))
    unique_edges_types = list(set([y[2] for y in x]))
    print("\nUnique edges type:",unique_edges_types)
    for i in unique_edges_types:
        print(i,": ", len([node_id for node_id,_, node_type in g.edges.data("type") if node_type == i]) )


def build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end):
    start_time = time.time()
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    print("Constructing:", provenance_graph_name)

    dt_start = datetime.fromtimestamp(provenance_graph_start // 1000000000,tz=pytz.timezone("America/Nipigon"))
    print("The Provenance Graph Start on ",dt_start.strftime('%Y-%m-%d %H:%M:%S'))
    dt_end = datetime.fromtimestamp(provenance_graph_end // 1000000000,tz=pytz.timezone("America/Nipigon"))
    print("The Provenance Graph Ends on ",dt_end.strftime('%Y-%m-%d %H:%M:%S'))
    print("The Provenance Graph duration is:",dt_end-dt_start) 

    #Get Events of the first objects
    df_events = pd.read_sql(query_events,db_url,
                       params={"start_timestamp":provenance_graph_start,"end_timestamp":provenance_graph_end})


    df_events['type'] = [event.split("EVENT_")[1].lower() if event else None for event in df_events["type"]]
    print("Total Number of Events:",len(df_events))
    current_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem

    provenance_graph = nx.from_pandas_edgelist(
        df_events,
        source="subject",
        target="object",
        edge_attr=["event","type","timestamp"],
        create_using=nx.MultiDiGraph()
    )
    
    df_events=None
    print("Number of Nodes:",provenance_graph.number_of_nodes(),"\nNumber of Edges",provenance_graph.number_of_edges())    
    
    print("Set Subjects attributes")
    subjects = pd.read_sql(query_subjects,db_url)

    node_attr = subjects.set_index('subject').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)

    node_attr,subjects = None,None
    current_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
 
    print("Set Objects attributes")
    object_files = pd.read_sql(query_files,db_url)

    node_attr = object_files.set_index('object').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,object_files = None,None


    object_flows = pd.read_sql(query_flows,db_url)
    # for index, row in object_flows.iterrows():
    #     print(row['object'])
    #     break
    node_attr = object_flows.set_index('object').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,object_flows = None,None

    for node_id, node_attrs in list(provenance_graph.nodes.data()):
        node_type = node_attrs["type"]
        if node_type == "FILE" and "object_paths" in node_attrs:
            print(node_id)
            print(node_attrs)

    # for node,node_type in provenance_graph.nodes.data("type"):
    #     print(node_type)
    None_nodes = [node for node,node_type in provenance_graph.nodes.data("type") if node_type == None]
    print("Number of filtered None nodes",len(None_nodes))
    provenance_graph.remove_nodes_from(None_nodes)
    None_nodes = None

    # explore_graph(provenance_graph)
    print("Writing the graph to a file")
    json_provenance_graph = json_graph.node_link_data(provenance_graph)
    file_path = "./provenance_graphs/" + provenance_graph_name + ".json"
    with open(file_path, 'w') as f:
        json.dump(json_provenance_graph, f)
    json_provenance_graph = None
    
    construct_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
    print("\nMemory usage to constract the provenance graph: ", construct_mem / 1024,"MB (based on resource Lib)")
    print("\nMemory usage to constract the provenance graph: ",process.memory_info().rss / (1024 ** 2),"MB (based on psutil Lib)")
    print("---Running Time : %s seconds ---" % (time.time() - start_time))
    print("/n*********************************************/n")
    provenance_graph.clear()
    return 

def datetime_to_ns_time_US(date):
    """
    :param date: str   format: %Y-%m-%d %H:%M:%S   e.g. 2013-10-10 23:40:00
    :return: nano timestamp
    """
    tz = pytz.timezone('US/Eastern')
    timeArray = time.strptime(date, "%Y-%m-%d %H:%M:%S")
    dt = datetime.fromtimestamp(mktime(timeArray))
    timestamp = tz.localize(dt)
    timestamp = timestamp.timestamp()
    timeStamp = timestamp * 1000000000
    return int(timeStamp)

            
def main():
    for day in tqdm(range(2, 14)):
        start_timestamp = datetime_to_ns_time_US('2018-04-' + str(day) + ' 00:00:00')
        end_timestamp = datetime_to_ns_time_US('2018-04-' + str(day + 1) + ' 00:00:00')
        build_graph("cadets_day_" + str(day), start_timestamp, end_timestamp)
    
    
if __name__ == "__main__":
    main()