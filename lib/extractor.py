import numpy
import pandas as pd
from ..config.mapping_data import *

""" This file contain all function releted to the log (export) file (write and read). There are also function that can be used for a comparison tool. """

# Internal functions
def _mapping_field():
    fields = []
    fields += [k for k in mapping_client.keys() if mapping_client[k] != 0] 
    fields += [k for k in mapping_server.keys() if mapping_server[k] != 0]
    fields += [k for k in mapping_dual.keys() if mapping_dual[k] != 0]
    fields += [k for k in extend_mappig_client.keys() if extend_mappig_client[k] != 0]
    fields += [k for k in extend_mappig_server.keys() if extend_mappig_server[k] != 0]
    fields += [k for k in extend_mappig_dual.keys() if extend_mappig_dual[k] != 0]
    return fields

def _clean_field(field):
    if "#" in field:
        field = field.split("#")[2]
    if ":" in field:
        field = field.split(":")[0]
    if "\n" in field:
        field = field.split("\n")[0]
    return field

def _get_logged_fields(fields):
    fields_set = []
    for f in fields:
        if f in mapping_client.keys() and mapping_client[f] != 0 and not ("c_" + mapping_client[f] in fields_set):
            fields_set.append("c_" + mapping_client[f])
        if f in mapping_server.keys() and mapping_server[f] != 0 and not ("s_" + mapping_server[f] in fields_set):
            fields_set.append("s_" + mapping_server[f])
        if f in mapping_dual.keys() and mapping_dual[f] != 0 and not (mapping_dual[f] in fields_set):
            fields_set.append(mapping_dual[f])
        if f in extend_mappig_client.keys() and extend_mappig_client[f] != 0 and not ("c_" + extend_mappig_client[f] in fields_set):
            fields_set.append("c_" + extend_mappig_client[f])
        if f in extend_mappig_server.keys() and extend_mappig_server[f] != 0 and not ("s_" + extend_mappig_server[f] in fields_set):
            fields_set.append("s_" + extend_mappig_server[f])
        if f in extend_mappig_dual.keys() and extend_mappig_dual[f] != 0 and not (extend_mappig_dual[f] in fields_set):
            fields_set.append(extend_mappig_dual[f])
    return fields_set

# Write functions
def write_header(file_name):
    """ Write header of log on file using extended tstat format """
    fields = _mapping_field()
    stream = " ".join(fields) + "\n"
    f = open(file_name, "a") # TODO - change with w
    f.write(stream)
    f.close()

def write_session_log(file_name, session_stats):
    """ Write log of a session on file using extended tstat format. (Live analysis) """
    f = open(file_name, "a")
    stream = " ".join(str(v) for v in session_stats) + "\n"
    f.write(stream)
    f.close()

# Read function
def read_log(file_name):
    """ Extract data from an extened tstat log file  """
    with open(file_name, mode='r') as csv_file:
        fields_line = csv_file.readline().split(" ")
        fields_m = [ _clean_field(f) for f in fields_line ]
        fields = _get_logged_fields(fields_m)

    stats = pd.read_csv(file_name, sep=" ", header=0, names=fields, index_col=False).dropna()
    return stats

# Convert function
def convert_to_list(session):
    """ Converts statistics in extended tstat format output"""
    res = []

    res += [session['client'][mapping_client[k]]
            for k in mapping_client.keys() if mapping_client[k] != 0]
    res += [session['server'][mapping_server[k]]
            for k in mapping_server.keys() if mapping_server[k] != 0]
    res += [session[mapping_dual[k]]
            for k in mapping_dual.keys() if mapping_dual[k] != 0]
    res += [session['client'][extend_mappig_client[k]]
            for k in extend_mappig_client.keys() if extend_mappig_client[k] != 0]
    res += [session['server'][extend_mappig_server[k]] 
            for k in extend_mappig_server.keys() if extend_mappig_server[k] != 0]
    res += [session[extend_mappig_dual[k]]
            for k in extend_mappig_dual.keys() if extend_mappig_dual[k] != 0]
    return res


def export_list(stats, output_file=False):
    log_fields = _mapping_field()
    fields = _get_logged_fields(log_fields)
    stats_pd = pd.DataFrame(stats, columns=fields)

    print(fields)

    if output_file:
        stats_pd.to_csv(output_file, header=log_fields, index=False, sep=" ")
    
    return stats_pd.dropna() #.drop(['c_client_ip', 'c_client_port', 's_server_ip', 's_server_port'], axis=1)

# Comparator Tool
def compair_field(my_session, tstat_session):
    """ Function that compare by field netstatpy and tstat values """
    for field in my_session.keys():
        if field in tstat_session.keys():
            if my_session[field] == tstat_session[field]:
                continue
            else:
                m = float(my_session[field])
                t = float(tstat_session[field])
                if abs(m - t) < 0.0002:
                    continue
                print("{} - tstat: {} --- my: {}".format(field,
                                                         tstat_session[field], my_session[field]))
