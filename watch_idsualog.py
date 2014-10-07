import re
import sys
#import subprocess
from sh import tail
from log_parser import parse_ids_ua
from pymongo import MongoClient


# Config info of ids-ua logger
mongodb_url = "mongodb://localhost:27017" 
logfile = "/data/ids-ua/ids-ua.log"
sys.settrace


mongo_client = MongoClient(mongodb_url)
#command = ['tail', '-F', logfile]
#p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
bulk_records_ids = {}
ids_count = 0
bulk_records_p = {}
p_count = 0
for line in tail("-F", logfile, _iter=True): #iter(p.stdout.readline, ''):
    try: 
        dname_ids, cname_ids, record_ids, dname_p, cname_p, record_p = parse_ids_ua(line)
        if record_ids != {}:
            ids_count += 1
            indexname = dname_ids + ":" + cname_ids
            if indexname not in bulk_records_ids:
                bulk_records_ids[indexname] = [record_ids]
            else:
                bulk_records_ids[indexname].append(record_ids)
        if record_p != {}:
            p_count += 1
            indexname = dname_p + ":" + cname_p
            if indexname not in bulk_records_p:
                bulk_records_p[indexname] = [record_p]
            else:
                bulk_records_p[indexname].append(record_p)
    except KeyboardInterrupt:
        sys.exit()
    except:
        raise
    else:
        if ids_count >= 2000:
            for index in bulk_records_ids:
                dname_ids, cname_ids = index.split(":")
                mongo_client[dname_ids][cname_ids].insert(bulk_records_ids[index])
            ids_count = 0
            bulk_records_ids.clear()
        if p_count >= 2000:
            for index in bulk_records_p:
                dname_p, cname_p = index.split(":")
                mongo_client[dname_p][cname_p].insert(record_p)
            p_count = 0
            bulk_records_p.clear()

