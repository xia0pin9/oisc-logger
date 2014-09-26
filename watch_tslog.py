import re
import sys
import subprocess
from log_parser import parse_ts_eid, parse_ts_ua, parse_ts_oldplatform
from pymongo import MongoClient


# Config info for truesight logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/tslog/ts.log"
pattern = "[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username:(.*)"


mongo_client = MongoClient(mongodb_url)
command = ['tail', '-F', logfile]
pattern = re.compile(pattern)
p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
bulk_records_eid = {}
eid_count = 0
bulk_records_ua = {}
ua_count = 0
bulk_records_op = {}
op_count = 0
for line in iter(p.stdout.readline, ''):
    try:
        db_name_eid, coll_name_eid, record_eid = parse_ts_eid(line, pattern)
        db_name_ua, coll_name_ua, record_ua = parse_ts_ua(line, pattern)
        db_name_op, coll_name_op, record_op = parse_ts_oldplatform(line, pattern)
        if record_eid != {}:
            eid_count += 1
            indexname = db_name_eid + ":" + coll_name_eid
            if indexname not in bulk_records_eid:
                bulk_records_eid[indexname] = [record_eid]
            else:
                bulk_records_eid[indexname].append(record_eid)
        if record_ua != {}:
            ua_count += 1
            indexname = db_name_ua + ":" + coll_name_ua
            if indexname not in bulk_records_ua:
                bulk_records_ua[indexname] = [record_ua]
            else:
                bulk_records_ua[indexname].append(record_ua)
        if record_op != {}:
            op_count += 1 
            indexname = db_name_op + ":" + coll_name_op
            if indexname not in bulk_records_op:
                bulk_records_op[indexname] = [record_op]
            else:
                bulk_records_op[indexname].append(record_op) 
    except KeyboardInterrupt:
        sys.exit()
    except:
        raise
    else:
        if eid_count >= 2000:
            for index in bulk_records_eid:
                db_name, coll_name = index.split(":")
                mongo_client[db_name][coll_name].insert(bulk_records_eid[index])
            eid_count = 0
            bulk_records_eid.clear()
        if ua_count >= 2000:
            for index in bulk_records_ua:
                db_name, coll_name = index.split(":")
                mongo_client[db_name][coll_name].insert(bulk_records_ua[index])
            ua_count = 0
            bulk_records_ua.clear()
        if op_count >= 2000:
            for index in bulk_records_op:
                db_name, coll_name = index.split(":") 
                mongo_client[db_name][coll_name].insert(bulk_records_op[index])
            op_count = 0
            bulk_records_op.clear()
