import re
from log_parser import parse_ts_eid, parse_ts_ua, parse_ts_oldplatform
from log_watcher import LogWatcher
from pymongo import MongoClient


# Config info for truesight logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/tslog"
pattern = "[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username:(.*)"


def callback(filename, lines):
    global pattern
    global mongo_client
    bulk_records_eid = {}
    bulk_records_ua = {}
    bulk_records_op = {}
    for line in lines:
        try:
            db_name_eid, coll_name_eid, record_eid = parse_ts_eid(line, pattern)
            db_name_ua, coll_name_ua, record_ua = parse_ts_ua(line, pattern)
            db_name_op, coll_name_op, record_op = parse_ts_oldplatform(line, pattern)
            if record_eid != {}:
                indexname = db_name_eid + ":" + coll_name_eid
                if indexname not in bulk_records_eid:
                    bulk_records_eid[indexname] = [record_eid]
                else:
                    bulk_records_eid[indexname].append(record_eid)
            if record_ua != {}:
                indexname = db_name_ua + ":" + coll_name_ua
                if indexname not in bulk_records_ua:
                    bulk_records_ua[indexname] = [record_ua]
                else:
                    bulk_records_ua[indexname].append(record_ua)
            if record_op != {}:
                indexname = db_name_op + ":" + coll_name_op
                if indexname not in bulk_records_op:
                    bulk_records_op[indexname] = [record_op]
                else:
                    bulk_records_op[indexname].append(record_op)                
        except:
            raise

    #mongo_client.ensure_index([('time', 1), ('client_ip', 1)])
    #mongo_client.ensure_index([('eid', 1)])
    for index in bulk_records_eid:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        #mongo_client[db_name][coll_name].insert(bulk_records_eid[index])
    for index in bulk_records_ua:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        #mongo_client[db_name][coll_name].insert(bulk_records_ua[index])
    for index in bulk_records_op:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        #mongo_client[db_name][coll_name].insert(bulk_records_op[index])

def process(logfile):
    global pattern
    pattern = re.compile(pattern)
    watcher = LogWatcher(logfile, callback)
    watcher.loop()


mongo_client = MongoClient(mongodb_url)
process(logfile)
