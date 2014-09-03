import re
from log_parser import parse_ids
from log_watcher import LogWatcher
from pymongo import MongoClient


# Config info of ids-ua logger
mongodb_url = "mongodb://localhost:27017" 
logfile = "/data/ids-ua"


def callback(filename, lines):
    global mongo_client
    bulk_records = {}
    for line in lines:
        try:
            db_name, coll_name, record = parse_ids(line)
            if record != {}:
                indexname = db_name + ":" + coll_name
                if indexname not in bulk_records:
                    bulk_records[indexname] = [record]
                else:
                    bulk_records[indexname].append(record)
        except:
            print parse_ids(line)
            raise
            #print "IdsParser error: ", line, matchline(line, pattern)
    for index in bulk_records:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        mongo_client[db_name][coll_name].insert(bulk_records[index])

def process(logfile):
    watcher = LogWatcher(logfile, callback)
    watcher.loop()

mongo_client = MongoClient(mongodb_url)
process(logfile)
