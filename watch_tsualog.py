import re
from log_parser import parse_tsua
from log_watcher import LogWatcher
from pymongo import MongoClient


# Config info for truesight logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/tslog"
pattern = "[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+\.\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username:(.*)"


def callback(filename, lines):
    global pattern
    global mongo_client
    bulk_records = {}
    for line in lines:
        try:
            db_name, coll_name, record = parse_tsua(line, pattern)
            if record != {}:
                indexname = db_name + ":" + coll_name
                if indexname not in bulk_records:
                    bulk_records[indexname] = [record]
                else:
                    bulk_records[indexname].append(record)
        except:
            print parse_tsua(line, pattern)
            raise
    for index in bulk_records:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        #mongo_client[db_name][coll_name].insert(bulk_records[index])

def process(logfile):
    global pattern
    pattern = re.compile(pattern)
    watcher = LogWatcher(logfile, callback)
    watcher.loop()


mongo_client = MongoClient(mongodb_url)
process(logfile)
