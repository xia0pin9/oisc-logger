import re
from log_parser import parse_fwteardown, is_fwteardown_log
from log_watcher import LogWatcher
from pymongo import MongoClient


# Config info for fw built logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/firewall"
pattern = "(\w+\s*\d+\s*\d\d:\d\d:\d\d).*?connection\s*(\d+)"


def callback(filename, lines):
    global pattern
    global mongo_client
    bulk_records = {}
    for line in lines:
        try:
            if not is_fwteardown_log(line):
                continue
            db_name, coll_name, record = parse_fwteardown(line, pattern)
            if record != {}:
                indexname = db_name + ":" + coll_name
                if indexname not in bulk_records:
                    bulk_records[indexname] = [record]
                else:
                    bulk_records[indexname].append(record)
        except:
            print parse_fwteardown(line, pattern)
            raise
    for index in bulk_records:
        db_name, coll_name = index.split(":")
        #print db_name, coll_name
        mongo_client[db_name][coll_name].insert(bulk_records[index])

def process(logfile):
    global pattern
    pattern = re.compile(pattern)
    watcher = LogWatcher(logfile, callback)
    watcher.loop()


mongo_client = MongoClient(mongodb_url)
process(logfile)
