import re
import sys
import subprocess
from log_parser import parse_procera
from pymongo import MongoClient


# Config info for procera (xp) logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/winxp/winxp.log"
pattern = "(\w+\s*\d+\s*\d+:\d+:\d+)\s*plr01 pld: \[Ruleset:Notice\] FW: \[Log\s*([\w\.\s-]+)\s* Hosts\] \(6\)\s*(\d+.\d+.\d+.\d+):\d+->\d+.\d+.\d+.\d+:\d+\s*.*"


pattern = re.compile(pattern)
mongo_client = MongoClient(mongodb_url)
command = ['tail', '-F', logfile]
p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
bulk_records = {}
count = 0
for line in iter(p.stdout.readline, ''):
    try:
        db_name, coll_name, record = parse_procera(line, pattern)
        if record != {}:
            count += 1
            indexname = db_name + ":" + coll_name
            if indexname not in bulk_records:
                bulk_records[indexname] = [record]
            else:
                bulk_records[indexname].append(record)
    except KeyboardInterrupt:
        sys.exit()
    except:
        raise
    else:
        if count >= 2000:
            for index in bulk_records:
                db_name, coll_name = index.split(":")
                mongo_client[db_name][coll_name].insert(bulk_records[index])
            count = 0
            bulk_records.clear()
