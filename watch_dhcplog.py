import re
import sys
#import subprocess
from sh import tail
from log_parser import parse_dhcp
from pymongo import MongoClient


# Config info for dhcp logger
mongodb_url = "mongodb://localhost:27017",
logfile = "/data/dhcplog/dhcp.log"
pattern = "(\w+\s*\d+\s*\d+:\d+:\d+).*?DHCPACK on.*?(\d+.\d+.\d+.\d+)\s+to\s+([\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+)\s+\(?([:.\w\d-]*)\)?\s*via.*"


pattern = re.compile(pattern)
#command = ['tail', '-F', logfile]
#p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
mongo_client = MongoClient(mongodb_url)
bulk_records = {}
count = 0
for line in tail("-F", logfile, _iter=True): #iter(p.stdout.readline, ''):
    try:
        db_name, coll_name, record = parse_dhcp(line, pattern)
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
