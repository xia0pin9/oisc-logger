import re
import sys
#import subprocess
from sh import tail
from log_parser import parse_fwbuilt, is_fwbuilt_log
from pymongo import MongoClient


# Config info for fw built logger
mongodb_url = "mongodb://localhost:27017"
logfile = "/data/firewall/fw.log"
pattern = "(\w+\s*\d+\s*\d+:\d+:\d+).*?outbound\s*(\w+)\s*connection\s*(\d+).*?outside:(\d+.\d+.\d+.\d+)/(\d+).*?inside:(\d+.\d+.\d+.\d+)/(\d+)\s*\((\d+.\d+.\d+.\d+)/(\d+)\)"


mongo_client = MongoClient(mongodb_url)
pattern = re.compile(pattern)
#command = ["tail", "-F", logfile]
#p = subprocess.Popen(command, stdout=subprocess.PIPE)
bulk_records = {}
count = 0
for line in tail("-F", logfile, _iter=True): #iter(p.stdout.readline, ''):
    try:
        if not is_fwbuilt_log(line):
            continue
        db_name, coll_name, record = parse_fwbuilt(line, pattern)
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
        print parse_fwbuilt(line, pattern)
        raise
    else:
        if count >= 6000:
            for index in bulk_records:
                db_name, coll_name = index.split(":")
                mongo_client[db_name][coll_name].insert(bulk_records[index])
            count = 0
            bulk_records.clear()
