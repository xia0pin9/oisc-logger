import re
from plugin.log_parser import parse_dhcp
from plugin.log_watcher import LogWatcher
from conf_d import Configuration
from pymongo import MongoClient

conf = Configuration(
    name = "dhcplog",
    path = "./config/dhcplog.conf",
    main_defaults = {
        "mongodb_url" : "mongodb://localhost:27017",
    }
)

config = conf.raw()

mongodb_url = config['dhcplog']['mongodb_url'].replace("\"", "")
sections = config['sections']
mongo_client = MongoClient(mongodb_url)

def callback(filename, lines):
    global pattern
    global mongo_client
    bulk_records = {}
    for line in lines:
        try:
            db_name, coll_name, record = parse_dhcp(line, pattern)
            if record != {}:
                indexname = db_name + ":" + coll_name
                if indexname not in bulk_records:
                    bulk_records[indexname] = [record]
                else:
                    bulk_records[indexname].append(record)
        except:
            print parse_dhcp(line, pattern)
            raise
    for index in bulk_records:
        db_name, coll_name = index.split(":")
        print db_name, coll_name
        #mongo_client[db_name][coll_name].insert(bulk_records[index])

def process(logfile):
    global pattern
    pattern = ''.join([x.replace("\"", "") for x in sections[logfile]['pattern'].split("\n")])
    pattern = re.compile(pattern)
    watcher = LogWatcher(logfile, callback)
    watcher.loop()

for logfile in sections:
    process(logfile)
