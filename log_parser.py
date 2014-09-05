#!/usr/bin/evn python

import re
import struct
import socket
import traceback
from dateutil import parser

mac_os_ua = {}
win_os_ua = {}


with open("mac_os_agents.txt") as f:
    for line in f:
        cfn, os = line.strip().split(",")
        mac_os_ua[cfn] = os.strip()

with open("win_os_agents.txt") as f:
    for line in f:
        nt, os = line.strip().split(",")
        win_os_ua[nt] = os.strip()


def get_platform(user_agent):
    osversion = ''
    if "CFNetwork" in user_agent:
        us_temp = user_agent[user_agent.find("CFNetwork"):].split()[0]
        if us_temp in mac_os_ua:
            osversion = mac_os_ua[us_temp]
        else:
            us_temp = user_agent[user_agent.find("Darwin"):].split()[0]
            if us_temp in mac_os_ua:
                osversion = mac_os_ua[us_temp]
    elif "Macintosh" in user_agent:
        if "OS" in user_agent:
            us_temp = user_agent[user_agent.find("OS"):].split(";")[0]
            osversion = "Mac " + us_temp.split(")")[0].replace("_", ".")
        else:
            osversion = "Macintosh unknown"
    elif "Mac" in user_agent:
        osprefix = ''
        if "iPhone" in user_agent or "iPad" in user_agent or \
                "iPod" in user_agent:
            osprefix = "i"
        else:
            osprefix = "Mac "
        if "OS" in user_agent:
            us_temp = user_agent[user_agent.find("OS"):].replace("_", ".")
            osversion = osprefix + us_temp
            osversion = osversion.replace("like", "(")
            osversion = osversion.replace(")", "(").split("(")[0]
        else:
            osversion = "Mac unknown"
    elif "iPhone" in user_agent:
        result1 = re.search("OS \d(\.\d)+", user_agent)
        result2 = re.search("\d(\.\d)+", user_agent)
        if result1:
            osversion = "iOS " + result1.group(0)
        elif "Apple" in user_agent and result2:
            osversion = "iOS " + result2.group(0)

    if "Windows" in user_agent:
        result1 = re.search("Windows;", user_agent)
        result2 = re.search("Windows NT \d(\.\d)+", user_agent)
        result3 = re.search("Windows \d(\.\d)?", user_agent)
        if result1:
            us_temp = user_agent[user_agent.find("Windows"):]
            osversion = us_temp.split(";")[1].strip()
            if "Windows" in osversion:
                us_temp = user_agent[user_agent.find("Windows"):]
                osversion = "Windows " + us_temp.split()[1]
            elif osversion.count('.') == 2:
                index_temp = osversion.split('.')[0] + "." + \
                    osversion.split('.')[1]
                osversion = win_os_ua["Windows NT " + index_temp]
            else:
                osversion = "Windows " + osversion
        elif result2:
            index_temp = result2.group(0).split(".")[0] + "." + \
                result2.group(0).split(".")[1]
            if index_temp in win_os_ua:
                osversion = win_os_ua[index_temp]
            else:
                osversion = "Windows unknown"
        elif result3:
            us_temp = user_agent[user_agent.find("Windows"):].split(";")[0]
            osversion = us_temp.split(")")[0].strip()
            if "Windows NT " + osversion.split()[1] in win_os_ua:
                osversion = win_os_ua["Windows NT "+osversion.split()[1]]
            else:
                osversion = "Windows " + osversion.split()[1]
        else:
            osversion = "Windows unknown"
    elif "Android" in user_agent or "android" in user_agent:
        result = re.search("Android \d(\.\d)+", user_agent)
        if result:
            osversion = result.group(0)
        else:
            osversion = "Android unknown"
    elif "ubuntu" in user_agent or "Linux" in user_agent or \
            "linux" in user_agent:
        osversion = "Linux"

    if osversion == "" or osversion == None:
        osversion = "Other" 
    return osversion


def parse_ids_ua(line):
    line_split = line.rstrip().split(",")
    db_name = ''
    coll_name = ''
    record = {}
    if len(line_split) < 6 and "snoopy UA-Strings" not in line:
        return db_name, coll_name, record
    try:
        ts, fwip, fwport, remote_ip, remote_port, us = line_split[:6]
        ts = parser.parse(ts.split("Strings:")[1].replace("/", "-"))
        platform = get_platform(us)
    except:
        print "Log line info:", line
        return db_name, coll_name, record 
    else:
        if platform != '':
            record['timestamp'] = ts
            record['firewall_ip'] = fwip
            if fwport != '':
                record['firewall_port'] = int(fwport)
            else:
                record['firewall_port'] = ''
            record['remote_ip'] = remote_ip
            if remote_port != '':
                record['remote_port'] = int(remote_port)
            else:
                record['remote_port'] = ''
            record['user_agent'] = us
            record['os'] = platform
            db_name = 'ids_ua_log_' + ts.strftime("%Y_%m_%d")
            coll_name = 'idsua_' + ts.strftime("%Y_%m_%d_%H")
    return db_name, coll_name, record


def addressInNetwork(ip,net):
    '''Is an address in a network'''
    # Convert addresses to host order, so shifts actually make sense
    ip = struct.unpack('>L',socket.inet_aton(ip))[0]
    netaddr,bits = net.split('/')
    netaddr = struct.unpack('>L',socket.inet_aton(netaddr))[0]
    # Must shift left an all ones value, /32 = zero shift, /0 = 32 shift left
    netmask = (0xffffffff << (32-int(bits))) & 0xffffffff
    # There's no need to mask the network address, as long as its a proper network address
    return (ip & netmask) == netaddr


def is_home_network(client_ip):
    home_nets = ['129.130.0.0/16', '10.130.0.0/16', '10.131.0.0/16']
    result = False
    for home_net in home_nets:
        if addressInNetwork(client_ip, home_net):
            result = True
            break
    return result


def parse_ts_ua(line, pattern):
    matched = pattern.match(line)
    db_name = 'ts_ua_log_'
    coll_name = 'tsua_'
    record = {}
    if matched:
	try:
            date = matched.group(1)
            date = parser.parse(date)
            client_ip = matched.group(2)
            remote_ip = matched.group(6)
            remote_port = matched.group(7)
            user_agent = matched.group(4)
            platform = get_platform(user_agent)
        except:
            print "Parser error, line info:", line
            traceback.print_exc(file=sys.stdout) 
        else:
            if is_home_network(client_ip):
                ts_day = date.strftime("%Y_%m_%d")
                ts_hour = date.strftime("%Y_%m_%d_%H")
                record["timestamp"] = date
                record["client_ip"] = client_ip
                record["remote_ip"] = remote_ip
                record["remote_port"] = remote_port
                record["os"] = platform
                record["user_agent"] = user_agent
                db_name = db_name + ts_day
                coll_name = coll_name + ts_hour
    return db_name, coll_name, record


def parse_dhcp(line, pattern):
    db_name = ''
    coll_name = ''
    record = {}
    matched = pattern.match(line)
    if(matched):
        timestamp = matched.group(1)
        ipaddress = matched.group(2)
        macaddress = matched.group(3)
        hostname = matched.group(4)
        
        date = parser.parse(timestamp)
        ts_day = date.strftime("%Y_%m_%d") 
        ts_hour = date.strftime("%Y_%m_%d_%H")

        record['timestamp'] = date
        record['ip_address'] = ipaddress
        record['mac_address'] = macaddress
        record['host_name'] = hostname
        
        db_name = 'incident_response_dhcp_log_' + ts_day
        coll_name = 'dhcplog_'+ts_hour
    return db_name, coll_name, record


def is_fwbuilt_log(line):
    if ('outbound UDP' in line) or ('outbound TCP' in line):
        return True
    else:
        return False


def parse_fwbuilt(line, pattern):
    matched = pattern.match(line)
    record = {}
    coll_name = ''
    db_name = ''
    if matched:
        timestamp = matched.group(1)
        protocol = matched.group(2)
        conn_id = matched.group(3)
        remote_ip = matched.group(4)
        remote_port = matched.group(5)
        internal_ip = matched.group(6)
        internal_port = matched.group(7)
        external_ip = matched.group(8)
        external_port = matched.group(9) 
        
        date = parser.parse(timestamp)
        ts_day = date.strftime("%Y_%m_%d")
        ts_hour = date.strftime("%Y_%m_%d_%H")

        record['_id'] = int(conn_id)
        record['firewall_ip'] = external_ip
        record['firewall_port'] = external_port
        record['internal_ip'] = internal_ip
        record['internal_port'] = internal_port
        record['remote_ip'] = remote_ip
        record['remote_port'] = remote_port
        record['protocol'] = protocol
        record['start_time'] = date
        
        coll_name = 'nat_start_'+ts_hour
        db_name = 'incident_response_nat_built_'+ts_day
    return db_name, coll_name, record


def is_fwteardown_log(line):
    if('Teardown TCP' in line) or ('Teardown UDP' in line):
        return True
    else:
        return False


def parse_fwteardown(line, pattern):
    matched = pattern.match(line)
    record = {}
    db_name = ''
    coll_name = ''
    if matched:
        timestamp = matched.group(1)
        date = parser.parse(timestamp)
        ts_day = date.strftime("%Y_%m_%d")
        ts_hour = date.strftime("%Y_%m_%d_%H")
        conn_id = matched.group(2)

        record['_id'] = int(conn_id)
        record['end_time'] = date
        
        db_name = 'incident_response_nat_teardown_'+ts_day
        coll_name = 'nat_end_'+ts_hour
    return db_name, coll_name, record

                  
def parse_ts_eid(line, pattern):
    db_name = 'incident_response_eid_ip'
    coll_name = 'eid_ip'
    record = {}
    matched = pattern.match(line)
    if matched:
        username = matched.group(8)
        if username:
            time = matched.group(1)
            time = parser.parse(time)
            client_ip = matched.group(2)
            record['time'] = time
            record['client_ip'] = client_ip
            record['eid'] = username
    return db_name, coll_name, record


def parse_procera(line, pattern):
    db_name = ''
    coll_name = ''
    record = {}
    matched = pattern.match(line)
    if matched:
        timestamp =  matched.group(1)
        platform = matched.group(2)
        client_ip = matched.group(3)
        timestamp = parser.parse(timestamp)
        ts_day = timestamp.strftime("%Y_%m_%d")
        ts_hour = timestamp.strftime("%Y_%m_%d_%H")
         
        record["timestamp"] = timestamp
        record["client_ip"] = client_ip
        record["platform"] = platform

        coll_name = 'coll_'+ts_hour
        db_name = 'xp_hosts_procera_'+ts_day
    return db_name, coll_name, record


def get_old_platform(user_agent):

    if "Windows NT 5.1" in user_agent or "Windows NT 5.2" in user_agent or "Windows XP" in user_agent:
        return "Windows XP"
    elif "Intel Mac OS X 10.3" in user_agent or "Intel Mac OS X 10_3" in user_agent :
        return "Mac OS X 10.3"
    elif "Intel Mac OS X 10.4" in user_agent or "Intel Mac OS X 10_4" in user_agent :
        return "Mac OS X 10.4"
    elif "Intel Mac OS X 10.5" in user_agent or "Intel Mac OS X 10_5" in user_agent :
        return "Mac OS X 10.5"
    else:
        return None
        

def parse_ts_oldplatform(line, pattern):
    matched = pattern.match(line)
    db_name = ''
    coll_name = ''
    record = {}
    if matched:
        try:
            date = matched.group(1)
            date = parser.parse(date)
            client_ip = matched.group(2)
            user_agent = matched.group(4)
            platform = get_old_platform(user_agent)
        except:
            print "Log error info:", line
        if (platform is not None) and (is_home_network(client_ip)):
            tsDay = date.strftime("%Y_%m_%d")
            tsHour = date.strftime("%Y_%m_%d_%H")
            record["timestamp"] = date
            record["client_ip"] = client_ip
            record["platform"] = platform
            db_name = 'xp_hosts_requests_db_'+tsDay
            coll_name = 'coll_'+tsHour
    return db_name, coll_name, record
