#!/usr/bin/env python

# Name: MalProfile.py
# By:   Frankie Li / Kenneth Tse
# Version Date: Jul 31, 2014
# For:  profiling malware infrastructure and attackers info based on
#       malicious file and hostname(s) identified
# 
# Modified based on Frankie's version and turn in to a class
#
# === old Desc ===
# Usage: create a ./database folder and init database
#        and put the malicious files in ./files folder before running the script with -f -d

import sys  
import os
import hashlib
import re
import whois
import sqlite3
import json
import urllib
import urllib2
import simplejson
import ConfigParser
import datetime
from utils.db import DBUtil
from utils.domainName import DNSUtil
from utils.hash import HashUtil
from utils.web import WebUtil
from utils.whoisBase import WhoisBase
from utils.whoisGenericRegex import WhoisGenericRegex
from MaltegoTransform import *
from optparse import OptionParser

class MalProfile:
    """ Malware domain profiling """
    def __init__(self):
        pass

try:
    config_ini = "MalProfile.ini"
    config = ConfigParser.ConfigParser()
    config.read(config_ini)
    DBNAME = config.get("MalProfile", "DBNAME")
    VT_APIKEY = config.get("API_KEYS", "VT_APIKEY")
except:
    print("Error reading config file: " + config_ini + "!")
    sys.exit()

FILE = ''
S_DATE = str(datetime.datetime.now()).split(" ")[0]

###########################

def updateDomains(ip_addr, ip_sid, s, c, t):
    d = []
    d = DNSUtil.retDomain(ip_addr, d)
    print "There are: " + str(len(d)) + " domains parking to " + ip_addr
    
    #   filter out if ip_addr parked with > 200 domains
    if len(d) > 0 and len(d) < 200:
        #   update domains
        for i in range(0, len(d)):
            
            #   init variables
            domain = d[i]
            
            # get Cname from (d)
            name = DNSUtil.retCName(domain)
            
            # check if the same record is found in domains table
            c.execute("SELECT * FROM domains WHERE domain=?", ((domain),))
            found = c.fetchone()
            
            #   add if not found
            if found is None:
                #   adding record ...
                list = (ip_sid, s, S_DATE, domain, name)
                if t == 'domains':
                    c.execute("INSERT INTO domains VALUES (NULL,?,?,?,?,?)", list)
                    print "[+] Adding to domains... " + domain
                else:
                    c.execute("INSERT INTO passive_domains VALUES (NULL,?,?,?,?,?)", list)
                    print "[+] Adding to passive_domains..." + domain
            else:
                print "[-] No records updated..."
    
    else:
        #   domains not updated
        print "[-] No or too many domain records updated|to be updated..."


# Grabbing whois data
def retWhois(data):
    try:
        w = whois.whois(data)
        return w.text
    except:
        w = ''
        return w


#   update whois table with one(1) domain provided
def updateWhois(domain, s, domain_sid, c, t):
    
    # change below line to use other Whois module derived from WhoisBase
    w = retWhois(domain)
    xwhois = WhoisGenericRegex()
    xwhois.query(domain, w)
    cname = DNSUtil.retCName(domain)
    tel = xwhois.tel
    email = xwhois.email
    cdate = xwhois.createdate
    name = xwhois.registrar
    owner = xwhois.registrant
    ns = xwhois.ns

    #   check if the same record (by scan date) is found in whois table
    wlist = (domain, email, owner)
    if t == 'whois':
        c.execute("SELECT * FROM whois WHERE domain=? and email=? and registrant=?", (wlist))
    else:
        c.execute("SELECT * FROM passive_whois WHERE domain=? and email=? and registrant=?", (wlist))
    found = c.fetchone()
    if found is None:
        #   preparing list record ...
        list = (domain_sid, s, domain, S_DATE, cdate, name, ns, email, tel, owner)
        return list
    else:
        return ''


#   update passive_ip table from VirusTotal with dns|domain name provided
def updateVTip(table, t, c):

    #   loop the table
    for j in range (0, len(table)):
            
        #   init variables
        if table[j][0] is None:
            dns = ''
        else:
            dns = table[j][0]
            
        sid = table[j][1]
            
        #   init VirusTotal api with dns supplied
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': dns, 'apikey': VT_APIKEY}
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            
        #   try catching json error
        try:
            response_dict = json.loads(response)
        except:
            response_dict = {}
            
        #   if resolutions is found
        if response_dict.get('resolutions') is not None:
                
            #   extract last_resolved and hostname from the json retrieved
            for i in range(0, len(response_dict.get('resolutions'))):
                ip = response_dict.get('resolutions')[i].get('ip_address')
                date = response_dict.get('resolutions')[i].get('last_resolved')
                    
                #   check last_resolved
                if date is None:
                    rdate = ""
                else:
                    rdate = date.split(' ')[0]
                    
                #   check if same record (by resolved date & source) is added before
                list = (ip, rdate, t)
                c.execute("SELECT * FROM passive_ip WHERE ip_addr=? and resolve_date=? and source=?", (list))
                found = c.fetchone()
                    
                #   add if not found
                if found is None:
                        
                    #   adding record ...
                    list = (sid, t, S_DATE, rdate, ip)
                    c.execute("INSERT INTO passive_ip VALUES (NULL,?,?,?,?,?)", list)
                    print dns + ": resolved to " + ip + " on " + rdate
                    
                else:
                    print "[-] No Passive IP record added ... " + dns
            
        else:
            print "[-] no Passive IP record found ... " + dns


def updateVTdns(table, t, c):

    #   loop the table
    for j in range (0, len(table)):
    
        #   init variables
        ip = table[j][0]
        sid = table[j][1]
    
        #   init VirusTotal api with ip_addr supplied
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': ip, 'apikey': VT_APIKEY}
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    
        #   try catching json error
        try:
            response_dict = json.loads(response)
        except:
            response_dict = {}
    
        #   if resolutions is found
        if response_dict.get('resolutions') is not None:
        
            #   extract last_resolved and hostname from the json retrieved
            for i in range(0, len(response_dict.get('resolutions'))):
            
                dns = response_dict.get('resolutions')[i].get('hostname')
                date = response_dict.get('resolutions')[i].get('last_resolved')
            
                #   check last_resolved
                if date is None:
                    rdate = ""
                else:
                    rdate = date.split(' ')[0]
            
                #   check if same record is added before
                list = (dns, rdate, t)
                c.execute("SELECT * FROM passive_dns WHERE dns=? and resolve_date=? and source=?", (list))
                found = c.fetchone()
            
                #   add if not found
                if found is None:
                
                    #   extract 'A' record part for a hostname
                    if len(dns.split('.')) == 3:
                        A = dns.split('.')[0]
                        d = dns.split('.')[1]+'.'+dns.split('.')[2]
                    else:
                        A = ""
                        d = dns
                
                    #   adding record ...
                    list = (sid, t, S_DATE, rdate, dns, A, d)
                    c.execute("INSERT INTO passive_dns VALUES (NULL,?,?,?,?,?,?,?)", list)
                    print ip + ": resolved to " + dns + " on " + rdate
            
                else:
                
                    print "[-] no Passive DNS record added..." + ip
    
        else:
            print "[-] no Passive DNS records found ... " + ip


#   return 2 arrays of VirusTotal scanned results by md5 hash provided
def retDetects(md5sum):
    
    vendor = []
    result = []
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {'resource': md5sum, 'apikey': VT_APIKEY}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
        
    #   try catching json error
    try:
        response_dict = simplejson.loads(json)
    except:
        response_dict = {}

    count = len(response_dict.get("scans", []))
    for i in range(0, count):
        k = response_dict.get("scans", []).keys()[i]
        v = response_dict.get("scans", []).values()[i].get('result')
        if v is not None:
            vendor.append(k)
            result.append(v)

    return vendor, result



def do_c2(c):
        print "Rescanning c2 ..."
        c.execute("SELECT * FROM c2")
        found = c.fetchall()
        for i in range(0, len(found)):
            sid = found[i][0]
            scan_date = found[i][2]
            dns = found[i][3]
            ip_addr = found[i][4]
            t = 'c2'
        
            #   updating passive_ip table from opts.dns in c2
            table = []
            table.append((dns, sid))
            updateVTip(table, t, c)
        
            #   updating passive_dns table from ip_addr in c2
            table = []
            table.append((ip_addr, sid))
            updateVTdns(table, t, c)
        
            #   updating ip table from ip_addr in c2
            #   checking ... if same ip_addr found
            c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
            found2 = c.fetchone()
            if found2 is None:
                #   adding ...
                list = (sid, t, S_DATE, S_DATE, ip_addr)
                c.execute("INSERT INTO ip VALUES (NULL,?,?,?,?,?)", (list))
                ip_sid = c.lastrowid
                print "[+] Added record to ip with %s" % ip_addr
            else:
                ip_sid = found2[0]
        
            #   update domains table from ip_addr in c2
            s = 'ip'
            t = 'domains'
            updateDomains(ip_addr, ip_sid, s, c, t)
        
            #   update whois table from newly created parking domains
            #   checking ...
            c.execute("SELECT * FROM domains where sid=? and source='ip'", ((ip_sid),))
            domains = c.fetchall()
        
            for i in range (0, len(domains)):
            
                #   init variables
                domain_sid = domains[i][0]
                domain = domains[i][4]
            
                #   update Whois records of newly added domains
                s = 'domains'
                t = 'whois'
                list = updateWhois(domain, s, domain_sid, c, t)
                if list != '':
                    c.execute("INSERT INTO whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
                    print "[+] Updating Whois record of ..." + " " + domain
                else:
                    print "[-] No whois records updated ..." + " " + domain


def do_owner(c):
    #   owner table
    c.execute("SELECT * FROM domains where source='owner'")
    domains = c.fetchall()
    for i in range(0, len(domains)):
        domain = domains[i][4]
        c.execute("SELECT * FROM whois where domain=?", ((domain),))
        found = c.fetchall()
        print domain
        for j in range(0, len(found)):
            scan_date = found[j][4]
            c_date = found[j][5]
            registrar = found[j][6]
            nameServer = found[j][7]
            email = found[j][8]
            tel = found[j][9]
            registrant = found[j][10]
            list = (found[j][3], scan_date, c_date, registrant, email, tel, nameServer, registrar)
            print list
        print ''


def do_passive(c):
    print "Rescanning f_c2 ..."
    c.execute("SELECT * FROM f_c2")
    found = c.fetchall()
    for i in range(0, len(found)):
        sid = found[i][0]
        scan_date = found[i][3]
        ip_addr = found[i][4]
        t = 'f_c2'
        
        #   updating ip table from ip_addr in f_c2
        #   checking ... if same ip_addr found
        c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
        found2 = c.fetchone()
        if found2 is None:
            #   adding ...
            list = (sid, t, S_DATE, S_DATE, ip_addr)
            c.execute("INSERT INTO ip VALUES (NULL,?,?,?,?,?)", (list))
            print "[+] Added record to ip with %s" % ip_addr

    print "Rescanning passive_dns ..."
    c.execute("SELECT * FROM passive_dns")
    found = c.fetchall()
    for i in range(0, len(found)):
        sid = found[i][0]
        scan_date = found[i][3]
        resolve_date = found[i][4]
        dns = found[i][5]
        ip_addr = DNSUtil.retIP(dns)
        t = 'passive_dns'

        #   updating ip table from ip_addr resolved from passive_dns
        #   checking ... if same ip_addr found
        c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
        found2 = c.fetchone()
        if found2 is None:
            #   adding ...
            list = (sid, t, scan_date, resolve_date, ip_addr)
            c.execute("INSERT INTO ip VALUES (NULL,?,?,?,?,?)", (list))
            print "[+] Added record to ip with %s" % ip_addr

    print "Rescanning passive_ip ..."
    c.execute("SELECT * FROM passive_ip")
    found = c.fetchall()
    for i in range(0, len(found)):
        sid = found[i][0]
        scan_date = found[i][3]
        resolve_date = found[i][4]
        ip_addr = found[i][5]
        t = 'passive_ip'

        #   updating ip table from ip_addr resolved from passive_dns
        #   checking ... if same ip_addr found
        c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
        found2 = c.fetchone()
        if found2 is None:
            #   adding ...
            list = (sid, t, scan_date, resolve_date, ip_addr)
            c.execute("INSERT INTO ip VALUES (NULL,?,?,?,?,?)", (list))
            print "[+] Added record to ip with %s" % ip_addr


def do_parking(c):
    print "Reading ip table to update domains and whois tables"
    c.execute("SELECT * FROM ip where source = 'c2'")
    found = c.fetchall()
    for i in range(0, len(found)):
        ip_sid = found[i][0]
        ip_addr = found[i][5]
    
        #   update domains table from ip_addr in c2
        s = 'ip'
        t = 'domains'
        updateDomains(ip_addr, ip_sid, s, c, t)
    
        #   update whois table from newly created parking domains
        #   checking newly updated domains
        c.execute("SELECT * FROM domains where sid=? and source='ip'", ((ip_sid),))
        domains = c.fetchall()
        for j in range (0, len(domains)):
        
            #   init variables
            domain_sid = domains[j][0]
            domain = domains[j][4]
        
            #   update Whois records of newly added domains
            s = 'domains'
            t = 'whois'
            list = updateWhois(domain, s, domain_sid, c, t)
            if list != '':
                c.execute("INSERT INTO whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
                print "[+] Updating Whois record of ... " + " " + domain
            else:
                print "[-] No whois records updated ..." + " " + domain

    print "Reading ip table to update passive_domains and passive_whois tables"
    c.execute("SELECT * FROM ip where source != 'c2'")
    found = c.fetchall()
    for i in range(0, len(found)):
        ip_sid = found[i][0]
        ip_addr = found[i][5]
    
        #   update domains table from ip_addr in c2
        s = 'ip'
        t = 'passive_domains'
        updateDomains(ip_addr, ip_sid, s, c, t)
    
        #   update whois table from newly created parking domains
        #   checking newly updated domains
        c.execute("SELECT * FROM passive_domains where sid=? and source='ip'", ((ip_sid),))
        domains = c.fetchall()
        for j in range (0, len(domains)):
        
            #   init variables
            domain_sid = domains[j][0]
            domain = domains[j][4]
        
            #   update Whois records of newly added domains
            s = 'passive_domains'
            t = 'passive_whois'
            list = updateWhois(domain, s, domain_sid, c, t)
            if list != '':
                c.execute("INSERT INTO passive_whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
                print "[+] Updating passive_whois record of ... " + " " + domain
            else:
                print "[-] No whois records updated ..." + " " + domain


def do_rescan(c):

    print "Rescanning domains ..."
    c.execute("SELECT * FROM domains")
    found = c.fetchall()
    for i in range(0, len(found)):
        id = found[i][0]
        sid = found[i][1]
        source = found[i][2]
        domain = found[i][4]
        ip_addr = retIP(domain)
        #   update ip_addr if current resolved ip_addr is not found on ip table and passive_ip
        #   checking ip table ...
        if source == "ip":
            c.execute("SELECT * FROM ip where id=?", ((sid),))
            found1 = c.fetchone()
            if found1 is not None:
                if found1[5] != ip_addr:
                    print "[+] Adding source of ip to passive_ip ... " + ip_addr
                    list = (id, 'domains', S_DATE, S_DATE, ip_addr)
                    c.execute("INSERT INTO passive_ip VALUES (NULL,?,?,?,?,?)", list)
    
        else:
            #   checking passive_ip table ...
            c.execute("SELECT * FROM passive_ip where sid=?", ((id),))
            found2 = c.fetchone()
            if found2 is not None:
                if found2[5] != ip_addr:
                    print "[+] Adding source of owner to passive_ip ... " + ip_addr
                    list = (id, 'domains', S_DATE, S_DATE, ip_addr)
                    c.execute("INSERT INTO passive_ip VALUES (NULL,?,?,?,?,?)", list)


def do_passiveDomains(c):
    
    print "Reading ip table ..."
    c.execute("SELECT * FROM ip where source != 'c2'")
    found = c.fetchall()
    for i in range(0, len(found)):
        ip_sid = found[i][0]
        ip_addr = found[i][5]
        
        #   update domains table from ip_addr in c2
        s = 'ip'
        t = 'passive_domains'
        updateDomains(ip_addr, ip_sid, s, c, t)
        
        #   update whois table from newly created parking domains
        #   checking newly updated domains
        c.execute("SELECT * FROM passive_domains where sid=? and source='ip'", ((ip_sid),))
        domains = c.fetchall()
        
        for j in range (0, len(domains)):
            
            #   init variables
            domain_sid = domains[j][0]
            domain = domains[j][4]
            
            #   update Whois records of newly added domains
            s = 'passive_domains'
            t = 'passive_whois'
            list = updateWhois(domain, s, domain_sid, c, t)
            if list != '':
                c.execute("INSERT INTO passive_whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
                print "[+] Updating Passive whois record of ..." + " " + domain
            else:
                print "[-] No whois records updated ..." + " " + domain


def do_whois(c):
    
    print "Reading domains table..."
    c.execute("SELECT * FROM domains")
    found = c.fetchall()
    for i in range(0, len(found)):
        domain_sid = found[i][0]
        domain = found[i][4]

        s = 'domains'
        t = 'whois'
        #   whois table
        list = updateWhois(domain, s, domain_sid, c, t)
        if list != '':
            c.execute("INSERT INTO whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
            print "[+] Updating whois record of ..." + " " + domain
        else:
            print "[-] No whois records updated ..." + " " + domain


def do_passive_whois(c):

    print "Reading passive_domains table..."
    c.execute("SELECT * FROM passive_domains")
    found = c.fetchall()
    for i in range(0, len(found)):
        domain_sid = found[i][0]
        domain = found[i][4]
        
        s = 'passive_domains'
        t = 'passive_whois'
        #   passive whois table
        list = updateWhois(domain, s, domain_sid, c, t)
        if list != '':
            c.execute("INSERT INTO passive_whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
            print "[+] Updating passive_whois record of ..." + " " + domain
        else:
            print "[-] No whois records updated ..." + " " + domain


def do_temp(c):
    
    #   adding domain part of a malicious dns from c2 to domains table
    print "Reading c2 table..."
    c.execute("SELECT * FROM c2")
    found = c.fetchall()
    for i in range(0, len(found)):
        c2_id = found[i][0]
        dns = found[i][3]
        if dns != "":
        
            #   extract 'A' record part for a hostname, d for a domain
            try:
                dns_len = len(dns.split('.'))
            except:
                dns_len = 0
            domain = ''
            if dns_len >= 3:
                A = dns.split('.')[0]
                for i in range (1, dns_len):
                    if i == dns_len-1:
                        domain = domain + dns.split('.')[i]
                    else:
                        domain = domain + dns.split('.')[i]+'.'
            else:
                if dns_len != 0:
                    A = ""
                    domain = dns.split('.')[dns_len-2]+'.'+dns.split('.')[dns_len-1]
        
        #   adding domain with c2_id as domain_sid
        #   check if domain has already added
        s = 'c2'
        c.execute("SELECT * FROM domains WHERE domain=?", ((domain),))
        found1 = c.fetchone()
        #   add if not found
        if found1 is None:
            #   adding record ...
            list = (c2_id, s, S_DATE, domain, A)
            c.execute("INSERT INTO domains VALUES (NULL,?,?,?,?,?)", list)
            print "[+] Adding to domains... " + domain

"""
        print "Rescanning samples ..."
        c.execute("SELECT * FROM samples")
        found2 = c.fetchall()
        for i in range(0, len(found2)):
            sid = found2[i][0]
            md5sum = found2[i][1]

            #   updating detects table
            print "[+] Checking with VirusTotal ....." + md5sum
            vendor, result = retDetects(md5sum)
            for j in range(0,len(vendor)):
                list = (sid, vendor[j], result[j])
                c.execute("INSERT INTO detects VALUES (NULL,?,?,?)", list)
"""


#   ===start===
def main():

    #   parse command line
    parser = OptionParser()
    parser.add_option("-i", action="store_true",dest="init", default=False, help="initialize c2 database [c2_dev.db]")
    parser.add_option("-f", action="store", dest="filename",
        type="string", help="Provide a FILENAME of the sample to check")
    parser.add_option("--md5", action="store", dest="md5",
        type="string", help="Provide a MD5 of the sample to check")
    parser.add_option("-d", action="store", dest="dns",
        type="string", help="Provide a DNSNAME to check")
    parser.add_option("-c", action="store_true",dest="c2", default=False, help="rescanning c2 to update all subsequent tables")
    parser.add_option("-o", action="store_true",dest="owner", default=False, help="rescanning owner table to update all subsequent tables")
    parser.add_option("-p", action="store_true",dest="passive", default=False, help="rescanning passive tables to update ip table")
    parser.add_option("-q", action="store_true",dest="parking", default=False, help="rescanning ip table to update domains & whois tables")
    parser.add_option("-r", action="store_true",dest="rescan", default=False, help="rescanning domains table to update passive_ip table")
    parser.add_option("-s", action="store_true",dest="passiveDomains", default=False, help="rescanning ip table to update passive_domains & passive_whois tables")
    parser.add_option("-t", action="store_true",dest="temp", default=False, help="rescanning and update domains table from malicious hostnames from c2")
    parser.add_option("-w", action="store_true",dest="whois", default=False, help="rescanning and update domains table to update whois")
    parser.add_option("-x", action="store_true",dest="passive_whois", default=False, help="rescanning and update whois table from passive_whois")
        
    (opts, args) = parser.parse_args()

    if opts.init:
        DBUtil.init()
        sys.exit()

    #  open database and create a cursor object
    if not os.path.isfile(DBNAME):
        print "%s does not exist, try initialization first." % DBNAME
        sys.exit()
    conn = sqlite3.connect(DBNAME)
    conn.text_factory = str
    c = conn.cursor()
    domains = []


    #   (-t) script to temp updating tables
    if opts.temp:
        #print "Do nothing ..."
        #   adding domain part of a malicious dns from c2 to domains table
        do_temp(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-c) script to rescanning c2 and subsequent tables
    if opts.c2:
        do_c2(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-o) update from owner table to domains (whois), passive_ip and ip tables
    if opts.owner:
        do_owner(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-p) script to rescanning f_c2, passive_dns, passive_ip to ip
    if opts.passive:
        do_passive(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-q) update parked domains and whois from ip table
    if opts.parking:
        do_parking(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-r) script to rescan domains registered by owners to update passive_ip table
    if opts.rescan:
        do_rescan(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-s) script to rescan ip to update passive_domains and passive_whois
    if opts.passiveDomains:
        do_passiveDomains(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-w) script to rescan domains table to update whois
    if opts.whois:
        do_whois(c)
        conn.commit()
        c.close()
        sys.exit()


    #   (-x) script to udpate passive_whois from passive_domains table
    if opts.passive_whois:
        do_passive_whois(c)
        conn.commit()
        c.close()
        sys.exit()


    #   MAIN script to update samples->detects, samples->c2->Passive_ip->ip,
    #   samples->c2->Passive_dns->ip,
    #   samples->c2->ip->domains->whois from filename & hostname provided

    if opts.filename == None:
        parser.print_help()
        parser.error("You must either provide a sample filename!")
    elif opts.md5 != None:
        if len(opts.md5) != 32:
            parser.error(opts.md5 + " doesn't look like a valid MD5 checksum!")
        else:
            md5sum = opts.md5
        name = opts.filename.split('.')[0]
    else:
        FILE = "./files/" + opts.filename
        name = opts.filename.split('.')[0]
        if not os.path.isfile(FILE):
            parser.error("%s does not exist" % FILE)
        else:
            md5sum = hashlib.md5(open(FILE, 'rb').read()).hexdigest()

    if opts.dns == None:
        parser.print_help()
        parser.error("You must provide a hostname!")

    #   updating samples table & check if same record (by md5 hash) is found
    c.execute("SELECT id FROM samples WHERE md5=?", ((md5sum),))
    found = c.fetchone()
    if found is None:
        #   update samples if not found
        list = (md5sum, name, S_DATE)
        c.execute("INSERT INTO samples VALUES (NULL,?,?,?)", (list))
        sid = c.lastrowid
        print "[+] Added record to samples with ID %d" % sid
    else:
        sid = found[0]
        print "[-] %s found ..." % name

    #   updating detects table
    print "[+] Checking with VirusTotal ....." + md5sum
    vendor, result = retDetects(md5sum)
    for j in range(0,len(vendor)):
        list = (sid, vendor[j], result[j])
        c.execute("INSERT INTO detects VALUES (NULL,?,?,?)", list)

    #   updating c2 table, check if dns and ip found in c2
    ip_addr = DNSUtil.retIP(opts.dns)
    list = (opts.dns, ip_addr)
    c.execute("SELECT dns FROM c2 WHERE dns=? and ip_addr=?", (list))
    found = c.fetchone()

    if found is None:
        
        #   updating c2 table
        #   checking ... if same hostname found
        list = (opts.dns, ip_addr)
        c.execute("SELECT * FROM c2 where dns=? and ip_addr=?", (list))
        found1 = c.fetchone()
        if found1 is None:
            #   adding ...
            list = (sid, S_DATE, opts.dns, ip_addr)
            c.execute("INSERT INTO c2 VALUES (NULL,?,?,?,?)", (list))
            sid = c.lastrowid
            print "[+] Added record to c2 with ID %d" % sid
        else:
            sid = found1[0]

        t = 'c2'

        #   updating passive_ip table from opts.dns in c2
        table = []
        table.append((opts.dns, sid))
        updateVTip(table, t, c)
        
        #   updating passive_dns table from ip_addr in c2
        table = []
        table.append((ip_addr, sid))
        updateVTdns(table, t, c)

        #   updating ip table from ip_addr in c2
        #   checking ... if same ip_addr found
        c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
        found2 = c.fetchone()
        if found2 is None:
            #   adding ...
            list = (sid, t, S_DATE, S_DATE, ip_addr)
            c.execute("INSERT INTO ip VALUES (NULL,?,?,?,?,?)", (list))
            ip_sid = c.lastrowid
            print "[+] Added record to ip with %s" % ip_addr
        else:
            ip_sid = found2[0]

        #   update domains table from ip_addr in c2
        s = 'ip'
        t = 'domains'
        updateDomains(ip_addr, ip_sid, s, c, t)
        
        #   update whois table from newly created parking domains
        #   checking ...
        c.execute("SELECT * FROM domains where sid=? and source='ip'", ((ip_sid),))
        domains = c.fetchall()

        for i in range (0, len(domains)):

            #   init variables
            domain_sid = domains[i][0]
            domain = domains[i][4]

            #   update Whois records of newly added domains
            s = 'domains'
            t = 'whois'
            list = updateWhois(domain, s, domain_sid, c, t)
            if list != '':
                c.execute("INSERT INTO whois VALUES (NULL,?,?,?,?,?,?,?,?,?,?)", list)
                print "[+] Updating Whois record of ... " + " " + domain
            else:
                print "[-] No whois records updated ..." + " " + domain

    else:
        hostname = found[0]
        print "[-] hostname:" + hostname + "(" + ip_addr + ")" + " has already added"

    conn.commit()
    c.close()

if __name__ == '__main__':
    main()

