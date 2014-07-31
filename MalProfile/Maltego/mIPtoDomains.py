#!/usr/bin/python
# Name: mIPtoDomains.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 7, 2014
# For:  Generate maltego scripts to plot Domains
#       from malicious IP addresses supplied
#
# Usage:

import sys
import os
import datetime
import sqlite3
import ConfigParser
from MaltegoTransform import *

DEBUG = True
try:
    config_ini = "MalProfile.ini"
    config = ConfigParser.ConfigParser()
    config.read(config_ini)
    DBNAME = config.get("MalProfile", "DBNAME")
    VT_APIKEY = config.get("API_KEYS", "VT_APIKEY")
except:
    #print("Error reading config file: " + config_ini + "!")
    sys.exit()

#   ===start===
def main():

    #   init Maltego
    me = MaltegoTransform()

    #  open database and create a cursor object
    if not os.path.isfile(DBNAME):
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", "Database file not found " + DBNAME)
    conn = sqlite3.connect(DBNAME)
    conn.text_factory = str
    c = conn.cursor()

    if len(sys.argv) == 1:
        me.addEntity("maltego.Phrase", "You must provide a Sample name!")
        sys.exit()
    else:
        input = sys.argv[1].split('=')
        if len(input) == 2:
            ip_addr = input[1]
        else:
            ip_addr = input[0]

    #   checking database, ip table
    c.execute("SELECT * FROM ip where ip_addr=?", ((ip_addr),))
    found = c.fetchone()
    if found is not None:
        #   adding entity domains...
        sid = found[0]
        #   checking database, domains
        c.execute("SELECT * FROM domains where sid=? and source='ip'", ((sid),))
        found1 = c.fetchall()
        #print "records =" + str(len(found1))
        if found1 is not None:
            for i in range(0, len(found1)):
                scan_date = found1[i][3]
                domain = found1[i][4]
                Cname = found1[i][5]
                #   adding entity domain (Cname)
                entity = MaltegoEntity()
                entity.setType("ran2.c2Domain")
                entity.setValue(domain)
                entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
                entity.addAdditionalFields('notes#', '', True, Cname)
                me.addEntityToMessage(entity)
                
        #   adding entity passive domains...
        c.execute("SELECT * FROM passive_domains where sid=? and source='ip'", ((sid),))
        found2 = c.fetchall()
        #print "records =" + str(len(found2))
        if found2 is not None:
            for j in range(0, len(found2)):
                scan_date = found2[j][3]
                domain = found2[j][4]
                Cname = found2[j][5]
                #   adding entity domain (Cname)
                entity = MaltegoEntity()
                entity.setType("maltego.Domain")
                entity.setValue(domain)
                entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                entity.addAdditionalFields('notes#', '', False, Cname)
                me.addEntityToMessage(entity)

    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", "no sample info found ...")

    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

