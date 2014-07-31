#!/usr/bin/python
# Name: mDnsToIP.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 18, 2014
# For:  Generate maltego scripts to resolve ip_addr
#       from malicious domains
#
# Usage: if dns is found in database, get all information from database
#        or gather information from open intelligence

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
            dns = input[1]
        else:
            dns = input[0]

    #   checking database, passive_dns table
    c.execute("SELECT * FROM passive_dns where dns=?", ((dns),))
    found = c.fetchone()
    if found is not None:
        #   adding entity ip ...
        id = found[0]
        sid = found[1]
        source = found[2]
        resolve_date = found[4]
        #   checking database, ip
        if source == 'c2':
            c.execute("SELECT * FROM c2 where id=?", ((sid),))
            found1 = c.fetchall()
            #print "records =" + str(len(found1))
            if found1 is not None:
                for i in range(0, len(found1)):
                    scan_date = found1[i][2]
                    ip_addr = found1[i][4]
                    #   adding entity ip (resolve_date)
                    entity = MaltegoEntity()
                    entity.setType("ran2.c2Address")
                    entity.setValue(ip_addr)
                    entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                    entity.addAdditionalFields('notes#', '', True, resolve_date)
                    me.addEntityToMessage(entity)

    #   checking database, c2 table
    c.execute("SELECT * FROM c2 where dns=?", ((dns),))
    found = c.fetchone()
    if found is not None:
        #   adding entity ip ...
        id = found[0]
        sid = found[1]
        scan_date = found[2]
        ip_addr = found[4]
        entity = MaltegoEntity()
        entity.setType("ran2.c2Address")
        entity.setValue(ip_addr)
        entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
        entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
        me.addEntityToMessage(entity)

    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

