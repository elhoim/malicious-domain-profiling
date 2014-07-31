#!/usr/bin/python
# Name: mFileToIP.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 7, 2014
# For:  Generate maltego scripts to plot passive exploits, hostname & ip_addr
#       from malicious sample name [or md5 hash supplied]
#
# Usage: sample name is used to extract hostname & ip_addr

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
            name = input[1]
        else:
            name = input[0]

    #print "Checking ... " + name
    c.execute("SELECT * FROM samples where name=?", ((name),))
    found = c.fetchone()
    if found is not None:
        sid = found[0]
        md5sum = found[1]

        #   checking database, detects
        c.execute("SELECT * FROM detects where sid=? and (vendor='AcAfee' or vendor='Kaspersky' or vendor='F-Secure')", ((sid),))
        found1 = c.fetchone()
        if found1 is not None:
            result = found1[3]
            entity = MaltegoEntity()
            entity.setType("ran2.exploits")
            entity.setValue(result)
            entity.addAdditionalFields('notes#', '', True, md5sum)
            me.addEntityToMessage(entity)

        #   checking database, c2 table
        c.execute("SELECT * FROM c2 where sid=?", ((sid),))
        found2 = c.fetchall()
        if found2 is not None:
            for i in range(0, len(found2)):

                scan_date = found2[i][2]
                dns = found2[i][3]
                ip_addr = found2[i][4]
                
                #   adding entity hostname + ip_addr (scan_date) ...
                entity = MaltegoEntity()
                entity.setType("ran2.c2Address")
                entity.setValue(ip_addr)
                entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
                me.addEntityToMessage(entity)
                entity = MaltegoEntity()
                entity.setType("ran2.c2Hostname")
                entity.setValue(dns)
                entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
                me.addEntityToMessage(entity)

        else:
            #print "Collecting intelligence from the Internet ..."
            me.addEntity("maltego.Phrase", name + " is not found")


    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", name + " is not found")
    

    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

