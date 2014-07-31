#!/usr/bin/python
# Name: mfromLikeIP.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 31, 2014
# For:  Generate maltego scripts to plot C-class ip_addr contained in ip table by ip_addr input (identifying friendly IP)
#
#


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

    #  open database and create a cursor object
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
        me.addEntity("maltego.Phrase", "You must provide an ip_addr!")
        sys.exit()
    else:
        input = sys.argv[1].split('=')
        if len(input) == 2:
            ip_addr = input[1]
        else:
            ip_addr = input[0]

    if ip_addr != "":
        ip = ip_addr.split('.')
        ip_addr = ip[0] + "." + ip[1] + "." + ip[2]

    input = '"%' + ip_addr + '%"'
    sql1 = "SELECT * FROM ip where ip_addr like " + input

    #   checking database, ip table
    c.execute(sql1)
    found1 = c.fetchall()
    if found1 is not None:
        for i in range(0, len(found1)):
            source = found1[i][2]
            ip_addr = found1[i][5]

            #   adding entity IP Entity
            if ip_addr != '' and ip_addr != sys.argv[1]:
                entity = MaltegoEntity()
                entity.setType("maltego.IPv4Address")
                entity.setValue(ip_addr)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                me.addEntityToMessage(entity)

    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", "no sample info found ...")

    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

