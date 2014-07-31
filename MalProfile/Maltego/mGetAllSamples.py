#!/usr/bin/python
# Name: mGetAllSamples.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 18, 2014
# For:  Generate maltego scripts to plot malicious Samples
#       from Samples table
#
# Usage: All records in Samples table are displayed

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

    #   reading samples table ...
    c.execute("SELECT * FROM samples")
    found = c.fetchall()
    if found is not None:
        for i in range(0, len(found)):
            #   adding Sample entity
            name = found[i][2]
            me.addEntity("ran2.Sample", name)
    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", name + " is not found")


    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

