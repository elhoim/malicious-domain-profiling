#!/usr/bin/python
# Name: mfromLikeEmail.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Feb 18, 2014
# For:  Generate maltego scripts to plot similar emails by a registrant
#
#
# Usage: if domain is found in database, get all information from database
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
        me.addEntity("maltego.Phrase", "You must provide a Sample name!")
        sys.exit()
    else:
        input = sys.argv[1].split('=')
        if len(input) == 2:
            email = input[1]
        else:
            email = input[0]

    e = email.split('@')
    input = '"%' + e[1] + '%"'
    sql1 = "SELECT * FROM whois where email like " + input
    sql2 = "SELECT * FROM passive_whois where email like " + input

    #   checking database, whois table
    c.execute(sql1)
    found1 = c.fetchall()
    if found1 is not None:
        for i in range(0, len(found1)):
            domain = found1[i][3]
            scan_date = found1[i][4]
            c_date = found1[i][5]
            registrar = found1[i][6]
            nameServer = found1[i][7]
            email = found1[i][8]
            tel = found1[i][9]
            registrant = found1[i][10]
            #   adding entity email
            if email != '':
                entity = MaltegoEntity()
                entity.setType("maltego.EmailAddress")
                entity.setValue(email)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                me.addEntityToMessage(entity)
            #   adding entity registrar
            if registrar != '':
                entity = MaltegoEntity()
                entity.setType("ran2.registrar")
                entity.setValue(registrar)
                entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                entity.addAdditionalFields('notes#', '', True, c_date)
                me.addEntityToMessage(entity)

        #   checking database, passive_whois table
        c.execute(sql2)
        found2 = c.fetchall()
        if found2 is not None:
            for i in range(0, len(found2)):
                domain = found2[i][3]
                scan_date = found2[i][4]
                c_date = found2[i][5]
                registrar = found2[i][6]
                nameServer = found2[i][7]
                email = found2[i][8]
                tel = found2[i][9]
                registrant = found2[i][10]
                #   adding entity email
                if email != '':
                    entity = MaltegoEntity()
                    entity.setType("maltego.EmailAddress")
                    entity.setValue(email)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808000')
                    me.addEntityToMessage(entity)
                #   adding entity registrar
                if registrar != '':
                    entity = MaltegoEntity()
                    entity.setType("ran2.registrar")
                    entity.setValue(registrar)
                    entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808000')
                    entity.addAdditionalFields('notes#', '', True, c_date)
                    me.addEntityToMessage(entity)

    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", "no sample info found ...")

    me.returnOutput()
    conn.commit()
    c.close()


if __name__ == '__main__':
    main()

