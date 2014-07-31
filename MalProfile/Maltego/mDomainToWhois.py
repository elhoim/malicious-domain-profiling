#!/usr/bin/python
# Name: mDomainToWhois.py
# By:   Frankie Li
# Created:  Feb 5, 2014
# Modified: Jul 7, 2014
# For:  Generate maltego scripts to plot Whois
#       from malicious c2 domains supplied
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
            domain = input[1]
        else:
            domain = input[0]

    #   checking database, domain table
    c.execute("SELECT * FROM domains where domain=?", ((domain),))
    found = c.fetchone()
    if found is not None:
        sid = found[0]
        #   checking database, whois
        c.execute("SELECT * FROM whois where sid=? and source='domains'", ((sid),))
        found1 = c.fetchall()
        #print "records =" + str(len(found1))
        if found1 is not None:
            for i in range(0, len(found1)):
                scan_date = found1[i][4]
                c_date = found1[i][5]
                registrar = found1[i][6]
                nameServer = found1[i][7]
                email = found1[i][8]
                tel = found1[i][9]
                registrant = found1[i][10]
                #   adding entity registrant
                if registrant != '':
                    entity = MaltegoEntity()
                    entity.setType("ran2.registrant")
                    entity.setValue(registrant)
                    entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
                    entity.addAdditionalFields('notes#', '', True, tel)
                    me.addEntityToMessage(entity)
                #   adding entity email
                if email != '':
                    entity = MaltegoEntity()
                    entity.setType("maltego.EmailAddress")
                    entity.setValue(email)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0xFF0000')
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
                #   adding entity nameServer
                if nameServer != '':
                    entity = MaltegoEntity()
                    entity.setType("maltego.NSRecord")
                    entity.setValue(nameServer)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x808080')
                    me.addEntityToMessage(entity)

    else:
        #print "Collecting intelligence from the Internet ..."
        me.addEntity("maltego.Phrase", "no sample info found ...")


    #   checking database, passive_domain table
    c.execute("SELECT * FROM passive_domains where domain=?", ((domain),))
    found = c.fetchone()
    if found is not None:
        sid = found[0]
        
        #   checking database, passive_whois
        c.execute("SELECT * FROM passive_whois where sid=? and source='passive_domains'", ((sid),))
        found1 = c.fetchall()
        #print "records =" + str(len(found1))
        if found1 is not None:
            for i in range(0, len(found1)):
                scan_date = found1[i][4]
                c_date = found1[i][5]
                registrar = found1[i][6]
                nameServer = found1[i][7]
                email = found1[i][8]
                tel = found1[i][9]
                registrant = found1[i][10]
                #   adding entity registrant
                if registrant != '':
                    entity = MaltegoEntity()
                    entity.setType("ran2.registrant")
                    entity.setValue(registrant)
                    entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x0000FF')
                    entity.addAdditionalFields('notes#', '', True, tel)
                    me.addEntityToMessage(entity)
                #   adding entity email
                if email != '':
                    entity = MaltegoEntity()
                    entity.setType("maltego.EmailAddress")
                    entity.setValue(email)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x0000FF')
                    me.addEntityToMessage(entity)
                #   adding entity registrar
                if registrar != '':
                    entity = MaltegoEntity()
                    entity.setType("ran2.registrar")
                    entity.setValue(registrar)
                    entity.addAdditionalFields('link#maltego.link.label', '', True, scan_date)
                    entity.addAdditionalFields('link#maltego.link.color', '', True, '0x0000FF')
                    entity.addAdditionalFields('notes#', '', True, c_date)
                    me.addEntityToMessage(entity)
                #   adding entity nameServer
                if nameServer != '':
                    entity = MaltegoEntity()
                    entity.setType("maltego.NSRecord")
                    entity.setValue(nameServer)
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

