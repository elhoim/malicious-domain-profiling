#!/usr/bin/env python

# Name: MalProfile/utils/db.py
# By:   Kenneth Tse
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Utility classes/methods for database acces (SQLite3). Based on Frankie's version
#

import sys
import os
import datetime
import sqlite3
import ConfigParser

class DBUtil:
    S_DATE = ''
    DBNAME = ''

    def __init__(self):
        S_DATE = str(datetime.datetime.now()).split(" ")[0]
        try:
            config_ini = "MalProfile.ini"
            config = ConfigParser.ConfigParser()
            config.read(config_ini)
            self.DBNAME = config.get("MalProfile", "DBNAME")
        except:
            print("Error reading config file: " + config_ini + "!")
            sys.exit()        
        pass

    @classmethod
    def init(cls):
        try:
            config_ini = "MalProfile.ini"
            config = ConfigParser.ConfigParser()
            config.read(config_ini)
            cls.DBNAME = config.get("MalProfile", "DBNAME")
        except:
            print("Error reading config file: " + config_ini + "!")
            sys.exit()        

        if os.path.isfile(cls.DBNAME):
            print "Database File found, no creation is required."
            return

        #   open database and create a cursor object
        conn = sqlite3.connect(cls.DBNAME)
        conn.text_factory = str
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE c2 (id INTEGER PRIMARY KEY, sid NUM, scan_date TEXT, dns TEXT, ip_addr TEXT);
            CREATE TABLE detects (id INTEGER PRIMARY KEY, sid NUMERIC, vendor TEXT, result TEXT);
            CREATE TABLE domains (id INTEGER PRIMARY KEY, sid NUMERIC, source TEXT, scan_date TEXT, domain TEXT, Cname TEXT);
            CREATE TABLE f_c2 (id INTEGER PRIMARY KEY, sid NUM, source TEXT, scan_date TEXT, ip_addr TEXT);
            CREATE TABLE ip (id INTEGER PRIMARY KEY, sid NUM, source TEXT, scan_date TEXT, resolve_date TEXT, ip_addr TEXT);
            CREATE TABLE owner (id INTEGER PRIMARY KEY, scan_date TEXT, domain TEXT, registrant TEXT);
            CREATE TABLE passive_dns (id INTEGER PRIMARY KEY, sid NUM, source TEXT, scan_date TEXT, resolve_date TEXT, dns TEXT, A_record TEXT, domain TEXT);
            CREATE TABLE passive_domains (id INTEGER PRIMARY KEY, sid NUM, source TEXT, scan_date TEXT, domain TEXT, Cname TEXT);
            CREATE TABLE passive_ip (id INTEGER PRIMARY KEY, sid NUM, source TEXT, scan_date TEXT, resolve_date TEXT, ip_addr TEXT);
            CREATE TABLE passive_whois (id INTEGER PRIMARY KEY, sid NUMERIC, source TEXT, domain TEXT, scan_date TEXT, c_date TEXT, registrar TEXT, nameServer TEXT, email TEXT, tel TEXT, registrant TEXT);
            CREATE TABLE samples (id INTEGER PRIMARY KEY, md5 TEXT, name TEXT, date TEXT);
            CREATE TABLE whois (id INTEGER PRIMARY KEY, sid NUMERIC, source TEXT, domain TEXT, scan_date TEXT, c_date TEXT, registrar TEXT, nameServer TEXT, email TEXT, tel TEXT, registrant TEXT);
            """)
        c.close()

        if os.path.isfile(cls.DBNAME):
            print "Success."
        else:
            print "Failed."

