#!/usr/bin/env python

# Name: MalProfile/utils/whois.py
# By:   Kenneth Tse
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Utility classes/methods for Whois. Based on Frankie's version
# (obsoleted, use WhoisBase and WhoisGenericRegex)
#

import sys
import whois

class WhoisUtil:
    def __init__(self):
        pass

    @staticmethod
    def retWhois(data):
        try:
            w = whois.whois(data)
            return w
        except:
            w = ''
            return w

    @staticmethod
    def getDate(wdate):
        
        # convert date
        if type(wdate) is list:
            if len(wdate) > 0:
                if type(wdate[0]) == str:
                    cdate = str(wdate[0]).split(" ")[0]
                else:
                    cdate = str(wdate[1]).split(" ")[0]
            else:
                cdate = ''
        else:
            if type(wdate) is str:
                cdate = str(wdate).split(" ")[0]
            else:
                cdate = str(wdate.year)+'-'+str(wdate.month)+'-'+str(wdate.day)
        
        return cdate


    @staticmethod
    def getRegistrar(wname):
        
        if type(wname) is list:
            if len(wname) > 0:
                name = wname[0]
            else:
                name = ''
        else:
            if type(wname) is str:
                name = wname
        
        return name


    @staticmethod
    def getRegistrant(wname):
        
        if type(wname) is list:
            if len(wname) > 0:
                owner = wname[0]
            else:
                owner = ''
        else:
            if type(wname) is str:
                owner = wname
        
        return owner


    @staticmethod
    def getTel(wtel):
        
        if type(wtel) is list:
            if len(wtel) > 0:
                tel = wtel[0]
            else:
                tel = ''
        else:
            if type(wtel) is str:
                tel = wtel
        
        return tel


    @staticmethod
    def getEmails(wemails):
        
        if type(wemails) is list:
            if len(wemails) > 0:
                email = wemails[0]
            else:
                email = ''
        else:
            if type(wemails) is str:
                email = wemails
        
        return email


    @staticmethod
    def getNS(wns):
        
        if type(wns) is list:
            if len(wns) > 0:
                ns = wns[0]
            else:
                ns = ''
        else:
            if type(wns) is str:
                ns = wns
        
        return ns
