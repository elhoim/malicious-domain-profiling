#!/usr/bin/env python

# Name: MalProfile/utils/whoisGenericRegix.py
# By:   Kenneth Tse, Eric Yuen, Frankie
# Version Date: Jul 4, 2014, Jul 27, 2014
# For:  utilities module
# 
# Implemented WhoisBase - using Regex to parse who.is output as example
#

import sys
import abc
import httplib
import re
from cStringIO import StringIO
from whoisBase import WhoisBase

class WhoisGenericRegex(WhoisBase):
# Implementating WhoisBase abc through subclassing

    # Variable defined in WhoisBase class
    _domain = ' '
    _createdate = ''
    _registrar = ''
    _registrant = ''
    _tel = ''
    _email = ''
    _address = ''
    _ns = ''
    
    # Variable specific to this class implementation
    _updatedate = ''
    _w = None

    def query(self, domain, content):
        try:
            _w = self.whois(self, domain)
            #print "Finish http request"
            self.parseWebData(self, content)
            _w.close()
        except:
            _w = None
    
    @staticmethod
    def whois(self, domain):
        url = "/whois/" + domain
        conn = httplib.HTTPConnection("who.is")
        conn.request("GET",url)
        res = conn.getresponse()
        conn.close()
        htmlcontent = StringIO()
        htmlcontent.write(res.read())
        return htmlcontent
    
    @staticmethod
    def parseWebData(self, content):
        self._domain = self.parseGeneric(self, content, "Domain Name:\s*(.+)|Domain name:\\n\s*([\w|\d]+.[\w|\d]+.[\w|\d]+)")
        self._registrar = self.parseGeneric(self, content, "Registrar:\s*(.+)|Registrar Name:\s?(.+)|Registrar:\\n\s*([\w|+\d|\s|\&|\[|\=|\]]+)|Registration Service Provider: \s*(.+)")
        self._registrant = self.parseGeneric(self, content, "Registrant Name:\s*(.+)|REGISTRANT CONTACT INFO\n\s?(.+)|Registrant:\n\s?(.+)|Registrant Contact:\n\s?(.+)|Registrant Name .................\s?(.+)|Registrant Contact Details:\n\s?(.+)|admin-contact:\s?(.+)|Given name:\s?(.+)|Registrant:\\n\s*([\w|\d|\s]+)|Registrant:\\n\s*(.+)")
        self._ns = self.parseGeneric(self, content, "Name Server:\s*(.+)|Name servers:\s*\\n\s*([\w|\d]+.[\w|\d]+.[\w|\d]+)|Name Servers Information:\\n\\n([\w|\d]+.[\w|\d]+.[\w|\d]+)|Nameservers:(.+)|Domain servers in listed order:\\n\s*(.+)")
        self._tel = self.parseGeneric(self, content, "[\+]\d*[\.-][\d.]*|[\+]\d*\s\d*\s\d*")
        self._email = self.parseGeneric(self, content, "[\w.-]+@[\w.-]+\.[\w]{2,4}|[\w.-]+@[\w.-]+\.[\w]{2,4}\.[\w]{2,4}")
        self._createdate = self.parseGeneric(self, content, "Creation Date:\s*(.+)|Domain Name Commencement Date:\s?(.+)|Registered on:\s*([\w|\d]+.[\w|\d]+.[\w|\d]+)|Domain Create Date:(.+)|Registration Date:\s*(.+)|Record created on\s*(.+)")
        self._updatedate = self.parseGeneric(self, content, "Updated Date:\s*(.+)")
        return
    
    @staticmethod
    def parseDate(self, content, dateOption = ''):
        re_creationDate = re.compile("Creation\sDate\:\s(?P<createDate>.*?)\<br\>")
        re_updateDate = re.compile("Updated\sDate\:\s(?P<updateDate>.*?)\<br\>")
        content.seek(0)
        _c = content.read()
        if dateOption in ('c', ''):
            match = re_creationDate.search(_c, re.M)
            if match:
                return match.group("createDate")
        if dateOption == 'u':
            match = re_updateDate.search(_c, re.M)
            if match:
                return match.group("updateDate")
        return ''
    
    @staticmethod
    def parseGeneric(self, content, regex):
        re_generic = re.compile(regex)
        match = re_generic.search(content, re.M)
        if match.lastindex == None:
            return match.group(0)
        else:
            return match.group(match.lastindex)

    
    @property   
    def updatedate(self):
        return self._updatedate
    
    @updatedate.setter
    def updatedate(self, newDate):
        self._updatedate = newDate

    # Below variable is defined in base class whoisBase
    @property
    def domain(self):
        return self._domain
    
    @domain.setter
    def domain(self, newDomain):
        self._domain = newDomain

    @property
    def createdate(self):
        return self._createdate
    
    @createdate.setter
    def createdate(self, newDate):
        self._createdate = newDate

    @property
    def registrar(self):
        return self._registrar
    
    @registrar.setter
    def registrar(self, newRegistrar):
        self._registrar = newRegistrar
        
    @property
    def registrant(self):
        return self._registrant
    
    @registrant.setter
    def registrant(self, newRegistrant):
        self._registrant = newRegistrant

    @property
    def tel(self):
        return self._tel
    
    @tel.setter
    def tel(self, newTel):
        self._tel = newTel

    @property
    def ns(self):
        return self._ns
    
    @property
    def email(self):
        return self._email
    
    @email.setter
    def email(self, newEmail):
        self._email = newEmail
