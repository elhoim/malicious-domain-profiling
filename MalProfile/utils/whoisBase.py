#!/usr/bin/env python

# Name: MalProfile/utils/whoisBase.py
# By:   Kenneth Tse, Eric Yuen
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Base class for Whois
#

import sys
import abc

class WhoisBase:
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    @abc.abstractmethod
    def query(self, domain, w):
        """ Should be implemented by subclass to retrieve whois result and parse
        and parse the result if neccessary """
        pass

    @abc.abstractproperty
    def domain(self):
        return
        
    @domain.setter
    def domain(self, newDomain):
        return

    @abc.abstractproperty
    def createdate(self):
        return
        
    @createdate.setter
    def createdate(self, newDate):
        return
    
    @abc.abstractproperty
    def registrar(self):
        return
    
    @registrar.setter
    def registrar(self, newRegistrar):
        return

    @abc.abstractproperty
    def registrant(self):
        return
    
    @registrant.setter
    def registrant(self, newRegistrant):
        return

    @abc.abstractproperty
    def tel(self):
        return
    
    @tel.setter
    def tel(self, newTel):
        return

    @abc.abstractproperty
    def email(self):
        return
    
    @email.setter
    def email(self, newEmail):
        return
