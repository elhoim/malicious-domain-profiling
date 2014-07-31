#!/usr/bin/env python

# Name: MalProfile/utils/web.py
# By:   Kenneth Tse
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Utility classes/methods for database acces (SQLite3). Based on Frankie's version
#

import sys
import os
import mechanize

class WebUtil:
    DEFAULT_USER_AGENT = 'Mozilla/5.0 (X11; U; '+\
                      'Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01'
    def init():
        pass

    @staticmethod
    def getPage(url):
        userAgent = [('User-agent', DEFAULT_USER_AGENT)]
        browser = mechanize.Browser()
        browser.addheaders = userAgent
        page = browser.open(url)
        source = page.read()
        
        return source

        
