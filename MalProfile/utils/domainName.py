#!/usr/bin/env python

# Name: MalProfile/utils/domainName.py
# By:   Kenneth Tse
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Utility classes/methods for DNS. Based on Frankie's version
#

import sys 
import dns.resolver
import mechanize
import re

class DNSUtil:
    def __init__(self):
        pass

    @staticmethod
    def retIP(data):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            answers = resolver.query(data)
            ip_addr = str(answers[0]).split(": ")[0]
            c_name = answers.canonical_name
            return ip_addr
        except:
            ip_addr = ''
            return ip_addr

    @staticmethod
    def chkIPAddr(ip):
        parts = ip.split('.')
        return (
                len(parts) == 4
                and all(part.isdigit() for part in parts)
                and all(0 <= int(part) <= 255 for part in parts)
                )

    @staticmethod
    def retCName(data):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            answers = resolver.query(data)
            c_name = answers.canonical_name
            name = c_name[0] +'.'+ c_name[1] + '.'+ c_name[2]
            return name
        except:
            name = ''
            return name

    @staticmethod
    def retDomain(ip_addr, d):
        try:
            url = "http://bgp.he.net/ip/" + ip_addr+ "#_dns"
            userAgent = [('User-agent','Mozilla/5.0 (X11; U; '+\
                          'Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01')]
            browser = mechanize.Browser()
            browser.addheaders = userAgent
            page = browser.open(url)
            html = page.read()
            link_finder = re.compile('href="(.*?)"')
            links = link_finder.findall(html)
            for i in range (0, len(links)):
                if links[i].find('/dns/') == 0:
                    d.append(links[i][5:])
            return d
        except:
            return d
