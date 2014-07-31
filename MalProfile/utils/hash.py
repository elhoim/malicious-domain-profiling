#!/usr/bin/env python

# Name: MalProfile/utils/hash.py
# By:   Kenneth Tse
# Version Date: Jul 4, 2014
# For:  utilities module
# 
# Utility classes/methods for database acces (SQLite3). Based on Frankie's version
#

import sys
import os
import hashlib

class HashUtil:
    def init():
        pass

    @staticmethod
    def md5sum(data):
        m = md5()
        m.update(data)
        return ({'name': 'md5', 'result': m.hexdigest()})
