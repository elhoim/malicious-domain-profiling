## README.txt
## for MalProfile (version 1.0.0-beta)

CONTENTS OF THIS FILE
---------------------

(1) Introduction
(2) History
(3) Requirements
(4) Package Files
(5) Installation
(6) Configuration
(7) Usage
(8) License
(9) Maintainers


(1) INTRODUCTION
----------------

MalProfile is a set of tools to:

i. Fetch useful data from different sources include malware samples, suspicious IP/Domain being used, passive DNS records, md5 hash and save to a database at different time slot for behaviour and/or timeline analysis
ii. Present in Maltego the relationship of malware, current and passive domain/IP/Email/Telephone etc to get the origin of the source. And elaborate the relationship to get suspected IP/Domain for proactive prevention and detection. 


(2) HISTORY
-----------

Please refer to CHANGELOG.txt


(3) REQUIREMENTS
----------------

i.	Kali Linux 1.0.7 or later (for illustration purpose only, for advance users, just use the tool per your preference, in my case, I install it on my Mac)
ii.	Maltego Edition 3.4.0 or later (If community version is used, only 12 records will be randomly displayed)
iii.	Virustotal registration and API key
iv.	Maltego Basic Python Library - https://www.paterva.com/web6/documentation/developer-local.php
 
(Other system with Python 2.7 and Maltego may work but never tried :) )


(4) PACKAGE FILES
-----------------

The following files are included in the MalProfile package.

MalProfile/MalProfile.py			# MalProfile main script
MalProfile/MalProfile.ini			# MalProfile configuration file
MalProfile/README.txt            		# this file
MalProfile/c2_PittyTiger			# Sample database file (not included in the code email ran2@vxrl.org)
MalProfile/c2_Xsecu				# Sample database file (not included in the code email ran2@vxrl.org)
MalProfile/Maltego/MyEntities.mtz    		# Maltego Input Entities
MalProfile/Maltego/*				# Maltego Transform scripts, Refer to ReadMe/Transform_Readme for more info
MalProfile/Utils/*				# Libraries and plugins for MalProfile
ReadMe/*					# Documentation of MalProfile design and usage
Samples/*					# Samples for demonstration (not included in the code email ran2@vxrl.org)


(5) INSTALLATION
----------------

MalProfile script:
1.	unzip the MalProfile.zip to /Root/MalProfile
2.	apt-get install python-setuptools
3.	easy_install pip
4.	pip install python-whois
5.	pip install hashlib
6.	pip install mechanize
7.	pip install ConfigParser
8.	pip install python-nmap
9.	copy ./ReadMe/PyWhois/parser.py to /usr/local/lib/python2.7/dist-packages/whois/
10.	unzip MaltegoTransform-Python and copy MaltegoTransform.py to MalProfile directory 


(6) CONFIGURATION
-----------------

MalProfile script:
i.	edit the MalProfile.ini file and fill in the DBNAME (Database file path) and VT_APIKEY (Virustotal API key)
ii. If you have an APT sample, put it in the ./files subdirectory (take risk to put unzipped APT sample here)


Maltego transforms (refer to screenshot for more details):
i.	import the input entities MyEntities through manage -> import entities
ii.	create transform sets through manage -> manage transform -> Transform Sets -> Create "MalProfile"
iii.	create local transform for each Maltego Transform script,input entity base on package file description
iv.	command fill in the full filename with path, working directory /root/MalProfile
v.	create a new maltego graph, add a SampleDB object, change the properties to database filename and have fun! :)

	
(7) USAGE
---------

i.	Change to directory /Root/MalProfile
ii.	Run the script ./MalProfile.py 

Usage: MalProfile.py [options]

Options:
  -h, --help   show this help message and exit
  -i           initialize c2 database [c2_dev.db]
  -f FILENAME  Provide a FILENAME of the sample to check
  --md5=MD5    Provide a MD5 of the sample to check
  -d DNS       Provide a DNSNAME to check
  -c           rescanning c2 to update all subsequent tables
  -o           rescanning owner table to update all subsequent tables
  -p           rescanning passive tables to update ip table
  -q           rescanning ip table to update domains & whois tables
  -r           rescanning domains table to update passive_ip table
  -s           rescanning ip table to update passive_domains & passive_whois tables
  -t           rescanning and update domains table from malicious hostnames
               from c2
  -w           rescanning and update domains table to update whois
  -x           rescanning and update whois table from passive_whois
Usage: MalProfile.py [options]

For different usage scenario:
	1. Check db_ReadMe.txt to understand how to grab intelligence with different known sources
	2. Check Transform_ReadMe to understand which Maltego Transform is available to analysis collected intelligence
	3. Check Installation_ReadMe if you need help to setup MaltegoTransform (note: Community ver only display 12 items)
	4. Check PittyTiger_ReadMe if you want to test a sample


(8) LICENSE
-----------
Copyright (C) 2014 Malware Domain Profiling Research Team

MalProfile is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.

MalProfile is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <http://www.gnu.org/licenses/>.


(9) CONTRIBUTORS
----------------

Current contributors:
* Frankie Li
* Kenneth Tse

Date: 31st Jul 2014

-----------------
End of README.txt
-----------------