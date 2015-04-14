# Introduction #
Advanced Persistent Threat (APT) attacks are highly organised and are launched for prolonged periods. APT attacks exhibit discernible attributes or patterns. In order to maintain the command and control (C2) network redundant, APT attacks are generally embedded with multiple DNS names. An intuitive view is that APT attackers keep and control a high number of DNS-IP address pairs. Most of existing malware attribution works placed great emphasis on grouping the technological or behavioural contexts from the malware binaries.

We studied a small sample of malware from a specific victim group who had been subjected to APT attacks. Our study indicates that the attackers follow some behavioural patterns of registering DNS domains and the frequent use of stable DNS-IP pairs. The gatherings of such evidence from malware binaries are not complicated, but it requires tedious online queries of open source information.

We developed an automated solution to simplify the tasks of collecting and storing the information as a knowledge base for future analysis. Once the initial set of malicious DNS-IP address pair, "parked domain" and "whois information" are identified, the database can be called to perform updates manually. This database can be used for further analysis by visualisation tool, and for identification of the possible identity or personas of the attackers.

In our studies, we used Maltego for the analysis.

# Download #
Google Code no longer supports file downloading. Please visit our Google Drive to download the releases:
http://goo.gl/iPJ0vd

# Documentations #
Please check [ReadMe](ReadMe.md)