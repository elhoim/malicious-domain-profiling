# PittyTiger #

Testing manually extracted data from PittyTiger Report. Please send `ran2@vxrl.org` for a `PittyTiger.db` for sample test of the tool.

## Sample usage ##

  1. Manual updated the database by extracting relevant data from PittyTiger Report by Airbus
  1. `MalProfile.py -c` to rescan all tables starting from c2 [table](table.md)
  1. `MalProfile.py -p` to update ip table from identified passive\_ip and passive\_dns
  1. `MalProfile.py -q` to update domains & whois tables from ip [table](table.md)
  1. `MalProfile.py -s` to update passive\_domain & passive\_whois tables from ip [table](table.md)
  1. `MalProfile.py -t` to update domains table from the domain part from dns contained in c2 tables
  1. `MalProfile.py -p` to re-run update ip from passiveDNS
  1. `MalProfile.py -q` to re-run update domains & passive\_domain, whois & passive\_whois tables