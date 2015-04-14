# Database #

How MalProfile database is kept?

Intelligences gathered from various sources and databases are captured in the following ways:

If samples [md5 hash](or.md) are available:
  1. Put them inside the subdirectory ./files
  1. By using behavioural analysis or upload it to a sandbox, the DNSs (hostnames) are extracted
  1. `MalProfile.py -f <filename> -d <dns_name> [-md5 <hash>]` will update a chain of tables
  1. Tables updated: samples, detects, c2, ip, passive\_dns, passive\_ip, domains & whois

If samples are not available:
  1. The samples and c2 tables are manually updated
  1. `MalProfile.py -c` will update a chain of tables
  1. Tables updated: ip, passive\_dns, passive\_ip, domains & whois

If suspicious ip\_addr is identified (ip\_addr of same C-class subnet):
  1. f\_ip ("friendly\_ip") table is manually updated
  1. `MalProfile.py -p` will update ip table from sources originated from: f\_c2, passive\_dns, passive\_ip

If ip table is updated (because new â€˜parked-domainsâ€™ are identified):
  1. If the ip\_addr are originated from "c2" (definitive malicious)
  1. `MalProfile.py -q` will update a 2 tables
  1. Tables updated: domains & whois tables

If ip table is updated (because passive\_dns are identified):
  1. `MalProfile.py -s` will update passive\_domains from source originated from: f\_c2, passive\_dns, passive\_ip
  1. `MalProfile.py -x` will update passive\_whois from passive\_domains
  1. option -s and -x options are divided because "parked-domains" may hanged because of bulk query issue
  1. Table updated: passive\_domains (by -s) and/or passive\_whois (by -x)

If suspicious registrant is identified:
  1. Owner table is manually updated (can automated domaintools' reverse-whois)
  1. `MalProfile.py -o` will update a chain of tables
  1. Table updated: domains and whois + passive\_ip

If domains are parked to another suspicious ip (pull out from a pool for actual use in an attack):
  1. `MalProfile.py -r` will update passive\_ip
  1. Table updated: passive\_ip

Two new functions are added (Jul 30)
  1. Adding domain part of a malicious dns from c2 to domains table
  1. `MalProfile.py -t` will update domains table

# Example #
Hence, to grab intelligence from the open source, the script may be executed in these orders:
  1. `MalProfile.py -f -d [-md5]`(if samples are available)
  1. `MalProfile.py -c` (if samples are not available)
  1. `MalProfile.py -p`, then `-q`, `-s` and `-x` (if f\_c2, passive\_ip or passive\_dns is updated)
  1. `MalProfile.py -o`, then `-r` (if owner is updated)
  1. `MalProfile.py -t` (if sample is uploaded to VirusTotal)