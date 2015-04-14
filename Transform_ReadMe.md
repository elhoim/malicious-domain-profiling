# Transformation #

How Maltego LocalTransform is queried intelligence from db?

  * `mGetAllSamples.py` (input:SampleDB) to display all samples in Maltego (from:samples)
  * `mSampleToDNS.py` (input:Sample) to display dns, ip, exploits (from:c2, samples & detects)
  * `mDnsToIP.py` (input:DNS Name) to display c2Address (from:c2, passive\_dns)
  * `mIPtoDomains.py` (input:IPv4 Address) to display c2\_domains (from:ip & passive\_domains)
  * `mDomainToWhois.py` (input:Domain) to display whois (from:domains & passive\_domains?)
  * `mfromOwner.py` (input:registrant) to display whois (from:whois & passive\_whois)
  * `mfromEmail.py` (input: Email Address) to display whois (from:whois & passive\_whois)
  * `mfromLikeEmail.py` (input: Email Address) to display whois (from:whois & passive\_whois)
  * `mfromLikeIP.py` (input: IPv4 Address) to display IP addresses within same c-class IP (from: ip)

## Installation ##
  1. Copy `MaltegoTransform.py` to MalProfile folder
  1. Copy `mSampleToDNS.py`, `mDnsToIP.py`, `mIPtoDomains.py`, `mDomainsToWhois.py`, `mGetAllSamples.py`, `mfromEmail.py`, `mfromLikeEmail.py`, `mfromOwner.py` to `/root/MalProfile/Maltego` folder
  1. Add the path of `/root/MalProfile`, `/root/MalProfile/Maltego` by: `PATH=/root/MalProfile:/root/MalProfile/Maltego:$PATH`.  (test by: `echo $PATH`)
  1. Configure MalProfile.ini (make sure DBNAME contains your database (e.g. c2\_PittyTiger.db)
  1. Test Maltego Local Transform. (e.g. `mSampleDNS.py <sample_name>`)
  1. Create new Local Transform in Maltego (Refer to dump screens in [Transform\_ReadMe](Transform_ReadMe.md) for detail parameters)
    1. Import new entities `MalProfile/Maltego/MyEntities.mtz`
    1. Create new Transform Sets called MalProfile
    1. Create new LocalTransforms:
      * Sample -> `mSampleToDNS.py`
      * DNS Name -> `mDnsToIP.py`
      * c2\_address -> `mIPtoDomains.py`
      * Domain -> `mDomainToWhois.py`
      * SamplesDB -> `mGetAllSamples.py`
      * Email Address -> `mfromEmail.py` or `mfromLikeEmail.py`
      * registrant -> `mfromOwner.py`
    1. Drag a SampleDB and name it as `<database_name>` at Properties(Description)
    1. Test check SampleDB by `MalProfile->mGetAllSamples` Transform

## How-To ##

Please refer to [Transform\_HowTo](Transform_HowTo.md)