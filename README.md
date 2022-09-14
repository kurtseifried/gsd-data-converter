# gsd-data-converter

Converts existing GSD files into normalized GSD files in the OSV 1.3.0 content.

Basically we parse data in order of preference and write to the {"gsd":{}} space, if a key exists we don't overwrite it.

Preference order is:

1. {"namespaces": {"mozilla.org": {}}}
2. {"GSD": {}}
3. {"OSV": {}}
4. {"namespaces": {"cve.org": {}}}
5. {"namespaces": {"nvd.nist.gov": {}}}

For the GSD and OSV data we delete any keys for data we use, the namespaces are read only so we leave the data alone. The existing GSD and OSV data is meant to be converted entirely so we delete it as we consume it.

Any remaining GSD and OSV data (e.g. keys we don't use) get written to {"gsd": {"database_specific":{}}} so we can deal with it in future.

There are several common cases for the data we have:

1. GSD data from requests form
2. GSD data and OSV data from the Linux Kernel automation
3. CVE entries in RESERVED state with no additional info
4. CVE entries in RESERVED state with additional info (e.g. Mozilla full data or SUSE reference links)
5. CVE entries in REJECT state 
6. CVE entries with data

# "Up converting" and sanitizing data

## Vendor names

There are many problems with vendor names, here are some exmaples, with example data (not complete, there are many more):

A good example is Red Hat, we have:

* "RED HAT"
* "Red Hat "
* "Red Hat Satellite 6"
* "Red Hat"
* "Red Hat, Inc."
* "RedHat"
* "Redhat"
* "[Red Hat]"
* "redhat"
* "redhat-certification"

Solution: Manually add to lookup table and normalize 

Also we have a lot of unknown data:

* 134759 "n/a"
* 240 "[UNKNOWN]"
* 175 ""

Solution: set to "" for unknown

Also escaping quotes, tabs, etc.:

* "Inc.\""
* "LTD.\""
* "\t ALLNET Gmbh"
* "\tfancy-product-designer"

Solution: Manually add to lookup table and normalize or set to "" for unknown

Leading spaces and trailing spaces:

* " AIFU Information Technology Co."
* " Fuji Electric"
* " Indeed Job Importer "
* " Notices "
* " SP Rental Manager "
* " ebics-java"
* " job-portal "

Solution: delete leading and trailing spaces

URL's in the name or just a url:

* "Kiboko Labs https://calendarscripts.info/"
* "https://github.com/microlinkhq"
* "https://github.com/sabelnikov"
* "https://github.com/vvo"

Solution: officially allow URLs? These are discoverable and unique

## Product names

Leading spaces and trailing spaces:
Solution: delete leading and trailing spaces

Leading and trailing quotes
Solution: delete leading and trailing quotes
NOTE: leave " in middle as it may indicate size in inches of e.g. TV product affected

We should probably remove the leading vendor name from product names, but many products include vendor names, e.g. "Sony Bravo". I know the old CVE data has "Adobe Acrobat" and the newer data has "Acrobat" for example. I think we should leave product name alone for now, and only fix obvious problems like extra spaces.

## Affected versions

Lots of unknown:

* 124944 "n/a"
* 29749 ""
* 1687 "None"

Lots of multiple affected and ranges:
* "All versions >= V2.3 and < V6.30.016"
* "Adobe Acrobat and Reader 2018.011.20040 and earlier, 2017.011.30080 and earlier, and 2015.006.30418 and earlier versions"
* "Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9"
* "2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier, and 2015.006.30523 and earlier versions"

Solution: We need to collect data and figure out ways to split up these, e.g. search for "multiple instanced of "and earlier"" or "look for >", I suspect looking for longer strings will be asimple way to find the problem cases (e.g. one line is 1228 characters long). Also commas followed by spaces.


