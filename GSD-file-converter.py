#!/usr/bin/env python3

import sys
import os
import json
import re
import datetime

#####################################################################################################

# This script assumes the input file is mostly clean 
# but by definition stuff won't pass schema checks, that's the point of this converter
# Read file and close.
# Parse file, indent, overwrite file
# So simple, see?

#####################################################################################################

# schema_version field 
# schema_version: "1.3.0"
# DONE GLOBALLY

# id, modified fields
# id: GSD
# modified: time(now)
# DONE GLOBALLY

# published field
# published publishedDate (GSD, then NVD)

# withdrawn field
# if REJECT insert end of year date, check NVD for something?
# ["description"]["description_data"][0]["value"]: "** REJECT ** "


# aliases field
# CVE if any, longer term populate with Linux aliases, etc.

# related field
# IGNORE for now

# summary, details fields
# Description basicly

# severity field
######################################
# severity[].type field
# severity[].score field
# Populate with CVSS_V2/CVSS_V3 string if exists in NVD data

# affected fields
######################################
# affected[].package field
# affected[].versions field
# affected[].ranges[] field
# affected[].ranges[].type field
# affected[].ranges[].events fields
# affected[].ranges[].repo field
# affected[].ranges[].database_specific field
# affected[].ecosystem_specific field
# affected[].database_specific field

# We need to walk the CVE/NVD data and also ensure that e.g. vendor is set, then product, then version, are any missing higher level data?

# references field
# Convert all existing references as "dumb" for now, map types later.

# credits fields
######################################
# credits[].name field
# credits[].contact[] field

# database_specific field


#####################################################################################################

def getJSONFromFile(pathname):
    with open(pathname, "r") as f:
        file_data = json.load(f)
        return(file_data)


# Read the ~/.gsdconfig file, e.g.:
#{
#	"gsd_database_path": "/home/kurt/GitHub/gsd-database/",
#	"gsd_tools_path": "/home/kurt/GitHub/gsd-tools/"
#}
def setgsdconfigGlobals():
    # Set gsdconfig globals like pathnames
    # TODO: check for trailing slash at some point
    user_homedir_path = os.path.expanduser('~')
    gsdconfig_path = user_homedir_path + "/.gsdconfig"
    global gsd_database_path
    global gsd_tools_path
    if os.path.exists(gsdconfig_path): 
        with open(gsdconfig_path, "r") as f:
            gsdconfig_data = json.load(f)
        gsd_database_path = gsdconfig_data["gsd_database_path"]
        gsd_tools_path = gsdconfig_data["gsd_tools_path"]
    else:
        print("no ~/.gsdconfig file set, please create one, see comments in this script for details")
        exit()

# Take the command line argument and figure out if it's a GSD/CVE/file path, and convert to a file path
# Valid arguments are:
# CVE-YEAR-INTEGER
# GSD-YEAR-INTEGER
# ./YEAR/INTxxx/GSD-YEAH-INTEGER.json
#
# Output is a global file path or exit if error

def convertArgumentToPath(argv1):
    if re.match("^CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*$", argv1):
        argv1 = re.sub("^CVE-", "GSD-", argv1)
    if re.match("^GSD-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*$", argv1):
        gsd_id_data = argv1.split("-")
        year = gsd_id_data[1]
        integer = gsd_id_data[2]
        integerdir = re.sub("[0-9][0-9][0-9]$", "xxx", integer)
        argv1 = "./" + year + "/" + integerdir + "/" + argv1 + ".json"
        # Convert to partial path
    if re.match("^\./[0-9][0-9][0-9][0-9]/[0-9]*xxx/GSD-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*.json", argv1):
        argv1 = re.sub("^\./", gsd_database_path, argv1)
    global gsd_file_path
    gsd_file_path = argv1


# All parse functions return a chunk of gsd:{} formatted data

# A second function then tries to write things to gsd:{} and either writes a new key, 
# or if exists writes the leftovers (GSD/OSV) to gsd:database_specific:NAME

#def parseNamespaces_mozillaorg(data):


#def parseGSD()

#def parseOSV()

#def parseNamespaces_cveorg():

#def parseNamespaces_nvd.nist.gov():

def determineCVEDataType(data):
    # Check CVE, return version, state
    CVEData_Version = data["data_version"]
    # Not all CVE data contains state, e.g. mozilla.org, but most people that public CVE data only public PUBLIC data
    if "CVE_data_meta" in data:
        if "STATE" in data["CVE_data_meta"]:
            CVEData_State = data["CVE_data_meta"]["STATE"]
        else:
            CVEData_State = "PUBLIC"
    return(CVEData_Version, CVEData_State)


def parseCVEv40PUBLIC(data):
    # Check for key, write to gsd:{} if not exist:
    if "description" in data:
        for entry in data["description"]["description_data"]:
            # No need to check language, only english is used. But what to do with multiple entries???
            # What happens if multiple entries? write as blocks I guess? How do we zero it out and not clobber the original?
            # Should we just do this via the API?
             
            if "summary" not in JSON_gsd:
                JSON_gsd["summary"] = entry["value"]
            if "details" not in JSON_gsd:
                JSON_gsd["details"] = entry["value"]
    if "references" in data:
        print("references")
    if "affects" in data:
        print("affects")
    if "problemtype" in data:
        print("problemtype")


#def writekeytogsd(GSD_file_data, new_data, keyname):
# basically try to write keys from new_data into GSD_file_data, if they exist don't overwrite
# write ALL the existing GSD/OSV data into alternate database when done, we'll delete it later.


if __name__ == "__main__":

    setgsdconfigGlobals()
    # gsd_database_path
    # gsd_tools_path

    convertArgumentToPath(sys.argv[1])
    # gsd_file_path

    # Reminder: this needs to be global if it gets moved into a function
    global GSD_file_data
    GSD_file_data = getJSONFromFile(gsd_file_path)


    # Check if gsd (lowercase) exists (has this file already been converted? partially?)
    global JSON_gsd
    if "gsd" in GSD_file_data:
        JSON_gsd = GSD_file_data["gsd"]
        print("Found gsd")
    else:
        JSON_gsd = {}

    if "schema_version" not in JSON_gsd:
        JSON_gsd["schema_version"] = "1.3.0"

    if "id" not in JSON_gsd:
        GSD_id = re.sub("^.*/", "", gsd_file_path)
        GSD_id = re.sub("\.json$", "", GSD_id)
        JSON_gsd["id"] = GSD_id
    
    if "modified" not in JSON_gsd:
        rfc3339time = datetime.datetime.utcnow()
        modified = rfc3339time.isoformat("T") + "Z"
        JSON_gsd["modified"] = modified
    

    # First we do vendors with authoritative information: (read only)
    if "namespaces" in GSD_file_data:
        if "mozilla.org" in GSD_file_data["namespaces"]:
            JSON_mozillaorg = GSD_file_data["namespaces"]["mozilla.org"]
            CVE_version, CVE_state  = determineCVEDataType(JSON_mozillaorg)
            if CVE_version == "4.0" and CVE_state == "PUBLIC":
                parseCVEv40PUBLIC(JSON_mozillaorg)

            print("Found Mozilla")

    # Second we do GSD data: (write leftovers to gsd:database_specific:GSD)
    if "GSD" in GSD_file_data:
        JSON_GSD = GSD_file_data["GSD"]
        del GSD_file_data["GSD"]
        print("Found GSD")
        

    # Third we do OSV data: (write leftovers to gsd:database_specific:OSV)
    if "OSV" in GSD_file_data:
        JSON_OSV = GSD_file_data["OSV"]
        del GSD_file_data["OSV"]
        print("Found OSV")

    # Fourth we do cve.org data and then nvd.nist.gov data: (read only)
    if "namespaces" in GSD_file_data:
        if "cve.org" in GSD_file_data["namespaces"]:
            JSON_cveorg = GSD_file_data["namespaces"]["cve.org"]
            print("Found cve.org")
        if "nvd.nist.gov" in GSD_file_data["namespaces"]:
            JSON_nvdnistgov = GSD_file_data["namespaces"]["nvd.nist.gov"]
            print("Found nvd.nist.gov")   

    print(JSON_gsd)