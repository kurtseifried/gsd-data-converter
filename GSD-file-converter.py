#!/usr/bin/env python3

import sys
import os
import json
import re

# This script assumes the input file is mostly clean 
# but by definition stuff won't pass schema checks, that's the point of this converter
# Read file and close.
# Parse file, indent, overwrite file
# So simple, see?

def getJSONFromFile(pathname):
    with open(pathname, "r") as f:
        file_data = json.load(f)
        return(file_data)


# Read the ~/.gsdconfig file, e.g.:
#{
#	"gsd_databas_path": "/home/kurt/GitHub/gsd-database/",
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

#def writekeytogsd(GSD_file_data, new_data, keyname):
# basically try to write keys from new_data into GSD_file_data, if they exist don't overwrite
# if keyname is GSD/OSV then write the leftovers?
# Writes the key if not exists


if __name__ == "__main__":

    setgsdconfigGlobals()
    # gsd_database_path
    # gsd_tools_path

    convertArgumentToPath(sys.argv[1])
    # gsd_file_path

    GSD_file_data = getJSONFromFile(gsd_file_path)

    # Check if gsd (lowercase) exists (has this file already been converted? partially?)
    if "gsd" in GSD_file_data:
        JSON_gsd = GSD_file_data["gsd"]
        print("Found gsd")
    else:
        JSON_gsd = {}

    # First we do vendors with authoritative information: (read only)
    if "namespaces" in GSD_file_data:
        if "mozilla.org" in GSD_file_data["namespaces"]:
            JSON_mozillaorg = GSD_file_data["namespaces"]["mozilla.org"]
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
            print("found cve.org")
        if "nvd.nist.gov" in GSD_file_data["namespaces"]:
            JSON_nvdnistgov = GSD_file_data["namespaces"]["nvd.nist.gov"]
            print("found nvd.nist.gov")   
