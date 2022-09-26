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
# Parse file sections (GSD, OSV, namespaces:foo)
# write in order of precedence:
# 1) namespaces:mozilla.org
# 2) GSD
# 3) OSV
# 4) namespaces:cve.org
# 5) namespaces:nvd.nist.gov
#
# Also write the GSD and OSV data into gsd:alternate_database:GSD/OSV

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
# If not set, do globlly with now?

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


# Examples of the "version_affected" data from CVE:
#   1 "!=<"
##   1 "0.17.0"# REPORT ERROR - is version_value broken?
##   1 "0.51.1"# REPORT ERROR - is version_value broken?
##   1 "10.16.3"# REPORT ERROR - is version_value broken?
##   1 "10.21.3"# REPORT ERROR - is version_value broken?
##   1 "11.15.0"# REPORT ERROR - is version_value broken?
##   1 "2021.3.12725"# REPORT ERROR - is version_value broken?
##   1 "2022.1.2454"# REPORT ERROR - is version_value broken?
##   1 "6.2.1.2289"# REPORT ERROR - is version_value broken?
##   1 "7.4"# REPORT ERROR - is version_value broken?
##   1 "7.8"# REPORT ERROR - is version_value broken?
#   1 "?>="
##   2 "1.09" # REPORT ERROR - is version_value broken?
#   2 "=<"
##   2 "None" # set to ""
#   4 "=>"
#   6 "!<="
#   8 ">?"
##   9 "undefined" # set to ""
#  21 "?<"
#  23 "!>"
#  27 "?<="
##  35 "" # set to ""
#  44 "?" 
#  57 ">"
# 133 "!<"
# 211 "!=>"
# 364 "?>"
# 373 "!" # PROBLEMATIC (before? after?)
# 575 "!>="
#1933 ">="
#7587 "<="
#14858 "="
#19904 "<"

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
# if references parse items, if itemtype == str convert to WEB link else treat as correct

#def parseOSV()

#def parseNamespaces_cveorg():

#def parseNamespaces_nvd.nist.gov():

def determineCVEDataType(data):
    # Check CVE, return version, state
    # Not all CVE data (e.g. mozilla) includes a state. It appears most vendors using CVE JSON 
    # (e.g. NVD, Mozilla) only publish PUBLIC CVEs which makes sense
    #
    if "data_version" in data:
        CVEData_Version = data["data_version"]
    else:
        # TODO: I think all vendors include this, we'll handle it better if we find some that don't
        print("ERROR: NO CVE DATA VERSION")
        quit()
    # Not all CVE data contains state, e.g. mozilla.org, but most people that public CVE data only public PUBLIC data
    if "CVE_data_meta" in data:
        if "STATE" in data["CVE_data_meta"]:
            CVEData_State = data["CVE_data_meta"]["STATE"]
        else:
            CVEData_State = "ASSUMED_PUBLIC"
    else: 
        CVEData_State = "ASSUMED_PUBLIC"
    return(CVEData_Version, CVEData_State)


def parseCVEv40PUBLIC(data, datatype):
    # Check for key, write to gsd:{} if not exist:
    if "description" in data:
        JSON_gsd["summary"] = ""
        JSON_gsd["details"] = ""
        for entry in data["description"]["description_data"]:
            if entry["lang"] == "eng":
                # No need to check language, only english is used. But what to do with multiple entries???
                # What happens if multiple entries? write as blocks I guess? How do we zero it out and not clobber the original?
                # Should we just do this via the API?
                if JSON_gsd["summary"] == "":
                    JSON_gsd["summary"] = entry["value"]
                if JSON_gsd["details"] == "":
                    JSON_gsd["details"] = entry["value"]
            else:
                print("INFORMATION: FOUND MULTIPLE DESCRIPTION TEXTS")
    if "references" in data:
        JSON_gsd["references"] = []
        if "reference_data" in data["references"]:
            for entry in data["references"]["reference_data"]:
                entry_item = {}
                if datatype == "vendor":
                    entry_item["type"] = "ADVISORY"
                else:
                    entry_item["type"] = "WEB"
                entry_item["url"] = entry["url"]
                JSON_gsd["references"].append(entry_item)
    # Check for affected stuff, walk the data, set things to null if not exist, how to handle things like vendor name but no products?
    if "affects" in data:
        JSON_gsd["affected"] = []
        if "vendor" in data["affects"]:
            if "vendor_data" in data["affects"]["vendor"]:
                for vendor_entry in data["affects"]["vendor"]["vendor_data"]:
                    # Check for vendor name first, should exist 
                    if "vendor_name" in vendor_entry:
                        # TODO: Add logic to handle the n/a and " " spaces?
                        vendor_name = vendor_entry["vendor_name"]
                    else:
                        # If there is no vendor name but there is product/affected data continue on I guess
                        vendor_name = ""
                    #
                    # Write data structure
                    #
                    #
                    if "product" in vendor_entry:
                        if "product_data" in vendor_entry["product"]:
                            for product_entry in vendor_entry["product"]["product_data"]:
                                affected_entry = {}
                                affected_entry["package"] = {}
                                affected_entry["package"]["ecosystem"] = vendor_name


                                if "product_name" in product_entry:
                                    # TODO: Add logic to handle the n/a and " " spaces?
                                    product_name = product_entry["product_name"]
                                else:
                                    product_name = ""
                                #
                                # Write data structure
                                affected_entry["package"]["name"] = product_name
                                #
                                #
                                # We want to group version data by product
                                affected_entry["version"] = []
                                affected_entry["ranges"] = []
                                # setup a range entry and then write it if not empty
                                range_entry = {}
                                #
                                if "version" in product_entry:
                                    if "version_data" in product_entry["version"]:
                                        for version_entry in product_entry["version"]["version_data"]:
                                            if "version_value" in version_entry:
                                                # TODO: Add logic to handle the n/a and " " spaces?
                                                if version_entry["version_value"] == "n/a":
                                                    version_value = ""
                                                elif version_entry["version_value"]  == " ":
                                                    version_value = ""
                                                version_value = version_entry["version_value"]
                                            else:
                                                version_value = ""
                                            if "version_affected" in version_entry:
                                                # TODO: Add logic to handle the n/a and " " spaces?
                                                version_affected = version_entry["version_affected"]
                                            else:
                                                version_affected = ""
                                            # We are now at the bottom of the data and can write it
                                            # We need logic to handle the cases:
                                            #
                                            # common cases:  ">"  "!<" "!=>" "?>" "!" "!>=" ">=" "<=" "=" "<"
                                            #
                                            if version_affected == "":
                                                # We write the "versions" string and that's it
                                                affected_entry["version"].append(version_value)
                                            elif version_affected == "<":
                                                range_entry["type"] = "SEMVER"
                                                if "events" not in range_entry:
                                                    range_entry["events"] = []
                                                range_entry_event = {}
                                                range_entry_event["fixed"] = version_value
                                                range_entry["events"].append(range_entry_event)
                                            elif version_affected == "=":
                                                # We write the "versions" string and that's it
                                                affected_entry["version"].append(version_value)
                                            else:
                                                # potentially mangled data, just write the version string
                                                affected_entry["version"].append(version_value)
                                            
                                        if range_entry != {}:
                                            affected_entry["ranges"].append(range_entry)
                                            range_entry = {}
                                else:
                                    # TODO: no version, so write incomplete data?
                                    version_value = ""
                                    version_affected = ""
                                JSON_gsd["affected"].append(affected_entry)

                                

                             
                    else:
                        # TODO: no product (so no version), so write incomplete data?
                        product_name = ""
                        version_value = ""
                        version_affected = ""
                    # WRITE to data structure
        else:
            # TODO: no vendor (so no product and no version), so write incomplete data?
            vendor_name = ""
            product_name = ""
            version_value = ""
            version_affected = ""
        # WRITE to data structure

        #JSON_gsd["affected"].append(entry_item)


    if "problemtype" in data:
        # No support for this in OSV yet so just ignore?
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
            if CVE_state == "PUBLIC" or "ASSUMED_PUBLIC":
                if CVE_version == "4.0":
                    parseCVEv40PUBLIC(JSON_mozillaorg, "vendor")


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

    print(json.dumps(JSON_gsd, indent=4))