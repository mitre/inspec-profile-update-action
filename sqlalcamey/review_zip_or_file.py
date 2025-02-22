# https://softwareengineering.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
# https://stackoverflow.com/questions/49515975/how-to-keep-track-of-the-files-i-read-into-a-database-in-python
# https://dunlapww.medium.com/setup-pythons-equivalent-or-ruby-s-pry-ipdb-33e98f4f847b
# https://wundergraph.com/blog/wunderbase_serverless_graphql_database_on_top_of_sqlite_firecracker_and_prisma

import os
from stig_parser import convert_stig
from stig_parser import convert_xccdf

## PARSE STIG ZIP FILE
file1 = "../test/U_CAN_Ubuntu_20-04_LTS_V1R5_STIG.zip"
file2 = "../benchmarks/DISA/U_CAN_Ubuntu_20-04_LTS_STIG_V1R4_Manual-xccdf.xml"
# import ipdb; ipdb.set_trace()


def process_stig(stig, type="zip"):
    """
    Process the STIG and return the JSON results.

    Args:
        stig (type): The STIG to be processed.

    Returns:
        dict: The JSON results of the processed STIG.
    """
    json_results = ""
    if type == "zip":
        json_results = convert_stig(stig)
    else:
        try:
            # import ipdb
            # ipdb.set_trace()
            fp = open(stig, "r")
            json_results = convert_xccdf(fp.read())
        except:
            print("could not open: " + file2)
            print("plese check the path")
            print(os.getcwd())

    print("Processing STIG: " + stig)
    print(json_results["Title"] + " Version: " + json_results["Version"] + " Release: " + json_results["Release"])
    print("\n")

    return json_results


process_stig(file1, "zip")

process_stig(file2, "xccdf")

path = "/tmp"

obj = os.scandir(path)

print("Files and Directories in '% s':" % path)
for entry in obj:
    if entry.is_dir() or entry.is_file():
        print(entry.name)
