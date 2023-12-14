# https://softwareengineering.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
# https://stackoverflow.com/questions/49515975/how-to-keep-track-of-the-files-i-read-into-a-database-in-python 
# https://dunlapww.medium.com/setup-pythons-equivalent-or-ruby-s-pry-ipdb-33e98f4f847b 
# https://wundergraph.com/blog/wunderbase_serverless_graphql_database_on_top_of_sqlite_firecracker_and_prisma

import os
from stig_parser import convert_stig

## PARSE STIG ZIP FILE
file = "U_CAN_Ubuntu_20-04_LTS_V1R5_STIG.zip"
json_results = convert_stig(file)

#import ipdb; ipdb.set_trace()

print("Processing STIG: " + file )
print(json_results['Title'] + " Version: " + json_results['Version'] + " Release: " + json_results['Release'])
print("\n")

path = "/tmp"

obj = os.scandir(path)

print("Files and Directories in '% s':" % path)
for entry in obj :
    if entry.is_dir() or entry.is_file():
        print(entry.name)