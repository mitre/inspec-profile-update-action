import os
import json

# Open the JSON file
stigs = []

with open('stigs.json') as json_file:
    stigs = json.load(json_file)

for stig in stigs:
    # Download ZIP from DISA
    if 'scc' not in stig['url'].lower():
        os.system(f"wget {stig['url']} -O tmp/input/{stig['id']}.zip")