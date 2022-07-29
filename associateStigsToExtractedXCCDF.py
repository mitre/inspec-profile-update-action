from difflib import SequenceMatcher
import json
import os
import re

updated = []


def getFilename(url):
    return url.split('/')[-1]

# Get filenames from benchmarks folder
downloadedStigs = os.listdir('benchmarks/DISA/')

with open('stigs.json', 'r') as infile:
    updated = json.load(infile)

for idx, benchmark in enumerate(updated):
    urlWithNoVersion = re.sub(
        r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', getFilename(benchmark['url']))
    version = re.search(
        r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', getFilename(benchmark['url']))
    if version is not None:
        version = version.group(0)
        highestSimilarity = 0.0
        highestSimilarityFilename = None
        for filename in downloadedStigs:
            filenameVersion = re.search(
                r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', getFilename(filename))
            if filenameVersion is not None:
                filenameVersion = filenameVersion.group(0)
                similarity = SequenceMatcher(
                    None, urlWithNoVersion, filename).ratio()
                if similarity > highestSimilarity and filenameVersion == version:
                    highestSimilarity = similarity
                    highestSimilarityFilename = filename
        if highestSimilarityFilename is not None:
            print(f"{getFilename(benchmark['url'])} -> {highestSimilarityFilename}")
            updated[idx]['file'] = f"https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/benchmarks/DISA/{highestSimilarityFilename}"
        else:
            del updated[idx]
    else:
        print("No version for url: "+benchmark['url'])

with open('stigs.json', 'w') as outfile:
    json.dump(updated, outfile)