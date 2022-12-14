import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import re
import json
import uuid
import re

url = "https://public.cyber.mil/stigs/downloads/"

headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '3600',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
}

req = requests.get(url, headers)
soup = BeautifulSoup(req.content, 'html.parser')
table = soup.find_all('table')[0]  # Grab the first table

row_marker = 0

stigs = []
knownURLs = []

with open('stigs.json', 'r') as existingSTIGsFile:
    existingSTIGs = json.load(existingSTIGsFile)
    stigs.extend(existingSTIGs)
    knownURLs.extend([stig['url'] for stig in existingSTIGs])

def cleanText(inputText):
    return re.sub(' +', ' ', inputText.replace('\r', ' ').replace('\u200b', '').replace('\n', ' ').split('\t')[0].strip()).strip()

def getFilenameFromURL(url):
    return url.split('/')[-1]

for row in table.find_all('tr'):
    try:
        columns = row.find_all('td')
        href = ""
        name = ""
        size = ""
        for idx, column in enumerate(columns):
            if idx == 2:
                size = column.get_text().strip()
            if idx == 1:
                href = column.find('a')['href']
                name = cleanText(column.get_text())
        if (href != "" and name != "" and size != "" and ('stig' in name.lower() or 'benchmark' in name.lower() or 'stig' in href.lower() or 'benchmark' in href.lower()) and "viewer" not in name.lower()):
            # Check if the similarity of the current name is similar to an existing name
            newStig = True
            knownIndex = 0
            hrefWithNoVersion = re.sub(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', href)
            for idx, knownURL in enumerate(knownURLs):
                knownURLWithNoVersion = re.sub(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', knownURL)
                if SequenceMatcher(None, hrefWithNoVersion, knownURLWithNoVersion).ratio() > 0.99:
                    # print(f"Similarity: {SequenceMatcher(None, hrefWithNoVersion, knownURLWithNoVersion).ratio()} {hrefWithNoVersion} -> {knownURLWithNoVersion}")
                    knownIndex = idx
                    newStig = False
                    break
            if newStig:
                if (href.lower().endswith('.zip')):
                    knownURLs.append(href)
                    #print(f"Downloading {name}: {href}")
                    #urllib.request.urlretrieve(href, "tmp/" + getFilenameFromURL(href))
                    # Get version from the file name e.g "U_IBM_MaaS360_with_Watson_v10-x_MDM_V1R2_STIG.zip"
                    version = re.search(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', href)
                    if version is not None:
                        stigs.append({
                            'id': str(uuid.uuid4()),
                            'name': name,
                            'url': href,
                            'size': size,
                            'version': version.group(0)
                        })
                    else:
                        print(f"Version not found in {href}")
                        # Attempt to get version number from name, e.g "Ver 1, Rel 1"
                        version = re.search(r'Ver (\d?)(\d?)(\d?)(\d?), Rel (\d?)(\d?)(\d?)(\d?)', name)
                        if version is not None:
                            versionNumber = f"V{version.group(1)}{version.group(2)}{version.group(3)}{version.group(4)}R{version.group(5)}{version.group(6)}{version.group(7)}{version.group(8)}"
                            print(f"Version found in {href} as {versionNumber}")
                            stigs.append({
                                'id': str(uuid.uuid4()),
                                'name': name,
                                'url': href,
                                'size': size,
                                'version': versionNumber
                            })
                        else:
                            stigs.append({
                                'id': str(uuid.uuid4()),
                                'name': name,
                                'url': href,
                                'size': size
                            })
            else:
                version = re.search(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', href)
                if version is not None:
                    stigs[knownIndex]['url'] = href
                    stigs[knownIndex]['size'] = size
                    stigs[knownIndex]['version'] = version.group(0)
                    stigs[knownIndex]['name'] = name
                elif version is None:
                    version = re.search(r'Ver (\d?)(\d?)(\d?)(\d?), Rel (\d?)(\d?)(\d?)(\d?)', name)
                    if version is not None:
                        versionNumber = f"V{version.group(1)}{version.group(2)}{version.group(3)}{version.group(4)}R{version.group(5)}{version.group(6)}{version.group(7)}{version.group(8)}"
                        print(f"Version found in '{name}' as {versionNumber}")
                        stigs[knownIndex]['url'] = href
                        stigs[knownIndex]['size'] = size
                        stigs[knownIndex]['version'] = versionNumber
                        stigs[knownIndex]['name'] = name
                    else:
                        # I've seen DISA remove the version number from the URL, so we need to remove it from the existing STIG if it's no longer there.
                        print(f"Version not found in {href}")
                        stigs[knownIndex]['url'] = href
                        stigs[knownIndex]['size'] = size
                        stigs[knownIndex]['name'] = name
                        if 'version' in stigs[knownIndex]:
                            del stigs[knownIndex]['version']

    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        # Bad rows ignored, typicall they don't contain a download link
        pass

with open('stigs.json', 'w') as outfile:
    json.dump(stigs, outfile, indent=2)
