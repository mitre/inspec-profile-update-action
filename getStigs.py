import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import re
import json
import uuid
import re
import urllib.request

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
                    print("Found a duplicate: " + href)
                    print("Similar to: " + knownURL)
                    knownIndex = idx
                    newStig = False
                    break
            if newStig:
                if (href.lower().endswith('.zip')):
                    knownURLs.append(href)
                    #print(f"Downloading {name}: {href}")
                    #urllib.request.urlretrieve(href, "tmp/" + getFilenameFromURL(href))
                    # Get version from the file name e.g "U_IBM_MaaS360_with_Watson_v10-x_MDM_V1R2_STIG.zip"
                    version = re.search(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', href).group(0)
                    if version:
                        stigs.append({
                            'id': str(uuid.uuid4()),
                            'name': name,
                            'url': href,
                            'size': size,
                            'version': version
                        })
            else:
                stigs[knownIndex]['url'] = href
                stigs[knownIndex]['size'] = size
                stigs[knownIndex]['version'] = version
                stigs[knownIndex]['name'] = name

    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        # Bad rows ignored, typicall they don't contain a download link
        pass

with open('stigs.json', 'w') as outfile:
    json.dump(stigs, outfile, indent=2)
