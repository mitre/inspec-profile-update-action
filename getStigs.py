import requests
from bs4 import BeautifulSoup
import re
import json

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
table = soup.find_all('table')[0] # Grab the first table

row_marker = 0

stigs = []

def cleanText(inputText):
    return re.sub(' +', ' ', inputText.replace('\r', ' ').replace('\u200b', '').replace('\n', ' ').split('\t')[0].strip()).strip()

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
            # If we have a zip file
            if (href.lower().endswith('.zip')):
                stigs.append({
                    'name': name,
                    'href': href,
                    'size': size
                })
    except:
        print("Error parsing row: ")
        print(row)

with open('stigs.json', 'w') as outfile:
    json.dump(stigs, outfile, indent=2)