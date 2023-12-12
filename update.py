import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import re
import json
import uuid
import re
import os
import xml.etree.ElementTree as ET
import pyscap
from io import BytesIO
import zipfile

URL = "https://public.cyber.mil/stigs/downloads/"
HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '3600',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
}
DOWNLOAD_DIR = "downloads"
EXTRACT_DIR = "extracted"
DB_FILE = "stigs.db"
EXCLUDE_KEYWORDS = ['scc', 'library', '.msi.zip', 'srg_stig_applicability_guide', 'STIGApplicabilityGuide']

extracted_rows = []

# Function to download and extract STIGs and SRGs
def download_and_extract_stigs():
    global extracted_rows
    response = requests.get(URL, HEADERS, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all rows in the table and download links
    rows = soup.find_all('tr')
    for row in rows:
        cols = row.find_all('td')
        if len(cols) == 3:
            title = cols[0].get_text(strip=True)
            size = cols[1].get_text(strip=True)
            datePublished = cols[2].get_text(strip=True)
            url = cols[0].find('a')['href']
            extracted_rows.append((title, size, datePublished, url))
            # url = cols[0].find('a')['href'].endswith('.zip')

            # Check if the url contains the excluded keywords
            if not any(keyword in url for keyword in EXCLUDE_KEYWORDS):
                zip_filename = os.path.join(DOWNLOAD_DIR, url.split('/')[-1])

                # Check if the file already exists
                if not os.path.exists(zip_filename):
                    print(f"Downloading {title} - {url}")
                    zip_response = requests.get(url)

                    # Save the zip file
                    with open(zip_filename, 'wb') as f:
                        f.write(zip_response.content)
                
                # Extract only the XML files from the zip file
                with zipfile.ZipFile(zip_filename) as zip_ref:
                    for file in zip_ref.namelist():
                        if file.endswith('.xml'):
                            zip_ref.extract(file, EXTRACT_DIR)
            else:
                print(f"Skipping excluded file: {title} - {url}")

def parse_xml_and_extract_info():
    global extracted_rows
    for xml_file in os.listdir(EXTRACT_DIR):
        if xml_file.endswith('.xml'):
            # Match the XML file to its metadata
            metadata = next((row for row in extracted_rows if row[3].endswith(xml_file)), None)
            if metadata:
                title, size, datePublished, url = metadata
                print("Table Data:")
                print(f"Title: {title}, Size: {size}, Date Published: {datePublished}, URL: {url}")
                current_benchmark = pyscap.xccdf.Benchmark.parse(os.path.join(EXTRACT_DIR, xml_file))
                pytitle = current_benchmark.title
                pyremark = current_benchmark.remark
                pyvenor = current_benchmark.vendor
                pyfamily = current_benchmark.family
                pymodel = current_benchmark.model
                pylevel = current_benchmark.level
                pyverison = current_benchmark.version
                pyversionrange = current_benchmark.version_range
                print("pyscap data:")
                print(f"Title: {pytitle}, Remark: {pyremark}, Vendor: {pyvenor}, Family: {pyfamily}, Model: {pymodel}, Level: {pylevel}, Version: {pyverison}, Version Range: {pyversionrange}")


    #         # Store in SQLite database
    #         store_in_db(filename, title, name, url, size, version)

# def store_in_db(filename, title, name, url, size, version):
#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()
#     cursor.execute('''CREATE TABLE IF NOT EXISTS stigs (filename TEXT, title TEXT, url TEXT, size TEXT, version TEXT)''')
#     cursor.execute("INSERT INTO stigs VALUES (?, ?, ?, ?, ?, ?)", (filename, title, name, url, size, version))
#     conn.commit()
#     conn.close()

def main():
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
    if not os.path.exists(EXTRACT_DIR):
        os.makedirs(EXTRACT_DIR)
    
    download_and_extract_stigs()
    parse_xml_and_extract_info()

if __name__ == "__main__":
    main()

# badTerms = ['scc', 'library', '.msi.zip', 'srg_stig_applicability_guide', 'STIGApplicabilityGuide']
# url = "https://public.cyber.mil/stigs/downloads/"
# headers = {
#     'Access-Control-Allow-Origin': '*',
#     'Access-Control-Allow-Methods': 'GET',
#     'Access-Control-Allow-Headers': 'Content-Type',
#     'Access-Control-Max-Age': '3600',
#     'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
# }
# stigs = []

# with open('stigs.json', 'r') as existingSTIGsFile:
#     stigs = json.load(existingSTIGsFile)

# def getFilename(url):
#     return url.split('/')[-1]

# ### Get STIGS from DISA'S site

# def updateSTIGSList():
#     # If you're running behind a proxy with SSL bumping
#     req = requests.get(url, headers, verify=False)
#     # req = requests.get(url, headers)
#     soup = BeautifulSoup(req.content, 'html.parser')
#     table = soup.find_all('table')[0]  # Grab the first table

#     knownURLs = []

#     with open('stigs.json', 'r') as existingSTIGsFile:
#         existingSTIGs = json.load(existingSTIGsFile)
#         knownURLs.extend([stig['url'] for stig in existingSTIGs])

#     def cleanText(inputText):
#         return re.sub(' +', ' ', inputText.replace('\r', ' ').replace('\u200b', '').replace('\n', ' ').split('\t')[0].strip()).strip()

#     for row in table.find_all('tr'):
#         try:
#             columns = row.find_all('td')
#             href = ""
#             name = ""
#             size = ""
#             for idx, column in enumerate(columns):
#                 if idx == 2:
#                     size = column.get_text().strip()
#                 if idx == 1:
#                     href = column.find('a')['href']
#                     name = cleanText(column.get_text())
#             if (href != "" and name != "" and size != "" and ('stig' in name.lower() or 'benchmark' in name.lower() or 'stig' in href.lower() or 'benchmark' in href.lower()) and "viewer" not in name.lower()):
#                 # Check if the similarity of the current name is similar to an existing name
#                 newStig = True
#                 knownIndex = 0
#                 hrefWithNoVersion = re.sub(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', href)
#                 for idx, knownURL in enumerate(knownURLs):
#                     knownURLWithNoVersion = re.sub(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', knownURL)
#                     if SequenceMatcher(None, hrefWithNoVersion, knownURLWithNoVersion).ratio() > 0.99:
#                         # print(f"Similarity: {SequenceMatcher(None, hrefWithNoVersion, knownURLWithNoVersion).ratio()} {hrefWithNoVersion} -> {knownURLWithNoVersion}")
#                         knownIndex = idx
#                         newStig = False
#                         break
#                 if newStig:
#                     if (href.lower().endswith('.zip')):
#                         knownURLs.append(href)
#                         #print(f"Downloading {name}: {href}")
#                         #urllib.request.urlretrieve(href, "tmp/" + getFilenameFromURL(href))
#                         # Get version from the file name e.g "U_IBM_MaaS360_with_Watson_v10-x_MDM_V1R2_STIG.zip"
#                         version = re.search(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', href)
#                         if version is not None:
#                             stigs.append({
#                                 'id': str(uuid.uuid4()),
#                                 'name': name,
#                                 'url': href,
#                                 'size': size,
#                                 'version': version.group(0)
#                             })
#                         else:
#                             print(f"Version not found in {href}")
#                             # Attempt to get version number from name, e.g "Ver 1, Rel 1"
#                             version = re.search(r'Ver (\d?)(\d?)(\d?)(\d?), Rel (\d?)(\d?)(\d?)(\d?)', name)
#                             if version is not None:
#                                 versionNumber = f"V{version.group(1)}{version.group(2)}{version.group(3)}{version.group(4)}R{version.group(5)}{version.group(6)}{version.group(7)}{version.group(8)}"
#                                 print(f"Version found in {href} as {versionNumber}")
#                                 stigs.append({
#                                     'id': str(uuid.uuid4()),
#                                     'name': name,
#                                     'url': href,
#                                     'size': size,
#                                     'version': versionNumber
#                                 })
#                             else:
#                                 stigs.append({
#                                     'id': str(uuid.uuid4()),
#                                     'name': name,
#                                     'url': href,
#                                     'size': size
#                                 })
#                 else:
#                     version = re.search(r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', href)
#                     if version is not None:
#                         stigs[knownIndex]['url'] = href
#                         stigs[knownIndex]['size'] = size
#                         stigs[knownIndex]['version'] = version.group(0)
#                         stigs[knownIndex]['name'] = name
#                     elif version is None:
#                         version = re.search(r'Ver (\d?)(\d?)(\d?)(\d?), Rel (\d?)(\d?)(\d?)(\d?)', name)
#                         if version is not None:
#                             versionNumber = f"V{version.group(1)}{version.group(2)}{version.group(3)}{version.group(4)}R{version.group(5)}{version.group(6)}{version.group(7)}{version.group(8)}"
#                             print(f"Version found in '{name}' as {versionNumber}")
#                             stigs[knownIndex]['url'] = href
#                             stigs[knownIndex]['size'] = size
#                             stigs[knownIndex]['version'] = versionNumber
#                             stigs[knownIndex]['name'] = name
#                         else:
#                             # I've seen DISA remove the version number from the URL, so we need to remove it from the existing STIG if it's no longer there.
#                             print(f"Version not found in {href}")
#                             stigs[knownIndex]['url'] = href
#                             stigs[knownIndex]['size'] = size
#                             stigs[knownIndex]['name'] = name
#                             if 'version' in stigs[knownIndex]:
#                                 del stigs[knownIndex]['version']

#         except KeyboardInterrupt:
#             exit()
#         except Exception as e:
#             print(e)
#             # Bad rows ignored, typicall they don't contain a download link
#             pass

#     with open('stigs.json', 'w') as outfile:
#         json.dump(stigs, outfile, indent=2)

# def updateSTIGS():
#     # Delete the existing STIGs
#     os.system("rm -rf tmp/input/*")

#     ## Download the STIGs
#     for stig in stigs:
#         # Download ZIP from DISA if it doesn't contain a banned term
#         foundTerm = False

#         for badTerm in badTerms:
#             if badTerm.lower() in stig['url'].lower():
#                 foundTerm = True

#         if not foundTerm:
#             if 'scc' not in stig['url'].lower() and 'library' not in stig['url'].lower():
#                 os.system(f"wget {stig['url']} -O tmp/input/{stig['id']}.zip")

#     # Unzip the STIGs
#     os.system("cd tmp; bash extract.sh")

# def associateSTIGFileArchives():
#     # Get filenames from benchmarks folder
#     downloadedStigs = os.listdir('benchmarks/DISA/')
    
#     for idx, benchmark in enumerate(stigs):
#         urlWithNoVersion = re.sub(
#             r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', '', getFilename(benchmark['url']))
#         version = re.search(
#             r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', getFilename(benchmark['url']))
#         if version is not None:
#             version = version.group(0)
#             highestSimilarity = 0.0
#             highestSimilarityFilename = None
#             for filename in downloadedStigs:
#                 filenameVersion = re.search(
#                     r'V\d(\d?)(\d?)(\d?)(\d?)R\d(\d?)(\d?)(\d?)(\d?)', getFilename(filename))
#                 if filenameVersion is not None:
#                     filenameVersion = filenameVersion.group(0)
#                     similarity = SequenceMatcher(
#                         None, urlWithNoVersion, filename).ratio()
#                     if similarity > highestSimilarity and filenameVersion == version:
#                         highestSimilarity = similarity
#                         highestSimilarityFilename = filename
#             if highestSimilarityFilename is not None:
#                 print(f"{getFilename(benchmark['url'])} -> {highestSimilarityFilename}")
#                 stigs[idx]['file'] = f"https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/benchmarks/DISA/{highestSimilarityFilename}"
#             else:
#                 del stigs[idx]
#         else:
#             print("No version for url: "+benchmark['url'])
    
#     with open('stigs.json', 'w') as outfile:
#         json.dump(stigs, outfile, indent=2)

# """
# Gets the Profile ID from the XCCDF xml file
# Example:
# <?xml version="1.0" encoding="utf-8"?><?xml-stylesheet type='text/xsl' href='STIG_unclass.xsl'?>
# <Benchmark xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
#     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
#     xmlns:cpe="http://cpe.mitre.org/language/2.0" xmlns:xhtml="http://www.w3.org/1999/xhtml"
#     xmlns:dc="http://purl.org/dc/elements/1.1/" id="Active_Directory_Domain" xml:lang="en"
#     xsi:schemaLocation="http://checklists.nist.gov/xccdf/1.1 http://nvd.nist.gov/schema/xccdf-1.1.4.xsd
#                         http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.1.xsd"
#     xmlns="http://checklists.nist.gov/xccdf/1.1">

# We want "Active_Directory_Domain" from this.
# """

# def getProfileIDFromProfileXMLs():
#     for stig in stigs:
#         if 'file' in stig:
#             # Get the file path from the file URL
#             filePath = stig['file'].split('https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/')[1]
#             # Get the file name from the file path
#             fileName = filePath.split('/')[-1]

#             # Parse the XML file
#             tree = ET.parse(filePath)
#             root = tree.getroot()

#             # Get the ID from the root
#             if 'id' in root.attrib:
#                 if '/' not in root.attrib['id']:
#                     stig['id'] = root.attrib['id']
#             else:
#                 print(f"No ID found for {fileName}")
    
#     with open('stigs.json', 'w') as outfile:
#         json.dump(stigs, outfile, indent=2)

# def pageGenerator():
#     # Delete existing generated actions
#     os.system("rm -rf actions/*")

#     for stig in stigs:
        
#         yml = f"""
# on: [push]

# jobs:
# test_action:
#     runs-on: ubuntu-latest
#     name: Test inpec-profile-update action
#     steps:
#     # To use this repository's private action,
#     # you must check out the repository
#     - name: Checkout
#         uses: actions/checkout@v3
#     # Update profile
#     - name: Updates profile
#         uses: mitre/inspec-profile-update-action@main
#         # Set env variables
#         env:
#         profile: {stig['id']}
#     # Create new branch
#     - name: Push changes to new PR
#         uses: peter-evans/create-pull-request@v4
#         with:
#         branch: update-profile
#         delete-branch: true"""

#         with open(f"actions/{stig['id']}.yml", "w") as f:
#             f.write(yml)

#     html = """
#     <html>
#         <head>
#             <link rel="stylesheet" href="site/styles.css">
#             <title>STIGs List</title>
#         </head>
#     <table>"""

#     html += "<tr><th>STIG ID</th><th>Name</th><th>Version</th><th>URL</th><th>Size</th><th>Action</th></tr>"
#     for stig in stigs:
#         html += f"""
#         <tr>
#             <td>{stig['id']}</td>
#             <td>{stig['name']}</td>
#             """
#         if 'version' in stig:
#             html += f"""<td>{stig['version']}</td>"""
#         else:
#             html += f"""<td></td>"""
#         html += f"""
#             <td><a href="{stig['url']}">Download</a></td>
#             <td>{stig['size']}</td>
#             <td><a href="actions/{stig['id']}.yml">Download Action</a></td>
#         </tr>"""
#     html += "</table>"

#     with open("index.html", "w") as f:
#         f.write(html)

# updateSTIGSList()
# updateSTIGS()
# associateSTIGFileArchives()
# getProfileIDFromProfileXMLs()
# pageGenerator()