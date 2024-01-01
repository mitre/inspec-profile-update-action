import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import re
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
from io import BytesIO
import zipfile
from stig_parser import convert_stig

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
SQLITE_DB_FILE = 'security_guidance.db'
EXCLUDE_KEYWORDS = ['scc', 'library', '.msi.zip', 'srg_stig_applicability_guide', 'stigapplicabilityguide', 'stigviewer', 'u_cci_list', 'overview', 'scap', 'ansible', 'u_draft_cci', 'srg', 'gpo', 'chef', 'dsc', 'u_apache_2-2', 'u_mot_solutions', 'u_multifunction_device', 'u_storage_area', 'u_ms_exchange', 'u_exchange', 'u_airwatch']

EXTRACTED_ROWS = []

# Function to download and extract STIGs and SRGs
def download_and_extract_stigs():
    response = requests.get(URL, HEADERS, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all rows in the table and download links
    rows = soup.find_all('tr')
    for row in rows:
        title_col = row.find('td', class_='title_column')
        size_col = row.find('td', class_='size_column')
        updated_col = row.find('td', class_='updated_column')

        if title_col and size_col and updated_col:
            title = title_col.get_text(strip=True)
            size = size_col.get_text(strip=True)
            datePublished = updated_col.get_text(strip=True)
            anchor = title_col.find('a')

            if anchor and 'href' in anchor.attrs:
                url = anchor['href']
            else:
                url = 'None'

            # Check if the url contains the excluded keywords, and the file is only a zip file
            if url.lower().endswith('.zip') and not any(keyword in url.lower() for keyword in EXCLUDE_KEYWORDS):
                existing_artifact = session.query(Artifact).filter(Artifact.location == url).first()
                zip_filename = os.path.join(DOWNLOAD_DIR, url.split('/')[-1])               

                # Check if the file already exists
                if not existing_artifact:
                    print(f"Downloading {title} - {url}")
                    zip_response = requests.get(url)

                    # "Description": "xxxxxxx",
                    # Save the zip file
                    with open(zip_filename, 'wb') as f:
                        f.write(zip_response.content)
                        json_results = convert_stig(zip_filename)

                        urlTitle = title
                        urlsize = size
                        urldatePublished = datePublished
                        urlUrl = url
                        id = json_results['Id']
                        title = json_results['Title']
                        status = json_results['Status']
                        description = json_results['Description']
                        version = json_results['Version']
                        release = json_results['Release']
                        benchmarkDate = json_results['BenchmarkDate']
                        releaseInfo = json_results['ReleaseInfo']
                        publisher = json_results['Publisher']
                        source = json_results['Source']
                        notice = json_results['Notice']

                        insert_benchmark_data(id, title, status, description, version, release, benchmarkDate, publisher, source, notice, urlUrl)
                
                    # Extract only the XML files from the zip file
                    with zipfile.ZipFile(zip_filename) as zip_ref:
                        for file in zip_ref.namelist():
                            if file.endswith('.xml'):
                                # Create a temporary directory
                                with tempfile.TemporaryDirectory() as temp_dir:
                                    zip_ref.extract(file, temp_dir)
                                    # Move the file to the desired directory
                                    shutil.move(os.path.join(temp_dir, file), os.path.join(EXTRACT_DIR, os.path.basename(file)))
            else:
                print(f"Skipping excluded file: {title} - {url}")
    
def insert_benchmark_data(id, title, status, description, version, release, datePublished, publisher, source, notice, url):
    new_benchmark = Benchmark(version=version, release=release, release_date=datePublished)
    new_product = Products(long_name=title, short_name=id, version=version, release=release)
    new_organizaiton = Organization(short_name=publisher)
    new_statuses = Statuses(name=status)
    new_artifact = Artifact(name=title, location=url)
    new_artifact_type = ArtifactTypes(type_name=title, description=description)
    session.add(new_benchmark)
    session.add(new_product)
    session.add(new_organizaiton)
    session.add(new_statuses)
    session.add(new_artifact)
    session.add(new_artifact_type)
    session.commit()

def main():
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
    if not os.path.exists(EXTRACT_DIR):
        os.makedirs(EXTRACT_DIR)
    
    download_and_extract_stigs()

if __name__ == "__main__":
    main()
