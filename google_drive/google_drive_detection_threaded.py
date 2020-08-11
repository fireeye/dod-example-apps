# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     [package root]/LICENSE.txt

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import fireeyepy
import concurrent.futures
import json
from datetime import datetime
import pickle
import time
import os.path
from io import BytesIO
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.discovery import build
import secrets

WORKER_THREADS=5 # Be careful how many threads you spawn to avoid reaching API rate limits
DOD_API_KEY = secrets.keys['DOD_API_KEY']
REPORT_RETRY_TIME = 5 # Wait 'n' seconds between each poll to the /reports endpoint to get the status of file reports
DOD_FILE_SIZE_LIMIT = 32000000 # 32 MB in SI units.  Files larger than this won't be downloaded from GDrive since DoD won't accept them.
QUARANTINE_FOLDER_NAME = "Quarantine" # Name of the folder to put malicious files in.  If this folder doesn't exist, the script will create it.
SCOPES = ['https://www.googleapis.com/auth/drive']


# Initialize credentials for Google API (https://developers.google.com/drive/api/v3/quickstart/python?authuser=1)
def initGoogleCreds():
    # Authorize with Google Drive
    creds = None
    
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                './credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    return creds


# Get the id of the folder that will be used to quarantine malicious files.  If it doesn't exist, create it.
def initQuarantineFolder(google_service, name=QUARANTINE_FOLDER_NAME):
    # Get the quarantine folder iD.  If it doesn't exist, create it.
    results = google_service.files().list(q="mimeType='application/vnd.google-apps.folder' and name='{}'".format(name),
                                          spaces='drive',
                                          fields='files(id)').execute()
    folders = results.get('files', [])
    if len(folders) > 0:
        quarantine_folder_id = folders[0]["id"]
    else:
        # Create the Quarantine folder
        file_metadata = {
            'name': name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        folder = google_service.files().create(body=file_metadata, fields='id').execute()
        quarantine_folder_id = folder.get('id')

    return quarantine_folder_id


# Get a list of files in the drive account.  Exclude folders, files in the trash, and files in the Quarantine folder
# Only return files that have been CREATED at or after the supplied timestamp. Follow pagination to get every file 
# that meets these conditions.
def getFiles(google_service, includeTrash=False, excludedFolderIDs=[], createdAfterTime=""):
    query = "mimeType != 'application/vnd.google-apps.folder' and trashed = {}".format(includeTrash)
    
    # Add ecluded folders to the query
    for id in excludedFolderIDs:
        query += " and not '{}' in parents".format(id)
    
    # Only return files created after the specified date.  If no date provided, get all files.
    if createdAfterTime:
        query += " and createdTime > '{}'".format(createdAfterTime)

    result = []
    page_token = None
    while True:
        param = {
            'q': query,
            'pageSize': 1000, # Maximum supported by Drive API
            'fields': "nextPageToken, files(id, name, mimeType, size)"
        }
        if page_token:
            param['pageToken'] = page_token
        files = google_service.files().list(**param).execute()

        result.extend(files['files'])
        page_token = files.get('nextPageToken')
        if not page_token:
            break

    return result


# Download the file from Google Drive and submit to DoD for malware scanning.
def downloadAndScanFile(creds, detection_client, file, quarantine_folder_id):
    google_service = build('drive', 'v3', credentials=creds)
    try:
        request = google_service.files().get_media(fileId=file["id"])
        # Keep the files in memory instead of saved to disk since we need to upload to DoD
        fh = BytesIO()
        downloader = MediaIoBaseDownload(fh, request) 
        downloader.next_chunk(num_retries=1)
        print(f"Downloaded from GDrive: {file}")
        # Submit file handler to DoD for scanning.
        response = detection_client.submit_file(
                    files={
                        "file": (file["name"], fh.getvalue())
                    }
                )
        if response["status"] == "success":
            quarantineMaliciousFile(google_service, detection_client, response["report_id"], file["id"], quarantine_folder_id)
    except Exception as e:
        print(e)

# Continuously poll the report until it is done and returns a verdict.  If the file is malicious, then move
# it to the designated quarantine folder.
def quarantineMaliciousFile(google_service, detection_client, report_id, file_id, quarantine_folder_id):
    print(f"Checking report {report_id}")
    try:
        report = detection_client.get_report(report_id)
        while report["overall_status"] != "DONE":
            time.sleep(REPORT_RETRY_TIME) # Wait a little bit to allow the detection engine to finish the report
            report = detection_client.get_report(report_id)
        if report["is_malicious"]:
            print(f'{report["file_name"]} is malicious.  Moving to {QUARANTINE_FOLDER_NAME}.')
            # Retrieve the existing parents folder to be removed
            file = google_service.files().get(fileId=file_id,
                                            fields='parents').execute()
            previous_parents = ",".join(file.get('parents'))
            # Move the file to the new folder
            file = google_service.files().update(fileId=file_id,
                                                addParents=quarantine_folder_id,
                                                removeParents=previous_parents,
                                                fields='id, parents').execute()
    except fireeyepy.ClientError as e:
        print(e)


def main(settings):
    detection_client = fireeyepy.Detection(key=DOD_API_KEY)
    creds = initGoogleCreds()
    google_service = build('drive', 'v3', credentials=creds)
    quarantine_folder_id = initQuarantineFolder(google_service)

    # Get the time this script was last run so we only get files from Google Drive that have been created since the last run
    lastRunAt = ""
    if settings['lastRunAt']:
        lastRunAt = settings['lastRunAt']
    else:
        settings['lastRunAt'] = "" # Initialize the lastRunAt setting so we can update it later

    # Uncomment below line to only scan new files
    files = getFiles(google_service, excludedFolderIDs=[quarantine_folder_id], createdAfterTime=lastRunAt) 
    # Uncomment below line to scan all files
    # files = getFiles(google_service, excludedFolderIDs=[quarantine_folder_id])

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        for file in files:
            if "size" in file:
                if int(file["size"]) <= DOD_FILE_SIZE_LIMIT:
                    # Create a new google service object for each thread since it isn't thread safe.  Based on this issue (https://github.com/googleapis/google-api-python-client/issues/626)
                    executor.submit(downloadAndScanFile, creds, detection_client, file, quarantine_folder_id)
                else:
                    print(f'Skipping file {file["name"]} since it is greater than the DoD file size limit.')
            else:
                print(f'Skipping file {file["name"]} since it is most likely a shared file not owned by the user.')
            

if __name__ == '__main__':
    # Read in the settings file
    with open('settings.json') as json_file:
        settings = json.load(json_file)

    start_time = time.time()
    main(settings)
    print(f"--- {(time.time() - start_time)} seconds ---")

    # Upon successful completion of the script, update the lastRunAt setting.  If the script
    # fails, then this won't execute so we can fix the issue and retry without missing any files.
    settings['lastRunAt'] = datetime.utcnow().isoformat().split('.')[0] # Split on the period to remove the milliseconds
    with open('settings.json', 'w') as outfile:
        json.dump(settings, outfile)