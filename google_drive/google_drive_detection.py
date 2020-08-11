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
import json
from datetime import datetime
import pickle
import time
import os.path
from io import BytesIO
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaIoBaseDownload
import secrets

DOD_API_KEY = secrets.keys['DOD_API_KEY']
REPORT_RETRY_TIME = 5 # Wait 'n' seconds between each poll to the /reports endpoint to get the status of file reports
DOD_FILE_SIZE_LIMIT = 32000000 # 32 MB in SI units.  Files larger than this won't be downloaded from GDrive since DoD won't accept them.
QUARANTINE_FOLDER_NAME = "Quarantine" # Name of the folder to put malicious files in.  If this folder doesn't exist, the script will create it.
SCOPES = ['https://www.googleapis.com/auth/drive']


# Safe way to get multiple reports if certain reports throw client exceptions.  If client error thrown, don't
# include that report in the final list.
def getSuccessfulReports(detection_client, report_ids):
    reports = []
    for report_id in report_ids:
        try:
            report = detection_client.get_report(report_id)
            reports.append(report)
        except fireeyepy.ClientError as e:
            print(e)
    return reports


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


# Download the list of files from Google Drive and submit each one to DoD for malware scanning. 
def downloadAndScanFiles(google_service, detection_client, files):
    # Since Google Drive can have many files with the same name, need a dictionary to map DoD report IDs to Google Drive file IDs 
    # so we know which file to take action on if the report says it's malicious.
    submitted_files = {} 

    for file in files:
        if "size" in file:
            if int(file["size"]) <= DOD_FILE_SIZE_LIMIT:
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
                        # Map the report ID to the file ID so we know which file to quarantine later if necessary
                        submitted_files[response["report_id"]] = file["id"]
                        print(f'Successfully submitted to DoD.  Report ID: {response["report_id"]}')
                except Exception as e:
                    print(e)
            else:
                print(f'Skipping file {file["name"]} since it is greater than the DoD file size limit.')
        else:
                print(f'Skipping file {file["name"]} since it is most likely a shared file not owned by the user.')
    
    return submitted_files


# Continuously loop through all reports until they are done and return a verdict.  If the file is malicious, then move
# it to the designated quarantine folder.
def quarantineMaliciousFiles(google_service, detection_client, submitted_files, quarantine_folder_id):
    # Some reports might not be successful due to client errors.  Ignore them and only get the successful reports.
    reports_in_progress = getSuccessfulReports(detection_client, submitted_files)
    # Keep looping over the reports until they are all finished.  Sleep for 'n' seconds between each run to allow DoD time to process files.
    while len(reports_in_progress) > 0:
        malicious_files = list(filter(lambda report: report["overall_status"] == "DONE" and report["is_malicious"], reports_in_progress))
        for malicious_file in malicious_files:
            print(f'{malicious_file["file_name"]} is malicious.  Moving to {QUARANTINE_FOLDER_NAME}.')
            file_id = submitted_files[malicious_file["report_id"]]
            # Retrieve the existing parents folder to be removed
            file = google_service.files().get(fileId=file_id,
                                            fields='parents').execute()
            previous_parents = ",".join(file.get('parents'))
            # Move the file to the new folder
            file = google_service.files().update(fileId=file_id,
                                                addParents=quarantine_folder_id,
                                                removeParents=previous_parents,
                                                fields='id, parents').execute()
        # Refresh report IDs list with those that are still in progress
        in_progress_report_ids = list(map(lambda report: report["report_id"], list(filter(lambda report: report["overall_status"] != "DONE", reports_in_progress))))
        if len(in_progress_report_ids) > 0:
            time.sleep(REPORT_RETRY_TIME) # Wait a little bit to allow the detection engine to finish more reports
            reports_in_progress = getSuccessfulReports(detection_client, in_progress_report_ids)
        else:
            reports_in_progress = [] # No more reports to check


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

    submitted_files = downloadAndScanFiles(google_service, detection_client, files) 

    # Get the report result for each file and move each malicious file to the designated quarantine folder in Google Drive
    quarantineMaliciousFiles(google_service, detection_client, submitted_files, quarantine_folder_id)

            
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
