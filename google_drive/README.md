# Overview
This software is provided as a working example of how FireEye's Detection on Demand service can be used to identify and remediate malicious files that are uploaded to file hosting services like Google Drive.  It can be used as-is or modified to suit your needs.

# Installation
### Install packages
This script requires Python3.  Install all required packages using requirements.txt and pip3
```
python3 -m pip install -r requirements.txt --user
```

### Setup a Google Drive API Project and Credentials
Open https://developers.google.com/drive/api/v3/quickstart/python in your browser and complete the following steps
1. Click “enable the drive api”
2. Enter a name for your project, like “DoD Scanning”
3. Select “Desktop app” when configuring your OAuth Client and click “Create”
4. Download the client configuration
5. Move the downloaded “credentials.json” to this project.

### Acquire Detection on Demand API Key
If you don't already have a key, go to https://fireeye.dev/docs/detection-on-demand/#prerequisites and follow the directions.  Once you have an API key, create a file in the project called "secrets.py" with the following contents:
```python
keys = {
    'DOD_API_KEY': "your_api_key"
}
```

# Usage
### Synchronous vs Threaded Scripts
The **synchronous** version of this script, "google_drive_detection.py", will download, scan, and take action on each file one at a time.  Single threaded applications are typically easier to reason about, and might be more suitable for integrating with other applications.  

The **threaded** version of this script, "google_drive_detection_threaded.py", will use one or more threads to download, scan, and take action on files in parallel.  The speed improvements offered by this version of the script vary depending on the files in the target Google Drive account, and the available bandwidth for the machine running the script.  The biggest gains in performance will be from processing lots of small files, where there is a lot of processor downtime waiting for TCP handshakes to occur for each file transfer.  The speed gains will be smaller if there are a lot of larger files because the network bandwidth will become a bottleneck.  In a mixed workload case, expect to see about a 25% speed increase.  You may also need to tune the number of worker threads to avoid hitting rate limits for the APIs.

### Configuring a script for execution
Both scripts have constants near the top of the file that allow some configuration.
- **REPORT_RETRY_TIME**: Number of seconds to wait before checking the status of a detection report again
- **DOD_FILE_SIZE_LIMIT**: Limit how many bytes of a file to download from Google Drive and upload to DoD.  Most malware is under 2MB, but DoD can support up to 32 MB.  In low bandwidth environments, you can see lot's of performance gains by reducing this number closer to 2MB.
- **QUARANTINE_FOLDER_NAME**: The name of the folder to put malicious files in.  If this folder doesn't exist, the script will create it.
- **WORKER_THREADS** (threaded script only): The number of threads to spawn to handle file submission and quarantine actions.  Too many threads might cause rate limit issues with the DoD and Google APIs, so you will need to tune this up or down to find the sweet spot.

You will also want to check the "settings.json" file to make sure it looks like the following before your first run:
```
{
    "lastRunAt": ""
}
```

### Running the script
Once you have configured the single or threaded script, simply invoke the script:
```python
python3 google_drive_detection.py
```

The first execution of this script will open your web browser to the Google authentication service where you will need allow the script to access your Google Drive account.  As a result, the Google client will download create a "token.pickle" file so you don't have to go through the same process on subsequent calls.

# Security Considerations
The "creds.json", "token.pickel", and DOD_API_KEY items contain secrets that you may wish to protect in a production setting.  It is beyond the scope of this README to provide guidance on how best to secure these files, just please note that the default setup is probably not secure enough for a production setting.
