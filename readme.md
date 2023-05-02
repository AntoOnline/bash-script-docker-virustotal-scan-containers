# Docker Backup and VirusTotal Scanner

This is a Bash script that backs up Docker images or containers, and then scans them using VirusTotal. The script uploads the Docker tar files to VirusTotal for analysis. Please read Virus Total's terms of service before using this script.

## Disclaimer

1. Use this code at your own risk.
2. The file is uploaded to VirusTotal for analysis. Please read Virus Total's terms of service before using this script.
3. VirusTotal shares uploaded files with their partners, which may include antivirus companies, researchers, and other organizations. Be cautious when uploading sensitive or proprietary files.

## How to get a VirusTotal API Key

To use this script, you will need a VirusTotal API key. Follow these steps to obtain one:

1. Visit [VirusTotal](https://www.virustotal.com/) and sign up for a free account.
2. After signing up, log in to your account.
3. Navigate to your [API Key](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey) page by clicking your username in the top-right corner and selecting "API Key."
4. Your API key will be displayed on the page. Copy it and use it as the `VIRUS_TOTAL_API_KEY` value when running the script.

## Usage

```bash
./vt_scan_containers.sh --OUTPUT_FOLDER=PATH --VIRUS_TOTAL_API_KEY=KEY --EXPORT_TYPE=[image/container] [--SLACK_WEB_HOOK=URL]
```

Example:

```
./vt_scan_containers.sh --OUTPUT_FOLDER=/mnt/container_backups/ --VIRUS_TOTAL_API_KEY=e4c0f729f84EXAMPLE539a280000000 --EXPORT_TYPE=container --SLACK_WEB_HOOK=https://hooks.slack.com/services/example/example/example
```

### Options

- `--BASE_FOLDER`: Path to the folder where the Docker backups and results will be stored.
- `--VIRUS_TOTAL_API_KEY`: Your VirusTotal API key.
- `--EXPORT_TYPE`: Export type can be either `image` or `container`.
- `--SLACK_WEB_HOOK` (Optional): Slack webhook URL to send notifications.

## Dependencies

- Docker
- cincan/virustotal Docker image
- cURL (for sending Slack notifications)

Make sure you have Docker installed and the `cincan/virustotal` Docker image available.

## How It Works

1. The script first checks for the required dependencies.
2. It exports the Docker images or containers based on the provided `EXPORT_TYPE`.
3. The exported tar files are scanned using the VirusTotal API.
4. The script waits for VirusTotal to analyze the files.
5. The analysis results are checked for malicious or suspicious content.
6. Notifications are sent to the provided Slack webhook URL if any malicious or suspicious content is detected.

Example console output:

```
Starting the container/image backup and scans.

Create the OUTPUT_FOLDER: /mnt/container_backups/

Delete all files in the OUTPUT_FOLDER that does not contain .virus

Exporting all containers (running and stopped):
nifty_goodall

nifty_goodall:
- Docker save container nifty_goodall to /mnt/container_backups/nifty_goodall.tar

Finished exporting all images/containers.

Scanning tar file: /mnt/container_backups/nifty_goodall.tar
- Upload tar file to VirusTotal for scanning: nifty_goodall.tar
- Received result: /files/nifty_goodall.tar NTNlMTU3ZDQzNDAwYTkzZjEzNjAzZjA4ODY3MWRhZWU6MTY4MzAyNzkxOA==

Sleeping for 30 seconds to give VirusTotal time to scan the file.

Analyzing result file: nifty_goodall.tar.result
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal is still scanning. Retrying in 15 seconds - 0/16
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal is still scanning. Retrying in 30 seconds - 1/16
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal is still scanning. Retrying in 60 seconds - 2/16
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal is still scanning. Retrying in 120 seconds - 3/16
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal is still scanning. Retrying in 240 seconds - 4/16
- Store analysis result in file: nifty_goodall.tar.result.analysis
- VirusTotal gave a status of completed. - 5/16
☣ Possible malicious or suspicious file in: /files/nifty_goodall.tar NTNlMTU3ZDQzNDAwYTkzZjEzNjAzZjA4ODY3MWRhZWU6MTY4MzAyNzkxOA==
```

## Want to connect?

Feel free to contact me on [Twitter](https://twitter.com/OnlineAnto), [DEV Community](https://dev.to/antoonline/) or [LinkedIn](https://www.linkedin.com/in/anto-online) if you have any questions or suggestions.

Or just visit my [website](https://anto.online) to see what I do.
