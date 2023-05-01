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
./vt_scan_containers.sh --BASE_FOLDER=PATH --VIRUS_TOTAL_API_KEY=KEY --EXPORT_TYPE=[image/container] [--SLACK_WEB_HOOK=URL] [--DEBUG]
```

Example:

```
./vt_scan_containers.sh --BASE_FOLDER=/mnt/container_backups/ --VIRUS_TOTAL_API_KEY=e4c0f729f84EXAMPLE539a280000000 --EXPORT_TYPE=container --SLACK_WEB_HOOK=https://hooks.slack.com/services/example/example/example
```

### Options

- `--BASE_FOLDER`: Path to the folder where the Docker backups and results will be stored.
- `--VIRUS_TOTAL_API_KEY`: Your VirusTotal API key.
- `--EXPORT_TYPE`: Export type can be either `image` or `container`.
- `--SLACK_WEB_HOOK` (Optional): Slack webhook URL to send notifications.
- `--DEBUG` (Optional): Run the script in debug mode. This will only do one container/image as a test run.

## Dependencies

- Docker
- cincan/virustotal Docker image

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
Docker save container dcl to /mnt/container_backups/dcl.tar
Docker save container portainer to /mnt/container_backups/portainer.tar
Upload tar file to VirusTotal for scanning: dcl.tar
Received result: /files/dcl.tar YmVlMDliODFjMjkwZDk1MmQ5YTk3Nj==
Upload tar file to VirusTotal for scanning: portainer.tar
Received result: /files/portainer.tar MzhlMjM0ZDY1NTA2N2IxNjkwM==
Sleeping for 1 minute to give VirusTotal time to scan the file.
Analyzing result file: dcl.tar.result
VirusTotal is still scanning. Retrying in 10 seconds - 0/30
VirusTotal is still scanning. Retrying in 10 seconds - 1/30
VirusTotal is still scanning. Retrying in 10 seconds - 2/30
VirusTotal is still scanning. Retrying in 10 seconds - 3/30
VirusTotal is still scanning. Retrying in 10 seconds - 4/30
VirusTotal is still scanning. Retrying in 10 seconds - 5/30
VirusTotal is still scanning. Retrying in 10 seconds - 6/30
VirusTotal is still scanning. Retrying in 10 seconds - 7/30
VirusTotal is still scanning. Retrying in 10 seconds - 8/30
VirusTotal is still scanning. Retrying in 10 seconds - 9/30
VirusTotal is still scanning. Retrying in 10 seconds - 10/30
VirusTotal is still scanning. Retrying in 10 seconds - 11/30
VirusTotal is still scanning. Retrying in 10 seconds - 12/30
VirusTotal is still scanning. Retrying in 10 seconds - 13/30
VirusTotal is still scanning. Retrying in 10 seconds - 14/30
VirusTotal is still scanning. Retrying in 10 seconds - 15/30
VirusTotal is still scanning. Retrying in 10 seconds - 16/30
VirusTotal is still scanning. Retrying in 10 seconds - 17/30
No malicious or suspicious file found in dcl.tar.
Analyzing result file: portainer.tar.result
No malicious or suspicious file found in portainer.tar.
```

## Want to connect?

Feel free to contact me on [Twitter](https://twitter.com/OnlineAnto), [DEV Community](https://dev.to/antoonline/) or [LinkedIn](https://www.linkedin.com/in/anto-online) if you have any questions or suggestions.

Or just visit my [website](https://anto.online) to see what I do.
