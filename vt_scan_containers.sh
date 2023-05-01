#!/bin/bash

# Script to backup docker images and containers and scan them with VirusTotal
#
# Currently only EXPORT_TYPE=container is supported. Image uploads but the status always remains "queued".
#
# Disclaimer :
#
# 1) Use this code at your own risk.
# 2) The file is uploaded to VirusTotal for analysis. Please read Virus Total's terms of service before using this script.
#
# Visit http://anto.online for more information or give a like on GitHub: https://github.com/AntoOnline/bash-script-docker-virustotal-scan-containers
#

# Docker image to use for VirusTotal scanning
VIRUS_TOTAL_DOCKER_IMAGE="cincan/virustotal"

# Max bytes to scan (600MB)
MAX_FILE_SIZE_TO_SCAN=629145600

# Max number of retries to check the scan status
MAX_RETRIES=16

# Number of seconds to wait between retries
RETRY_INTERVAL=15

# Sleep seconds after uploading all files to VirusTotal
SLEEP_TIME_AFTER_ALL_FILES_UPLOADED=30

# Emojis
VIRUS_FOUND=$(echo -e "\U2623")
NO_VIRUS_FOUND=$(echo -e "\U2714")

# Function to print usage instructions
print_usage() {
  echo "Usage: $0 --BASE_FOLDER=PATH --VIRUS_TOTAL_API_KEY=KEY --EXPORT_TYPE=[image/container] [--SLACK_WEB_HOOK=URL] [--DEBUG]"
  exit 1
}

# Function to sanitize the item id and remove / space and dots
sanitize_item_id() {
    local item_id="$1"
    local item_id_safe

    # Remove / and : and . and spaces
    item_id_safe=$(echo "$item_id" | tr -d '/: .')

    # Remove she word "sha" from the beginning of the string
    item_id_safe=$(echo "$item_id_safe" | sed 's/^sha//')

    echo "$item_id_safe"
}

# Function to backup a docker item (image or container)
backup_docker_item() {
    local EXPORT_TYPE="$1"
    local item_id="$2"
    local BASE_FOLDER="$3"
    local item_id_safe="$4"

    if [ "$EXPORT_TYPE" = "image" ]; then
        # Images somehow always return resource not found when using docker save - this is a workaround
        # instead of: docker save "$item_id" > "${BASE_FOLDER}${item_id_safe}.tar"
        # The docker create command initializes a container based on the specified image, but it doesn't start the container or run any processes in it.
        echo "Creating a temporary container from image $item_id"
        local container_id=$(docker create "$item_id")

        echo "Docker export container $container_id (from image $item_id) to ${BASE_FOLDER}${item_id_safe}.tar"
        docker export "$container_id" > "${BASE_FOLDER}${item_id_safe}.tar" 2>/dev/null

        echo "Removing temporary container $container_id"
        docker rm "$container_id" > /dev/null 2>&1
    elif [ "$EXPORT_TYPE" = "container" ]; then
        echo "Docker save container $item_id to ${BASE_FOLDER}${item_id_safe}.tar"
        docker export "$item_id" > "${BASE_FOLDER}${item_id_safe}.tar" 2>/dev/null
    fi
}

# Function send a Slack notification
send_slack_notification() {
    local SLACK_WEB_HOOK="$1"
    local slack_message="$2"

    if [[ -n "$SLACK_WEB_HOOK" ]]; then
        curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$slack_message\"}" "$SLACK_WEB_HOOK"
    fi
}

# Parse arguments
for arg in "$@"; do
  case $arg in
    --BASE_FOLDER=*)
      BASE_FOLDER="${arg#*=}"
      shift
      ;;
    --VIRUS_TOTAL_API_KEY=*)
      VIRUS_TOTAL_API_KEY="${arg#*=}"
      shift
      ;;
    --EXPORT_TYPE=*)
      EXPORT_TYPE="${arg#*=}"
      shift
      ;;
    --SLACK_WEB_HOOK=*)
      SLACK_WEB_HOOK="${arg#*=}"
      shift
      ;;
    --DEBUG)
      DEBUG=true
      shift
      ;;
    *)
      print_usage
      ;;
  esac
done

# Check if BASE_FOLDER and VIRUS_TOTAL_API_KEY are provided
if [[ -z "$BASE_FOLDER" || -z "$VIRUS_TOTAL_API_KEY" || -z "$EXPORT_TYPE" ]]; then
  print_usage
fi

# Check if EXPORT_TYPE is valid
if [[ "$EXPORT_TYPE" != "image" && "$EXPORT_TYPE" != "container" ]]; then
  echo "Invalid EXPORT_TYPE. Exiting."
  exit 1
fi

# Make sure BASE_FOLDER ends with a slash
if [[ "$BASE_FOLDER" != */ ]]; then
  BASE_FOLDER="${BASE_FOLDER}/"
fi

# Set DEBUG to false if not provided
DEBUG=${DEBUG:-false}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Exiting."
  exit 1
fi

# Starting script
printf "\n\nStarting the container/image backup and scans.\n\n"

# Delete and recreate the BASE_FOLDER
rm -rf "$BASE_FOLDER"
mkdir -p "$BASE_FOLDER"
chmod 555 -R "$BASE_FOLDER"

# Export image or container
format_string="{{.Names}}"
if [ "$EXPORT_TYPE" = "image" ]; then
    # Images do not contain the mounted volumes
    format_string="{{.ID}}"
elif [ "$EXPORT_TYPE" = "container" ]; then
    format_string="{{.Names}}"
fi

if [ "$DEBUG" = true ]; then
  if [ "$EXPORT_TYPE" = "image" ]; then
    item_id=$(docker ps --format "$format_string" | xargs docker inspect --format '{{.Image}}' | sort -u | head -n 1)
  else
    item_id=$(docker ps --format "$format_string" | head -n 1)
  fi
  item_id_safe=$(sanitize_item_id "$item_id")
  backup_docker_item "$EXPORT_TYPE" "$item_id" "$BASE_FOLDER" "$item_id_safe"
else
  if [ "$EXPORT_TYPE" = "image" ]; then
    item_ids=$(docker ps --format "$format_string" | xargs docker inspect --format '{{.Image}}' | sort -u)
  else
    item_ids=$(docker ps --format "$format_string" | sort -u)
  fi

  for item_id in $item_ids; do
    item_id_safe=$(sanitize_item_id "$item_id")

    if [ "$EXPORT_TYPE" = "image" ]; then
      if docker image inspect "$item_id" > /dev/null 2>&1; then
          echo "Image $item_id exists."
      else
          echo "Image $item_id not found. Skipping export.\n\n"
          continue
      fi
    fi

    backup_docker_item "$EXPORT_TYPE" "$item_id" "$BASE_FOLDER" "$item_id_safe"
  done
fi

# Scan the exported tar files with VirusTotal
for tar_file in "${BASE_FOLDER}"*.tar; do
    # check if the file is larger than xMB for the public api, if so, skip it
    if [[ $(stat -c%s "$tar_file") -gt $MAX_FILE_SIZE_TO_SCAN ]]; then
        echo "Skipping and removing $tar_file as it is larger than $MAX_FILE_SIZE_TO_SCAN bytes.\n\n"
        rm "$tar_file"
        continue
    fi

    tar_file_name=$(basename "$tar_file")
    result_file="${tar_file}.result"
    analysis_file="${result_file}.analysis"

    # Perform VirusTotal scan
    echo "Upload tar file to VirusTotal for scanning: $tar_file_name"
    result=$(docker run --rm -v "${BASE_FOLDER}:/files" $VIRUS_TOTAL_DOCKER_IMAGE -k $VIRUS_TOTAL_API_KEY scan file "/files/${tar_file_name}")
    echo "Received result: ${result}"

    # Check if the result contains one space and two words, if not, exit the script and send a Slack notification
    if [[ $(echo "$result" | wc -w) -ne 2 ]]; then
        slack_message="Result not received for $tar_file_name."
        printf "%s\n" "$slack_message"
        send_slack_notification $SLACK_WEB_HOOK "${slack_message}"
        continue
    fi
    echo "$result" > $result_file
done

echo "Sleeping for $SLEEP_TIME_AFTER_ALL_FILES_UPLOADED seconds to give VirusTotal time to scan the file."
sleep $SLEEP_TIME_AFTER_ALL_FILES_UPLOADED

# Scan the exported tar files with VirusTotal
for tar_file in "${BASE_FOLDER}"*.tar; do
    tar_file_name=$(basename "${tar_file}")
    result_file="${tar_file}.result"
    analysis_file="${result_file}.analysis"

    # Loop until the text 'status: "completed"' is found in the result file
    printf "Analyzing result file: %s\n" "$(basename "$result_file")"
    result_content=$(cat "$result_file" | tr -d '\r')

    retries=0
    while [ "$retries" -lt "$MAX_RETRIES" ]; do
        analysis=$(docker run --rm -v "${BASE_FOLDER}:/files" $VIRUS_TOTAL_DOCKER_IMAGE -k $VIRUS_TOTAL_API_KEY analysis $result_content)
        printf "Store analysis result in file: %s\n" "$(basename "$analysis_file")"
        printf "%s\n" "$analysis" > "$analysis_file"

        if grep -q "status" "$analysis_file" && grep -q "completed" "$analysis_file"; then
            break
        else
            backoff_time=$((2**retries * RETRY_INTERVAL))
            printf "VirusTotal is still scanning. Retrying in $backoff_time seconds - %s/%s\n" "$retries" "$MAX_RETRIES"
            sleep $backoff_time
            retries=$((retries + 1))
        fi
    done

    if [ "$retries" -eq "$MAX_RETRIES" ]; then
        echo "Error: Reached the maximum number of retries. Skip.\n\n"
        continue
    fi

    # Double check if the analysis file was successfully created by looking for the word 'result'
    if ! grep -q "result" "$analysis_file"; then
        slack_message="Analysis file not created for $tar_file_name."
        printf "%s\n" "$slack_message"
        send_slack_notification $SLACK_WEB_HOOK "${slack_message}"
        continue
    fi

    # Check for malicious or suspicious results and send a Slack notification or print the result
    if ! (grep -q "malicious: 0" "$analysis_file" && grep -q "suspicious: 0" "$analysis_file"); then
        slack_message="$VIRUS_FOUND Possible malicious or suspicious file in:\n\`\`\`$(cat "$analysis_file")\`\`\`"
        printf "%s\n" "$slack_message"
        send_slack_notification $SLACK_WEB_HOOK "${slack_message}"
        printf "\n"

    else
        printf "$NO_VIRUS_FOUND No malicious or suspicious file found in %s.\n" "$tar_file_name"
        printf "\n"

    fi
done
