#!/bin/bash
#
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
RETRY_INTERVAL=60

# Sleep seconds after uploading all files to VirusTotal
SLEEP_TIME_AFTER_ALL_FILES_UPLOADED=180

# Emojis
VIRUS_FOUND=$(echo -e "\U2623")
NO_VIRUS_FOUND=$(echo -e "\U2714")

# Function to print usage instructions
print_usage() {
  echo "Usage: $0 --OUTPUT_FOLDER=PATH --VIRUS_TOTAL_API_KEY=KEY --EXPORT_TYPE=[image/container] [--SLACK_WEB_HOOK=URL]"
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
    local OUTPUT_FOLDER="$3"
    local item_id_safe="$4"

    if [ "$EXPORT_TYPE" = "image" ]; then
        printf "\n$item_id:\n"

        command_create="docker create '$item_id'"
        printf -- "- Creating a temporary container from image %s\n" "$item_id"
        local container_id=$(eval "$command_create")
        echo "$command_create" >> "${OUTPUT_FOLDER}commands.log"

        command_export="docker export '$container_id' > '${OUTPUT_FOLDER}${item_id_safe}.tar'"
        printf -- "- Docker export container %s (from image %s) to %s%s.tar\n" "$container_id" "$item_id" "$OUTPUT_FOLDER" "$item_id_safe"
        eval "$command_export" 2>/dev/null
        echo "$command_export" >> "${OUTPUT_FOLDER}commands.log"

        command_rm="docker rm '$container_id'"
        printf -- "- Removing temporary container %s\n" "$container_id"
        eval "$command_rm" > /dev/null 2>&1
        echo "$command_rm" >> "${OUTPUT_FOLDER}commands.log"

    elif [ "$EXPORT_TYPE" = "container" ]; then
        printf "\n$item_id:\n"

        command_export="docker export '$item_id' > '${OUTPUT_FOLDER}${item_id_safe}.tar'"
        printf -- "- Docker save container %s to %s%s.tar\n" "$item_id" "$OUTPUT_FOLDER" "$item_id_safe"
        eval "$command_export" 2>/dev/null
        echo "$command_export" >> "${OUTPUT_FOLDER}commands.log"
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
    --OUTPUT_FOLDER=*)
      OUTPUT_FOLDER="${arg#*=}"
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
    *)
      print_usage
      ;;
  esac
done

# Check if OUTPUT_FOLDER and VIRUS_TOTAL_API_KEY are provided
if [[ -z "$OUTPUT_FOLDER" || -z "$VIRUS_TOTAL_API_KEY" || -z "$EXPORT_TYPE" ]]; then
  print_usage
fi

# Check if EXPORT_TYPE is valid
if [[ "$EXPORT_TYPE" != "image" && "$EXPORT_TYPE" != "container" ]]; then
  echo "Invalid EXPORT_TYPE. Exiting."
  exit 1
fi

# Make sure OUTPUT_FOLDER ends with a slash
if [[ "$OUTPUT_FOLDER" != */ ]]; then
  OUTPUT_FOLDER="${OUTPUT_FOLDER}/"
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Exiting."
  exit 1
fi

# Starting script
printf "\n\nStarting the container/image backup and scans.\n\n"

# Delete and recreate the OUTPUT_FOLDER
printf "Create the OUTPUT_FOLDER: $OUTPUT_FOLDER\n\n"

# Create the OUTPUT_FOLDER if it does not exist
if [ ! -d "$OUTPUT_FOLDER" ]; then
  mkdir -p "$OUTPUT_FOLDER"
fi

# Set permissions to 555
chmod 555 -R "$OUTPUT_FOLDER"

# Delete all files in the OUTPUT_FOLDER that does not contain .virus
printf "Delete all files in the OUTPUT_FOLDER that does not contain .virus\n\n"
find "$OUTPUT_FOLDER" -type f ! -name "*.virus" -delete

# Export image or container
format_string="{{.Names}}"
if [ "$EXPORT_TYPE" = "image" ]; then
    # Images do not contain the mounted volumes
    format_string="{{.ID}}"
elif [ "$EXPORT_TYPE" = "container" ]; then
    format_string="{{.Names}}"
fi

if [ "$EXPORT_TYPE" = "image" ]; then
  item_ids=$(docker images --format "{{.Repository}}:{{.Tag}}" | sort -u)
  printf "Exporting all images:\n${item_ids}\n"
else
  item_ids=$(docker ps -a --format "$format_string" | sort -u)
  printf "Exporting all containers (running and stopped):\n${item_ids} \n"
fi

# Use to debug a single image/container
#item_ids="cincan/virustotal"

for item_id in $item_ids; do
  # check if the item id is not empty
  item_id_safe=$(sanitize_item_id "$item_id")
  if [[ -n "$item_id" ]]; then
    backup_docker_item "$EXPORT_TYPE" "$item_id" "$OUTPUT_FOLDER" "$item_id_safe"
    continue
  fi
done

printf "\nFinished exporting all images/containers.\n\n"

# Scan the exported tar files with VirusTotal
for tar_file in "${OUTPUT_FOLDER}"*.tar; do
    printf "Scanning tar file: $tar_file\n"

    # check if the file is larger than xMB for the public api, if so, skip it
    if [[ $(stat -c%s "$tar_file") -gt $MAX_FILE_SIZE_TO_SCAN ]]; then
        printf -- "- Skipping and removing %s as it is larger than %d bytes.\n\n" "$tar_file" "$MAX_FILE_SIZE_TO_SCAN"
        rm "$tar_file"
        continue
    fi

    tar_file_name=$(basename "$tar_file")
    result_file="${tar_file}.result"
    analysis_file="${result_file}.analysis"

    # Perform VirusTotal scan
    printf -- "- Upload tar file to VirusTotal for scanning: %s\n" "$tar_file_name"
    command="docker run --rm -v '${OUTPUT_FOLDER}:/files' $VIRUS_TOTAL_DOCKER_IMAGE -k $VIRUS_TOTAL_API_KEY scan file '/files/${tar_file_name}'"
    result=$(eval "$command")
    echo "$command" >> "${OUTPUT_FOLDER}commands.log"
    printf -- "- Received result: %s\n\n" "${result}"

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
printf "\n"

# Scan the exported tar files with VirusTotal
for tar_file in "${OUTPUT_FOLDER}"*.tar; do
    tar_file_name=$(basename "${tar_file}")
    result_file="${tar_file}.result"
    analysis_file="${result_file}.analysis"

    # Loop until the text 'status: "completed"' is found in the result file
    printf "Analyzing result file: %s\n" "$(basename "$result_file")"
    result_content=$(cat "$result_file" | tr -d '\r')

    completed=false
    retries=0
    while [ "$retries" -lt "$MAX_RETRIES" ] && [ "$completed" = false ]; do
        command_analysis="docker run --rm -v '${OUTPUT_FOLDER}:/files' $VIRUS_TOTAL_DOCKER_IMAGE -k $VIRUS_TOTAL_API_KEY analysis $result_content"
        analysis=$(eval "$command_analysis")
        echo "$command_analysis" >> "${OUTPUT_FOLDER}commands.log"
        printf -- "- Store analysis result in file: %s\n" "$(basename "$analysis_file")"
        printf "%s\n" "$analysis" > "$analysis_file"

        if grep -q "status" "$analysis_file" && grep -q "completed" "$analysis_file"; then
            printf -- "- VirusTotal gave a status of completed. - %s/%s\n" "$retries" "$MAX_RETRIES"
            completed=true
        else
            backoff_time=$((2**retries * RETRY_INTERVAL))
            printf -- "- VirusTotal is still scanning. Retrying in $backoff_time seconds - %s/%s\n" "$retries" "$MAX_RETRIES"
            sleep $backoff_time
            retries=$((retries + 1))
        fi
    done

    if [ "$retries" -eq "$MAX_RETRIES" ]; then
        echo -- "- Error: Reached the maximum number of retries. Skip.\n\n"
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
    malicious_or_suspicious_detected=$(grep -E 'category: "malicious"|category: "suspicious"' "$analysis_file")

    if [ -n "$malicious_or_suspicious_detected" ]; then
      slack_message="Possible malicious or suspicious file in: ${result_content}"
      echo -e "$VIRUS_FOUND ${slack_message}\n"
      send_slack_notification $SLACK_WEB_HOOK "${slack_message}"

      # Rename the tar file to indicate that it contains a virus
      mv "$analysis_file" "${analysis_file}.virus"
    else
        printf "%s No malicious or suspicious file found in %s.\n\n" "$NO_VIRUS_FOUND" "$tar_file_name"
    fi
done


