import re
import json
import datetime
import logging # Added logging module

# --- Basic Logging Setup ---
# Configure logging to output to the console with a specific format and level
logging.basicConfig(
    level=logging.INFO, # Set the minimum level to log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# --- Configuration (Simulating parts of the initial design) ---

# 1. Log Sources (Simulated Input)
SAMPLE_LOGS = [
    "Oct 10 10:00:01 fedora-server systemd[1]: Starting Cleanup of Temporary Directories...",
    "Oct 10 10:00:05 fedora-server audit[1234]: AVC avc:  denied  { read } for  pid=5678 comm=\"httpd\" name=\"config.file\" dev=\"dm-0\" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:etc_t:s0 tclass=file permissive=0",
    "Oct 10 10:00:10 fedora-server myapp[6789]: ERROR: Failed to connect to database [Errno 111] Connection refused",
    "Oct 10 10:00:15 fedora-server kernel: [ 123.456789] usb 1-1: New USB device found, idVendor=abcd, idProduct=1234",
    "Oct 10 10:00:20 fedora-server sshd[7890]: Accepted publickey for user_x from 192.168.1.100 port 54321 ssh2: RSA SHA256:...",
    "Oct 10 10:00:22 fedora-server myapp[6789]: INFO: User 'admin' logged in successfully.",
    "Oct 10 10:00:25 some-other-host unknown_service: This log won't match known patterns.", # Added unmatched log
]

# 2. Preprocessing Engine (Basic Regex Examples)
LOG_PATTERNS = {
    'systemd': re.compile(r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>systemd\[\d+\]):\s+(?P<message>.*)"),
    'audit': re.compile(r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+audit\[(?P<pid>\d+)\]:\s+(?P<message>.*)"),
    'custom_app': re.compile(r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>myapp\[\d+\]):\s+(?P<level>INFO|ERROR|WARN|DEBUG):\s+(?P<message>.*)"),
    'kernel': re.compile(r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+kernel:\s+\[\s*(?P<uptime>\d+\.\d+)\]\s+(?P<message>.*)"),
    'sshd': re.compile(r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>sshd\[\d+\]):\s+(?P<message>.*)"),
}

# --- Core Functions (Representing Flowchart Stages) ---

def collect_logs():
    """
    Simulates the Bash Collection Layer.
    Yields raw log lines.
    """
    logging.info("Simulating log collection...") # Use logging
    for log_line in SAMPLE_LOGS:
        yield log_line
    logging.info("Finished log simulation.") # Use logging


def preprocess_log(raw_log_line):
    """
    Simulates the Preprocessing Engine.
    Attempts to parse, normalize, and structure the log line.
    Returns a dictionary (Structured Data) or None if parsing fails.
    """
    logging.debug(f"Attempting to preprocess: {raw_log_line[:100]}...") # Use logging (DEBUG level)
    for log_type, pattern in LOG_PATTERNS.items():
        match = pattern.match(raw_log_line)
        if match:
            logging.debug(f"Matched pattern: {log_type}") # Use logging (DEBUG level)
            structured_data = match.groupdict()
            structured_data['log_type'] = log_type
            structured_data['raw_log'] = raw_log_line

            # Basic Normalization Placeholder (e.g., timestamp)
            try:
                ts_str = structured_data.get('timestamp')
                if ts_str:
                    current_year = datetime.datetime.now().year
                    dt_obj = datetime.datetime.strptime(f"{ts_str} {current_year}", "%b %d %H:%M:%S %Y")
                    structured_data['@timestamp'] = dt_obj.isoformat()
            except ValueError as e:
                logging.warning(f"Failed to parse timestamp '{ts_str}': {e}", exc_info=False) # Use logging
                structured_data['@timestamp'] = None

            # Placeholder for more processing
            if log_type == 'audit' and 'message' in structured_data:
                 if 'denied' in structured_data['message']:
                     structured_data['audit_action'] = 'denied'

            return structured_data

    # If no pattern matched
    logging.warning(f"Failed to parse log (no pattern matched): {raw_log_line[:100]}...") # Use logging
    return None


def analyze_log(structured_data):
    """
    Simulates the Hybrid AI Analysis Engine.
    Returns analysis results.
    """
    logging.debug(f"Analyzing log type: {structured_data.get('log_type')}") # Use logging (DEBUG level)
    analysis = {
        'label': 'Normal',
        'confidence': 0.9,
        'explanation': 'Standard log entry.',
        'mitre_ttp': None
    }

    log_type = structured_data.get('log_type')
    message = structured_data.get('message', '').lower()

    # --- Simple Rule-Based/Keyword Analysis ---
    if log_type == 'custom_app' and 'error' in structured_data.get('level', '').lower():
        analysis['label'] = 'Error'
        analysis['confidence'] = 0.8
        analysis['explanation'] = 'Application reported an error.'
        logging.info(f"Detected 'Error' label for custom_app log.") # Use logging
    elif log_type == 'audit' and 'denied' in message:
         analysis['label'] = 'Security Alert'
         analysis['confidence'] = 0.75
         analysis['explanation'] = 'Potential SELinux denial detected.'
         analysis['mitre_ttp'] = 'T1222'
         logging.info(f"Detected 'Security Alert' label for audit log.") # Use logging
    elif 'failed' in message or 'refused' in message:
        analysis['label'] = 'Warning'
        analysis['confidence'] = 0.6
        analysis['explanation'] = 'Operation failed or connection refused.'
        logging.info(f"Detected 'Warning' label based on keywords.") # Use logging
    elif log_type == 'sshd' and 'accepted publickey' in message:
         analysis['label'] = 'Informational'
         analysis['confidence'] = 0.95
         analysis['explanation'] = 'Successful SSH login.'
         # logging.debug("Detected informational SSH login.") # Example DEBUG log

    # --- Placeholder for LLM Enhancement ---
    # if analysis['confidence'] < 0.7:
    #    logging.info("Confidence below threshold, considering LLM enhancement.") # Use logging
    #    # ... LLM logic ...

    return analysis


def prioritize_and_store(structured_data, analysis_result):
    """
    Simulates the Priority Engine and Storage & Export.
    Prints high-priority events.
    """
    if analysis_result['label'] != 'Normal' and analysis_result['label'] != 'Informational': # Adjusted condition
        priority_score = 0
        if analysis_result['label'] == 'Security Alert':
            priority_score = 8
        elif analysis_result['label'] == 'Error':
            priority_score = 6
        elif analysis_result['label'] == 'Warning':
            priority_score = 4
        else:
            priority_score = 2 # Should not happen with current logic if Normal/Info excluded

        logging.info(f"Prioritizing event: Label={analysis_result['label']}, Score={priority_score}") # Use logging

        # Output the alert (using print for now, as it's the main output)
        print("-" * 70)
        print(f"🚨 ALERT DETECTED (Priority: {priority_score}) 🚨")
        print(f"  Label:       {analysis_result['label']}")
        print(f"  Confidence:  {analysis_result['confidence']:.2f}")
        print(f"  Explanation: {analysis_result['explanation']}")
        if analysis_result['mitre_ttp']:
            print(f"  MITRE TTP:   {analysis_result['mitre_ttp']}")
        print(f"  Timestamp:   {structured_data.get('@timestamp', 'N/A')}")
        print(f"  Log Type:    {structured_data.get('log_type', 'N/A')}")
        print(f"  Raw Log:     {structured_data['raw_log']}")
        print("-" * 70)

        # Placeholder for Storage
        # logging.info("Storing alert to database/SIEM...") # Use logging
        # store_in_db(structured_data, analysis_result, priority_score)

    else:
         logging.debug(f"Ignoring event with label '{analysis_result['label']}'.") # Use logging (DEBUG level)


# --- Main Execution Flow ---

if __name__ == "__main__":
    logging.info("Starting AI Log Analyzer Prototype...") # Use logging

    log_generator = collect_logs()

    processed_count = 0
    alert_count = 0
    parse_failures = 0

    for raw_log in log_generator:
        structured_log = preprocess_log(raw_log)

        if structured_log:
            processed_count += 1
            analysis = analyze_log(structured_log)
            prioritize_and_store(structured_log, analysis)
            if analysis['label'] not in ['Normal', 'Informational']:
                 alert_count += 1
        else:
            parse_failures += 1

    logging.info(f"Processing complete. Processed={processed_count}, Alerts={alert_count}, Parse Failures={parse_failures}") # Use logging
    logging.info("AI Log Analyzer Prototype Finished.") # Use logging