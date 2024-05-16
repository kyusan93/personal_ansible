import csv
import re
import json
from datetime import datetime

# Define patterns
LOG_SOURCE_PATTERN = r"and when the event\(s\) were detected by one or more of (.*)"
NOT_LOG_SOURCE_PATTERN = r"and NOT when the event\(s\) were detected by one or more of (.*)"
EVENT_CATEGORY_PATTERN = r"(?:and when|and where) the event category for the event is one of the following (.*)"
EVENT_ID_DETAILS_PATTERN = r"and when any of EventID \(custom\) are contained in any of (.*)"
EVENT_QID_DETAILS_PATTERN = r"(?:and when|and) the event QID is one of the following (.*)"
IP_PROTOCOL_PATTERN = r"and when the IP protocol is one of the following (.*)"
FLOW_TYPE_PATTERN = r"and when (?:the flow type|the flow|a flow|a flow or an event) (?:matches any of the following|is one of|matches Application is) (.*)"
ERROR_CODE_PATTERN = r"and when any of Error Code \(custom\)(?:, Sub Status \(custom\))? are contained in any of (.*)"
APPLICATION_PATTERN = r"and when the flow matches Application is any of (\[.*\])"
EVENT_SEVERITY_PATTERN = r"and (?:where|when) the Event Severity is (.*)"
EVENT_CREDIBILITY_PATTERN = r"and (?:where|when) the Event Credibility is (.*)"
EVENT_RELEVANCE_PATTERN = r"and (?:where|when) the Event Relevance is (.*)"
OBJECT_NAME_PATTERN = r"and when any of ObjectName \(custom\) are contained in any of (.*)"
EVENT_TYPE_PATTERN = r"and when (?:the|an|we see an) event (?:matches|match) (?:any|all) of the following (.*)"
EVENT_CONTEXT_PATTERN = r"and when the (?:event|) context is (.*)"
EVENT_ADDITIONAL_CONDITION_PATTERN = r"and when at least 1 of these (.*)"
SOURCE_BYTE_PACKET_RATIO_PATTERN = r"and when the source byte/packet ratio is (.*)"
DESTINATION_BYTE_PACKET_RATIO_PATTERN = r"and when the destination byte/packet ratio is (.*)"
DESTINATION_BYTES_PATTERN = r"and when the destination bytes is (.*)"
SOURCE_BYTES_PATTERN = r"and when the source bytes is (.*)"
SOURCE_OR_DESTINATION_IP_PATTERN = r"and (?:when|where) (?:either the source or destination IP is one of the following|any of Destination IP, Source IP are contained in any of|the any IP is a part of any of the following) (.*)"
SOURCE_IP_PATTERN = r"and (?:when|where) the (?:S|s)ource IP is (?:a part of any|one) of the following (.*)"
LOCAL_NETWORK_PATTERN = r"and when the local network is (.*)"
DESTINATION_IP_PATTERN = r"and when the destination IP is a part of any of the following (.*)"
SOURCE_IP_PATTERN = r"and when the source IP is a part of any of the following (.*)"
SOURCE_OR_DESTINATION_PORT_PATTERN = r"and when the source or destination port is any of (.*)"
DESTINATION_PORT_PATTERN = r"and when the destination port is one of the following (.*)"
SOURCE_PORT_PATTERN = r"and when the source port is one of the following (.*)"
DESTINATION_PACKETS_PATTERN = r"and when the destination packets is (.*)"
SOURCE_PACKETS_PATTERN = r"and when the source packets is (.*)"
SOURCE_PATTERN = r"and when the source is (.*)"
DESTINATION_PATTERN = r"and when the destination is (.*)"
NUMBER_OF_LOCALHOST_PATTERN = r"and when the number of local hosts is (.*)"
IDENTITY_MAC_PATTERN = r"and when the identity MAC matches the following (.*)"
USERNAME_PATTERN = r"and when any of Username are contained in any of (.*)"
ATTACK_CONTEXT_PATTERN = r"and where the attack context is (.*)"
FLOW_BIAS_PATTERN = r"and when the flow bias is (.*)"

def extract_log_source(tests):
    log_source_match = re.search(LOG_SOURCE_PATTERN, tests, re.IGNORECASE)
    if log_source_match:
        return log_source_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_not_log_source(tests):
    not_log_source_match = re.search(NOT_LOG_SOURCE_PATTERN, tests, re.IGNORECASE)
    if not_log_source_match:
        return not_log_source_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_category(tests):
    event_category_match = re.search(EVENT_CATEGORY_PATTERN, tests, re.IGNORECASE)
    if event_category_match:
        return event_category_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_id_details(tests):
    event_id_details_match = re.search(EVENT_ID_DETAILS_PATTERN, tests, re.IGNORECASE)
    if event_id_details_match:
        return event_id_details_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_id(event_id_details):
    event_id_match = re.findall(r"\bEventID\s+(\d+)\b", event_id_details, re.IGNORECASE)
    if event_id_match:
        return "\n".join(event_id_match)
    else:
        return ""

def extract_event_qid_details(tests):
    event_qid_details_match = re.search(EVENT_QID_DETAILS_PATTERN, tests, re.IGNORECASE)
    if event_qid_details_match:
        return event_qid_details_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_qid(event_qid_details):
    event_qid_match = re.findall(r"\((\d+)\)", event_qid_details)
    if event_qid_match:
        return "\n".join(event_qid_match)
    else:
        return ""

def extract_ip_protocol(tests):
    ip_protocol_match = re.search(IP_PROTOCOL_PATTERN, tests, re.IGNORECASE)
    if ip_protocol_match:
        return ip_protocol_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_flow_type(tests, flow_type_map):
    flow_type_match = re.search(FLOW_TYPE_PATTERN, tests, re.IGNORECASE)
    if flow_type_match:
        original_flow_types = flow_type_match.group(1).split(",")
        flow_type_descriptions = []
        for original_flow_type in original_flow_types:
            original_flow_type = original_flow_type.strip()
            if original_flow_type in flow_type_map:
                flow_type_descriptions.append(
                    f"{original_flow_type} - {flow_type_map[original_flow_type]}"
                )
            else:
                flow_type_descriptions.append(original_flow_type)
        return "\n".join(flow_type_descriptions)
    else:
        return ""

def extract_error_code(tests):
    error_code_match = re.search(ERROR_CODE_PATTERN, tests, re.IGNORECASE)
    if error_code_match:
        return error_code_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_application(tests):
    application_match = re.search(APPLICATION_PATTERN, tests, re.IGNORECASE)
    if application_match:
        applications = re.findall(r"\[([^]]+)\]", application_match.group(1))
        application_list = []
        for app in applications:
            app = app.strip().replace(" or ", "\n")
            application_list.append(app)
        return "\n".join(application_list)
    else:
        return ""

def extract_object_name(tests):
    object_name_match = re.search(OBJECT_NAME_PATTERN, tests, re.IGNORECASE)
    if object_name_match:
        return object_name_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_severity(tests):
    event_severity_match = re.search(EVENT_SEVERITY_PATTERN, tests, re.IGNORECASE)
    if event_severity_match:
        return event_severity_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_credibility(tests):
    event_credibility_match = re.search(EVENT_CREDIBILITY_PATTERN, tests, re.IGNORECASE)
    if event_credibility_match:
        return event_credibility_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_relevance(tests):
    event_relevance_match = re.search(EVENT_RELEVANCE_PATTERN, tests, re.IGNORECASE)
    if event_relevance_match:
        return event_relevance_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_type(tests):
    event_type_match = re.search(EVENT_TYPE_PATTERN, tests, re.IGNORECASE)
    if event_type_match:
        return event_type_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_context(tests):
    event_context_match = re.search(EVENT_CONTEXT_PATTERN, tests, re.IGNORECASE)
    if event_context_match:
        return event_context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_additional_condition(tests):
    event_additional_condition_match = re.search(EVENT_ADDITIONAL_CONDITION_PATTERN, tests, re.IGNORECASE)
    if event_additional_condition_match:
        return event_additional_condition_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_byte_packet_ratio(tests):
    source_byte_packet_ratio_match = re.search(SOURCE_BYTE_PACKET_RATIO_PATTERN, tests, re.IGNORECASE)
    if source_byte_packet_ratio_match:
        return source_byte_packet_ratio_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_destination_byte_packet_ratio(tests):
    destination_byte_packet_ratio_match = re.search(DESTINATION_BYTE_PACKET_RATIO_PATTERN, tests, re.IGNORECASE)
    if destination_byte_packet_ratio_match:
        return destination_byte_packet_ratio_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_bytes(tests):
    source_bytes_match = re.search(SOURCE_BYTES_PATTERN, tests, re.IGNORECASE)
    if source_bytes_match:
        return source_bytes_match.group(1)
    else:
        return ""

def extract_destination_bytes(tests):
    destination_bytes_match = re.search(DESTINATION_BYTES_PATTERN, tests, re.IGNORECASE)
    if destination_bytes_match:
        return destination_bytes_match.group(1)
    else:
        return ""

def extract_source_or_destination_ip(tests):
    source_or_destination_ip_match = re.search(SOURCE_OR_DESTINATION_IP_PATTERN, tests, re.IGNORECASE)
    if source_or_destination_ip_match:
        return source_or_destination_ip_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_attack_context(tests):
    attack_context_match = re.search(ATTACK_CONTEXT_PATTERN, tests, re.IGNORECASE)
    if attack_context_match:
        return attack_context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_destination_ip(tests):
    destination_ip_match = re.search(DESTINATION_IP_PATTERN, tests, re.IGNORECASE)
    if destination_ip_match:
        return destination_ip_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_or_destination_ip(tests):
    source_or_destination_ip_match = re.search(SOURCE_OR_DESTINATION_IP_PATTERN, tests, re.IGNORECASE)
    if source_or_destination_ip_match:
        return source_or_destination_ip_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source(tests):
    source_match = re.search(SOURCE_PATTERN, tests, re.IGNORECASE)
    if source_match:
        return source_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_destination(tests):
    destination_match = re.search(DESTINATION_PATTERN, tests, re.IGNORECASE)
    if destination_match:
        return destination_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_identity_mac(tests):
    identity_mac_match = re.search(IDENTITY_MAC_PATTERN, tests, re.IGNORECASE)
    if identity_mac_match:
        return identity_mac_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_username(tests):
    username_match = re.search(USERNAME_PATTERN, tests, re.IGNORECASE)
    if username_match:
        return username_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_attack_context(tests):
    attack_context_match = re.search(ATTACK_CONTEXT_PATTERN, tests, re.IGNORECASE)
    if attack_context_match:
        return attack_context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_used_by_building_blocks(data_dicts):
    for data_dict in data_dicts:
        rule_name = data_dict["Rule Name"]
        for other_dict in data_dicts:
            if (
                rule_name in other_dict["Tests"]
                and other_dict["Building Block"] == "TRUE"
            ):
                if data_dict["Used by Building Blocks"]:
                    data_dict["Used by Building Blocks"] += "\n"
                data_dict["Used by Building Blocks"] += other_dict["Rule Name"]

def extract_used_by_use_cases(data_dicts):
    for data_dict in data_dicts:
        rule_name = data_dict["Rule Name"]
        for other_dict in data_dicts:
            if (
                rule_name in other_dict["Tests"]
                and other_dict["Building Block"] == "FALSE"
            ):
                if data_dict["Used by Use Cases"]:
                    data_dict["Used by Use Cases"] += "\n"
                data_dict["Used by Use Cases"] += other_dict["Rule Name"]

def extract_destination_ip(tests):
    destination_ip_match = re.search(DESTINATION_IP_PATTERN, tests, re.IGNORECASE)
    if destination_ip_match:
        return destination_ip_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_ip(tests):
    source_ip_match = re.search(SOURCE_IP_PATTERN, tests, re.IGNORECASE)
    if source_ip_match:
        return source_ip_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_destination_port(tests):
    destination_port_match = re.search(DESTINATION_PORT_PATTERN, tests, re.IGNORECASE)
    if destination_port_match:
        return destination_port_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_port(tests):
    source_port_match = re.search(SOURCE_PORT_PATTERN, tests, re.IGNORECASE)
    if source_port_match:
        return source_port_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_destination_packets(tests):
    destination_packets_match = re.search(DESTINATION_PACKETS_PATTERN, tests, re.IGNORECASE)
    if destination_packets_match:
        return destination_packets_match.group(1)
    else:
        return ""

def extract_source_packets(tests):
    source_packets_match = re.search(SOURCE_PACKETS_PATTERN, tests, re.IGNORECASE)
    if source_packets_match:
        return source_packets_match.group(1)
    else:
        return ""

def extract_local_network(tests):
    local_network_match = re.search(LOCAL_NETWORK_PATTERN, tests, re.IGNORECASE)
    if local_network_match:
        return local_network_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_number_of_localhost(tests):
    number_of_localhost_match = re.search(NUMBER_OF_LOCALHOST_PATTERN, tests, re.IGNORECASE)
    if number_of_localhost_match:
        return number_of_localhost_match.group(1)
    else:
        return ""

def extract_flow_bias(tests):
    flow_bias_match = re.search(FLOW_BIAS_PATTERN, tests, re.IGNORECASE)
    if flow_bias_match:
        return flow_bias_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_source_or_destination_port(tests):
    source_or_destination_port_match = re.search(SOURCE_OR_DESTINATION_PORT_PATTERN, tests, re.IGNORECASE)
    if source_or_destination_port_match:
        return source_or_destination_port_match.group(1).replace(", ", "\n")
    else:
        return ""

def process_data(file_path):
    data_dicts = []
    flow_type_map = {
        "Standard": "Single standard flow",
        "Superflow A": "Network scan",
        "Superflow B": "DDOS",
        "Superflow C": "Port scan",
    }

    with open(file_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Initialize Not Used Tests
            not_used_tests_lines = []

            # Extract data based on predefined patterns
            row["Log Source"] = extract_log_source(row["Tests"])
            row["Not Log Source"] = extract_not_log_source(row["Tests"])
            row["EventCategory"] = extract_event_category(row["Tests"])
            row["EventID_Details"] = extract_event_id_details(row["Tests"])
            row["EventID"] = extract_event_id(row["EventID_Details"])
            row["EventQID_Details"] = extract_event_qid_details(row["Tests"])
            row["EventQID"] = extract_event_qid(row["EventQID_Details"])
            row["IPProtocol"] = extract_ip_protocol(row["Tests"])
            row["Flow Type"] = extract_flow_type(row["Tests"], flow_type_map)
            row["ErrorCode"] = extract_error_code(row["Tests"])
            row["Application"] = extract_application(row["Tests"])
            row["EventSeverity"] = extract_event_severity(row["Tests"])
            row["EventCredibility"] = extract_event_credibility(row["Tests"])
            row["EventRelevance"] = extract_event_relevance(row["Tests"])
            row["ObjectName"] = extract_object_name(row["Tests"])
            row["EventType"] = extract_event_type(row["Tests"])
            row["EventContext"] = extract_event_context(row["Tests"])
            row["EventAdditionalCondition"] = extract_event_additional_condition(row["Tests"])
            row["SourceBytePacketRatio"] = extract_source_byte_packet_ratio(row["Tests"])
            row["DestinationBytePacketRatio"] = extract_destination_byte_packet_ratio(row["Tests"])
            row["DestinationBytes"] = extract_destination_bytes(row["Tests"])
            row["SourceBytes"] = extract_source_bytes(row["Tests"])
            row["SourceOrDestinationIP"] = extract_source_or_destination_ip(row["Tests"])
            row["SourceIP"] = extract_source_ip(row["Tests"])
            row["LocalNetwork"] = extract_local_network(row["Tests"])
            row["DestinationIP"] = extract_destination_ip(row["Tests"])
            row["SourceOrDestinationPort"] = extract_source_or_destination_port(row["Tests"])
            row["SourcePort"] = extract_source_port(row["Tests"])
            row["DestinationPort"] = extract_destination_port(row["Tests"])
            row["DestinationPackets"] = extract_destination_packets(row["Tests"])
            row["SourcePackets"] = extract_source_packets(row["Tests"])
            row["Source"] = extract_source(row["Tests"])
            row["Destination"] = extract_destination(row["Tests"])
            row["NumberOfLocalhost"] = extract_number_of_localhost(row["Tests"])
            row["IdentityMAC"] = extract_identity_mac(row["Tests"])
            row["Username"] = extract_username(row["Tests"])
            row["AttackContext"] = extract_attack_context(row["Tests"])
            row["FlowBias"] = extract_flow_bias(row["Tests"])
            row["Used by Building Blocks"] = ""
            row["Used by Use Cases"] = ""
            row["Not Used Tests"] = ""

            # Extract Not Used Test Lines
            tests_lines = row["Tests"].split("\n")
            extracted_lines = [
                LOG_SOURCE_PATTERN,
                NOT_LOG_SOURCE_PATTERN,
                EVENT_CATEGORY_PATTERN,
                EVENT_ID_DETAILS_PATTERN,
                EVENT_QID_DETAILS_PATTERN,
                IP_PROTOCOL_PATTERN,
                FLOW_TYPE_PATTERN,
                ERROR_CODE_PATTERN,
                APPLICATION_PATTERN,
                EVENT_SEVERITY_PATTERN,
                EVENT_CREDIBILITY_PATTERN,
                EVENT_RELEVANCE_PATTERN,
                OBJECT_NAME_PATTERN,
                EVENT_TYPE_PATTERN,
                EVENT_CONTEXT_PATTERN,
                EVENT_ADDITIONAL_CONDITION_PATTERN,
                SOURCE_BYTE_PACKET_RATIO_PATTERN,
                DESTINATION_BYTE_PACKET_RATIO_PATTERN,
                DESTINATION_BYTES_PATTERN,
                SOURCE_BYTES_PATTERN,
                SOURCE_OR_DESTINATION_IP_PATTERN,
                SOURCE_IP_PATTERN,
                LOCAL_NETWORK_PATTERN,
                DESTINATION_IP_PATTERN,
                SOURCE_OR_DESTINATION_PORT_PATTERN,
                DESTINATION_PORT_PATTERN,
                SOURCE_PORT_PATTERN,
                DESTINATION_PACKETS_PATTERN,
                SOURCE_PACKETS_PATTERN,
                SOURCE_PATTERN,
                DESTINATION_PATTERN,
                NUMBER_OF_LOCALHOST_PATTERN,
                IDENTITY_MAC_PATTERN,
                USERNAME_PATTERN,
                ATTACK_CONTEXT_PATTERN,
                FLOW_BIAS_PATTERN
            ]
            for line in tests_lines:
                if not any(re.search(pattern, line, re.IGNORECASE) for pattern in extracted_lines):
                    not_used_tests_lines.append(line.strip())
            row["Not Used Tests"] = "\n".join(not_used_tests_lines)

            # Add row to data_dicts
            data_dicts.append(row)

    extract_used_by_building_blocks(data_dicts)
    extract_used_by_use_cases(data_dicts)
    sorted_data_dicts = sorted(
        data_dicts, key=lambda x: (x["Building Block"] != "TRUE", x["Rule Name"])
    )
    return sorted_data_dicts


def write_to_csv(data_dicts, output_file):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data_dicts[0].keys())
        writer.writeheader()
        writer.writerows(data_dicts)

def print_json(data_dicts):
    print(json.dumps(data_dicts, indent=4))

if __name__ == "__main__":
    input_file = "usecases_protected.csv"
    output_file = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    processed_data = process_data(input_file)
    write_to_csv(processed_data, output_file)
    print_json(processed_data)


