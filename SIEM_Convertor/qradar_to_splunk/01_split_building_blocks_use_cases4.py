import csv
import re
import json
from datetime import datetime

# Define patterns
APPLICATION_PATTERN = r"and when the flow matches Application is any of (\[.*\])"
ATTACK_CONTEXT_PATTERN = r"and where the attack context is (.*)"
CONTEXT_PATTERN = r"and when the context is (.*)"
DESTINATION_PATTERN = r"and when the destination is (.*)"
DESTINATION_BYTE_PACKET_RATIO_PATTERN = r"and when the destination byte/packet ratio is (.*)"
DESTINATION_BYTES_PATTERN = r"and when the destination bytes is (.*)"
DESTINATION_IP_PATTERN = r"and (?:when|where) the (?:D|d)estination IP is (?:a part of any|one) of the following (.*)"
DESTINATION_PACKETS_PATTERN = r"and when the destination packets is (.*)"
DESTINATION_PORT_PATTERN = r"and when the destination port is one of the following (.*)"
ERROR_MATCHES_PATTERN = r"and when an event matches any of the following (.*)"
NOT_ERROR_MATCHES_PATTERN = r"and NOT when an event matches any of the following (.*)"
ERROR_CODE_PATTERN = r"and when any of Error Code \(custom\)(?:, Sub Status \(custom\))? are contained in any of (.*)"
EVENT_ADDITIONAL_CONDITION_PATTERN = r"and when at least 1 of these (.*)"
EVENT_CATEGORY_PATTERN = r"(?:and when|and where) the event category for the event is one of the following (.*)"
EVENT_CONTEXT_PATTERN = r"and when the (?:event|) context is (.*)"
EVENT_CREDIBILITY_PATTERN = r"and (?:where|when) the Event Credibility is (.*)"
EVENT_ID_DETAILS_PATTERN = r"and when any of EventID \(custom\) are contained in any of (.*)"
EVENT_QID_DETAILS_PATTERN = r"(?:and when|and) the event QID is one of the following (.*)"
NOT_EVENT_QID_DETAILS_PATTERN = r"(?:and NOT when|and NOT) the event QID is one of the following (.*)"
EVENT_IDENTITY_TRUE_PATTERN = r"and when the event matches Has Identity is (.*)"
EVENT_PAYLOAD_PATTERN = r"and when the Event Payload contains (.*)"
EVENT_RELEVANCE_PATTERN = r"and (?:where|when) the Event Relevance is (.*)"
EVENT_SEVERITY_PATTERN = r"and (?:where|when) the Event Severity is (.*)"
EVENT_TYPE_PATTERN = r"and when (?:the|an|we see an) event (?:matches|match) (?:any|all) of the following (.*)"
FLOW_OR_EVENT_PATTERN = r"and when a flow or an event matches any of the following (.*)"
FLOW_OR_EVENT_OCCUR_AFTER_PATTERN = r"and when the flow\(s\) or event\(s\) occur after (.*)"
FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN = r"and when the flow\(s\) or event\(s\) occur before (.*)"
FLOW_BIAS_PATTERN = r"and when the flow bias is (.*)"
FLOW_TYPE_PATTERN = r"and when (?:the flow type|the flow|a flow|a flow or an event) (?:matches any of the following|is one of|matches Application is) (.*)"
FLOW_DURATION_PATTERN = r"and when the flow duration is (.*)"
FLOW_CONTEXT_PATTERN = r"and when the flow context is (.*)"
NOT_FLOW_CONTEXT_PATTERN = r"and NOT when the flow context is (.*)"
IDENTITY_MAC_PATTERN = r"and when the identity MAC matches the following (.*)"
IP_PROTOCOL_PATTERN = r"and (?:when the|where) IP protocol is one of the following (.*)"
LOCAL_NETWORK_PATTERN = r"and when the local network is (.*)"
LOG_SOURCE_PATTERN = r"and when the event\(s\) were detected by one or more of (.*)"
NOT_LOG_SOURCE_PATTERN = r"and NOT when the event\(s\) were detected by one or more of (.*)"
NUMBER_OF_LOCALHOST_PATTERN = r"and when the number of local hosts is (.*)"
OBJECT_NAME_PATTERN = r"and when any of ObjectName \(custom\) are contained in any of (.*)"
SOURCE_BYTE_PACKET_RATIO_PATTERN = r"and when the source byte/packet ratio is (.*)"
SOURCE_BYTES_PATTERN = r"and when the source bytes is (.*)"
SOURCE_IP_PATTERN = r"and (?:when|where) the source IP is (?:a part of any|one) of the following (.*)"
SOURCE_OR_DESTINATION_IP_PATTERN = r"and (?:when|where) (?:either the source or destination IP is one of the following|any of Destination IP, Source IP are contained in any of|any of Source IP, Destination IP are contained in any of|the any IP is a part of any of the following) (.*)"
SOURCE_OR_DESTINATION_PORT_PATTERN = r"and when the source or destination port is any of (.*)"
SOURCE_PACKETS_PATTERN = r"and when the source packets is (.*)"
SOURCE_PATTERN = r"and when the source is (.*)"
SOURCE_PORT_PATTERN = r"and when the source port is one of the following (.*)"
USERNAME_PATTERN = r"and when any of Username are contained in any of (.*)"
EVENT_AT_LEAST_SEEN_PATTERN = r"and when at least (\d+) events are seen (.*)"
ICMP_TYPE_PATTERN = r"and when the ICMP type is any of (.*)"
NOT_ICMP_TYPE_PATTERN = r"and NOT when the ICMP type is any of (.*)"

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

def extract_not_event_qid_details(tests):
    not_event_qid_details_match = re.search(EVENT_QID_DETAILS_PATTERN, tests, re.IGNORECASE)
    if not_event_qid_details_match:
        return not_event_qid_details_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_not_event_qid(event_qid_details):
    not_event_qid_match = re.findall(r"\((\d+)\)", event_qid_details)
    if not_event_qid_match:
        return "\n".join(not_event_qid_match)
    else:
        return ""

def extract_event_matches(tests):
    event_matches_match = re.search(ERROR_MATCHES_PATTERN, tests, re.IGNORECASE)
    if event_matches_match:
        return event_matches_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_not_event_matches(tests):
    not_event_matches_match = re.search(NOT_ERROR_MATCHES_PATTERN, tests, re.IGNORECASE)
    if not_event_matches_match:
        return not_event_matches_match.group(1).replace(", ", "\n")
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

def extract_flow_duration(tests):
    flow_duration_match = re.search(FLOW_DURATION_PATTERN, tests, re.IGNORECASE)
    if flow_duration_match:
        return flow_duration_match.group(1)
    else:
        return ""

def extract_flow_context(tests):
    flow_context_match = re.search(FLOW_CONTEXT_PATTERN, tests, re.IGNORECASE)
    if flow_context_match:
        return flow_context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_not_flow_context(tests):
    not_flow_context_match = re.search(NOT_FLOW_CONTEXT_PATTERN, tests, re.IGNORECASE)
    if not_flow_context_match:
        return not_flow_context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_event_payload(tests):
    event_payload_match = re.search(EVENT_PAYLOAD_PATTERN, tests, re.IGNORECASE)
    if event_payload_match:
        return event_payload_match.group(1).replace(", ", "\n")
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

def extract_destination_ip(tests):
    destination_ip_match = re.search(DESTINATION_IP_PATTERN, tests, re.IGNORECASE)
    if destination_ip_match:
        return destination_ip_match.group(1).replace(", ", "\n")
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

def extract_events_at_least_seen(tests):
    event_at_least_seen_match = re.search(EVENT_AT_LEAST_SEEN_PATTERN, tests, re.IGNORECASE)
    if event_at_least_seen_match:
        return event_at_least_seen_match.group(0).replace(", ", "\n")
    else:
        return ""

def extract_icmp_type(tests):
    icmp_type_match = re.search(ICMP_TYPE_PATTERN, tests, re.IGNORECASE)
    if icmp_type_match:
        return icmp_type_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_not_icmp_type(tests):
    not_icmp_type_match = re.search(NOT_ICMP_TYPE_PATTERN, tests, re.IGNORECASE)
    if not_icmp_type_match:
        return not_icmp_type_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_context(tests):
    context_match = re.search(CONTEXT_PATTERN, tests, re.IGNORECASE)
    if context_match:
        return context_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_flow_or_event(tests):
    flow_or_event_match = re.search(FLOW_OR_EVENT_PATTERN, tests, re.IGNORECASE)
    if flow_or_event_match:
        return flow_or_event_match.group(1).replace(", ", "\n")
    else:
        return ""

def extract_flow_or_event_occur_after(tests):
    flow_or_event_occur_after_match = re.search(FLOW_OR_EVENT_OCCUR_AFTER_PATTERN, tests, re.IGNORECASE)
    if flow_or_event_occur_after_match:
        return flow_or_event_occur_after_match.group(1)
    else:
        return ""

def extract_flow_or_event_occur_before(tests):
    flow_or_event_occur_before_match = re.search(FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN, tests, re.IGNORECASE)
    if flow_or_event_occur_before_match:
        return flow_or_event_occur_before_match.group(1)
    else:
        return ""

def extract_event_identity_true(tests):
    event_identity_true_match = re.search(EVENT_IDENTITY_TRUE_PATTERN, tests, re.IGNORECASE)
    if event_identity_true_match:
        return event_identity_true_match.group(1).replace(", ", "\n")
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
            # Log Source
            row["LogSource"] = extract_log_source(row["Tests"])
            row["NotLogSource"] = extract_not_log_source(row["Tests"])

            # Event Category
            row["EventCategory"] = extract_event_category(row["Tests"])
            row["NotEventCategory"] = extract_not_event_category(row["Tests"])

            # Event ID
            row["EventIDDetails"] = extract_event_id_details(row["Tests"])
            row["EventID"] = extract_event_id(row["EventIDDetails"])
            row["NotEventID"] = extract_not_event_id(row["EventIDDetails"])

            # Event QID
            row["EventQIDDetails"] = extract_event_qid_details(row["Tests"])
            row["EventQID"] = extract_event_qid(row["EventQIDDetails"])
            row["NotEventQIDDetails"] = extract_not_event_qid_details(row["Tests"])
            row["NotEventQID"] = extract_not_event_qid(row["NotEventQIDDetails"])

            # IP Protocol
            row["IPProtocol"] = extract_ip_protocol(row["Tests"])
            row["NotIPProtocol"] = extract_not_ip_protocol(row["Tests"])

            # Event Matches
            row["EventMatches"] = extract_event_matches(row["Tests"])
            row["NotEventMatches"] = extract_not_event_matches(row["Tests"])

            # Flow Type
            row["FlowType"] = extract_flow_type(row["Tests"], flow_type_map)
            row["NotFlowType"] = extract_not_flow_type(row["Tests"], flow_type_map)

            # Flow Duration
            row["FlowDuration"] = extract_flow_duration(row["Tests"])
            row["NotFlowDuration"] = extract_not_flow_duration(row["Tests"])

            # Flow Context
            row["FlowContext"] = extract_flow_context(row["Tests"])
            row["NotFlowContext"] = extract_not_flow_context(row["Tests"])

            # Event Payload
            row["EventPayload"] = extract_event_payload(row["Tests"])

            # Error Code
            row["ErrorCode"] = extract_error_code(row["Tests"])
            row["NotErrorCode"] = extract_not_error_code(row["Tests"])

            # Application
            row["Application"] = extract_application(row["Tests"])
            row["NotApplication"] = extract_not_application(row["Tests"])

            # Event Severity
            row["EventSeverity"] = extract_event_severity(row["Tests"])
            row["NotEventSeverity"] = extract_not_event_severity(row["Tests"])

            # Event Credibility
            row["EventCredibility"] = extract_event_credibility(row["Tests"])
            row["NotEventCredibility"] = extract_not_event_credibility(row["Tests"])

            # Event Relevance
            row["EventRelevance"] = extract_event_relevance(row["Tests"])
            row["NotEventRelevance"] = extract_not_event_relevance(row["Tests"])

            # Object Name
            row["ObjectName"] = extract_object_name(row["Tests"])
            row["NotObjectName"] = extract_not_object_name(row["Tests"])

            # Event Type
            row["EventType"] = extract_event_type(row["Tests"])
            row["NotEventType"] = extract_not_event_type(row["Tests"])

            # Event Context
            row["EventContext"] = extract_event_context(row["Tests"])
            row["NotEventContext"] = extract_not_event_context(row["Tests"])

            # Event Additional Condition
            row["EventAdditionalCondition"] = extract_event_additional_condition(row["Tests"])
            row["NotEventAdditionalCondition"] = extract_not_event_additional_condition(row["Tests"])

            # Source Byte Packet Ratio
            row["SourceBytePacketRatio"] = extract_source_byte_packet_ratio(row["Tests"])
            row["NotSourceBytePacketRatio"] = extract_not_source_byte_packet_ratio(row["Tests"])

            # Destination Byte Packet Ratio
            row["DestinationBytePacketRatio"] = extract_destination_byte_packet_ratio(row["Tests"])
            row["NotDestinationBytePacketRatio"] = extract_not_destination_byte_packet_ratio(row["Tests"])

            # Destination Bytes
            row["DestinationBytes"] = extract_destination_bytes(row["Tests"])
            row["NotDestinationBytes"] = extract_not_destination_bytes(row["Tests"])

            # Source Bytes
            row["SourceBytes"] = extract_source_bytes(row["Tests"])
            row["NotSourceBytes"] = extract_not_source_bytes(row["Tests"])

            # Source or Destination IP
            row["SourceOrDestinationIP"] = extract_source_or_destination_ip(row["Tests"])
            row["NotSourceOrDestinationIP"] = extract_not_source_or_destination_ip(row["Tests"])

            # Source IP
            row["SourceIP"] = extract_source_ip(row["Tests"])
            row["NotSourceIP"] = extract_not_source_ip(row["Tests"])

            # Local Network
            row["LocalNetwork"] = extract_local_network(row["Tests"])
            row["NotLocalNetwork"] = extract_not_local_network(row["Tests"])

            # Destination IP
            row["DestinationIP"] = extract_destination_ip(row["Tests"])
            row["NotDestinationIP"] = extract_not_destination_ip(row["Tests"])

            # Source or Destination Port
            row["SourceOrDestinationPort"] = extract_source_or_destination_port(row["Tests"])
            row["NotSourceOrDestinationPort"] = extract_not_source_or_destination_port(row["Tests"])

            # Source Port
            row["SourcePort"] = extract_source_port(row["Tests"])
            row["NotSourcePort"] = extract_not_source_port(row["Tests"])

            # Destination Port
            row["DestinationPort"] = extract_destination_port(row["Tests"])
            row["NotDestinationPort"] = extract_not_destination_port(row["Tests"])

            # Destination Packets
            row["DestinationPackets"] = extract_destination_packets(row["Tests"])
            row["NotDestinationPackets"] = extract_not_destination_packets(row["Tests"])

            # Source Packets
            row["SourcePackets"] = extract_source_packets(row["Tests"])
            row["NotSourcePackets"] = extract_not_source_packets(row["Tests"])

            # Source
            row["Source"] = extract_source(row["Tests"])
            row["NotSource"] = extract_not_source(row["Tests"])

            # Destination
            row["Destination"] = extract_destination(row["Tests"])
            row["NotDestination"] = extract_not_destination(row["Tests"])

            # Number of Localhost
            row["NumberOfLocalhost"] = extract_number_of_localhost(row["Tests"])
            row["NotNumberOfLocalhost"] = extract_not_number_of_localhost(row["Tests"])

            # Identity MAC
            row["IdentityMAC"] = extract_identity_mac(row["Tests"])
            row["NotIdentityMAC"] = extract_not_identity_mac(row["Tests"])

            # Username
            row["Username"] = extract_username(row["Tests"])
            row["NotUsername"] = extract_not_username(row["Tests"])

            # Attack Context
            row["AttackContext"] = extract_attack_context(row["Tests"])
            row["NotAttackContext"] = extract_not_attack_context(row["Tests"])

            # Flow Bias
            row["FlowBias"] = extract_flow_bias(row["Tests"])
            row["NotFlowBias"] = extract_not_flow_bias(row["Tests"])

            # Event At Least Seen
            row["EventAtLeastSeen"] = extract_events_at_least_seen(row["Tests"])
            row["NotEventAtLeastSeen"] = extract_not_events_at_least_seen(row["Tests"])

            # ICMP Type
            row["ICMPType"] = extract_icmp_type(row["Tests"])
            row["NotICMPType"] = extract_not_icmp_type(row["Tests"])

            # Context
            row["Context"] = extract_context(row["Tests"])
            row["NotContext"] = extract_not_context(row["Tests"])

            # Flow or Event
            row["FlowOrEvent"] = extract_flow_or_event(row["Tests"])
            row["NotFlowOrEvent"] = extract_not_flow_or_event(row["Tests"])

            # Flow or Event Occur After/Before
            row["FlowOrEventOccurAfter"] = extract_flow_or_event_occur_after(row["Tests"])
            row["NotFlowOrEventOccurAfter"] = extract_not_flow_or_event_occur_after(row["Tests"])

            row["FlowOrEventOccurBefore"] = extract_flow_or_event_occur_before(row["Tests"])
            row["NotFlowOrEventOccurBefore"] = extract_not_flow_or_event_occur_before(row["Tests"])

            # Event Identity True
            row["EventIdentityTrue"] = extract_event_identity_true(row["Tests"])
            row["NotEventIdentityTrue"] = extract_not_event_identity_true(row["Tests"])

            row["Used by Building Blocks"] = ""
            row["Used by Use Cases"] = ""
            row["Not Used Tests"] = ""

            # Extract Not Used Test Lines
            tests_lines = row["Tests"].split("\n")
            extracted_lines = [
                APPLICATION_PATTERN,
                CONTEXT_PATTERN,
                ATTACK_CONTEXT_PATTERN,
                DESTINATION_PATTERN,
                DESTINATION_BYTE_PACKET_RATIO_PATTERN,
                DESTINATION_BYTES_PATTERN,
                DESTINATION_IP_PATTERN,
                DESTINATION_PACKETS_PATTERN,
                DESTINATION_PORT_PATTERN,
                ERROR_MATCHES_PATTERN,
                NOT_ERROR_MATCHES_PATTERN,
                ERROR_CODE_PATTERN,
                EVENT_ADDITIONAL_CONDITION_PATTERN,
                EVENT_CATEGORY_PATTERN,
                EVENT_CONTEXT_PATTERN,
                EVENT_CREDIBILITY_PATTERN,
                EVENT_ID_DETAILS_PATTERN,
                EVENT_QID_DETAILS_PATTERN,
                NOT_EVENT_QID_DETAILS_PATTERN,
                EVENT_IDENTITY_TRUE_PATTERN,
                EVENT_PAYLOAD_PATTERN,
                EVENT_RELEVANCE_PATTERN,
                EVENT_SEVERITY_PATTERN,
                EVENT_TYPE_PATTERN,
                FLOW_OR_EVENT_PATTERN,
                FLOW_OR_EVENT_OCCUR_AFTER_PATTERN,
                FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN,
                FLOW_BIAS_PATTERN,
                FLOW_TYPE_PATTERN,
                FLOW_DURATION_PATTERN,
                FLOW_CONTEXT_PATTERN,
                NOT_FLOW_CONTEXT_PATTERN,
                IDENTITY_MAC_PATTERN,
                IP_PROTOCOL_PATTERN,
                LOCAL_NETWORK_PATTERN,
                LOG_SOURCE_PATTERN,
                NOT_LOG_SOURCE_PATTERN,
                NUMBER_OF_LOCALHOST_PATTERN,
                OBJECT_NAME_PATTERN,
                SOURCE_BYTE_PACKET_RATIO_PATTERN,
                SOURCE_BYTES_PATTERN,
                SOURCE_IP_PATTERN,
                SOURCE_OR_DESTINATION_IP_PATTERN,
                SOURCE_OR_DESTINATION_PORT_PATTERN,
                SOURCE_PACKETS_PATTERN,
                SOURCE_PATTERN,
                SOURCE_PORT_PATTERN,
                USERNAME_PATTERN,
                EVENT_AT_LEAST_SEEN_PATTERN,
                ICMP_TYPE_PATTERN,
                NOT_ICMP_TYPE_PATTERN
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


