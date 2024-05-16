import csv
import re
import json
from datetime import datetime

# Define patterns
APPLICATION_PATTERN = r"and when the flow matches Application is any of (\[.*\])"
APPLICATION_NOT_PATTERN = r"and NOT when the flow matches Application is any of (\[.*\])"
ATTACK_CONTEXT_PATTERN = r"and where the attack context is (.*)"
ATTACK_CONTEXT_NOT_PATTERN = r"and NOT where the attack context is (.*)"
CONTEXT_PATTERN = r"and when the context is (.*)"
CONTEXT_NOT_PATTERN = r"and NOT when the context is (.*)"
DESTINATION_PATTERN = r"and when the destination is (.*)"
DESTINATION_NOT_PATTERN = r"and NOT when the destination is (.*)"
DESTINATION_BYTE_PACKET_RATIO_PATTERN = r"and when the destination byte/packet ratio is (.*)"
DESTINATION_BYTE_PACKET_RATIO_NOT_PATTERN = r"and NOT when the destination byte/packet ratio is (.*)"
DESTINATION_BYTES_PATTERN = r"and when the destination bytes is (.*)"
DESTINATION_BYTES_NOT_PATTERN = r"and NOT when the destination bytes is (.*)"
DESTINATION_IP_PATTERN = r"and (?:when|where) the (?:D|d)estination IP is (?:a part of any|one) of the following (.*)"
DESTINATION_IP_NOT_PATTERN = r"and NOT (?:when|where) the (?:D|d)estination IP is (?:a part of any|one) of the following (.*)"
DESTINATION_PACKETS_PATTERN = r"and when the destination packets is (.*)"
DESTINATION_PACKETS_NOT_PATTERN = r"and NOT when the destination packets is (.*)"
DESTINATION_PORT_PATTERN = r"and when the destination port is one of the following (.*)"
DESTINATION_PORT_NOT_PATTERN = r"and NOT when the destination port is one of the following (.*)"
ERROR_MATCHES_PATTERN = r"and when an event matches any of the following (.*)"
ERROR_MATCHES_NOT_PATTERN = r"and NOT when an event matches any of the following (.*)"
ERROR_CODE_PATTERN = r"and when any of Error Code \(custom\)(?:, Sub Status \(custom\))? are contained in any of (.*)"
ERROR_CODE_NOT_PATTERN = r"and NOT when any of Error Code \(custom\)(?:, Sub Status \(custom\))? are contained in any of (.*)"
EVENT_ADDITIONAL_CONDITION_PATTERN = r"and when at least 1 of these (.*)"
EVENT_ADDITIONAL_CONDITION_NOT_PATTERN = r"and NOT when at least 1 of these (.*)"
EVENT_CATEGORY_PATTERN = r"(?:and when|and where) the event category for the event is one of the following (.*)"
EVENT_CATEGORY_NOT_PATTERN = r"(?:and NOT when|and NOT where) the event category for the event is one of the following (.*)"
EVENT_CONTEXT_PATTERN = r"and when the (?:event|) context is (.*)"
EVENT_CONTEXT_NOT_PATTERN = r"and NOT when the (?:event|) context is (.*)"
EVENT_CREDIBILITY_PATTERN = r"and (?:where|when) the Event Credibility is (.*)"
EVENT_CREDIBILITY_NOT_PATTERN = r"and NOT (?:where|when) the Event Credibility is (.*)"
EVENT_ID_DETAILS_PATTERN = r"and when any of EventID \(custom\) are contained in any of (.*)"
EVENT_ID_DETAILS_NOT_PATTERN = r"and NOT when any of EventID \(custom\) are contained in any of (.*)"
EVENT_QID_DETAILS_PATTERN = r"(?:and when|and) the event QID is one of the following (.*)"
EVENT_QID_DETAILS_NOT_PATTERN = r"(?:and NOT when|and NOT) the event QID is one of the following (.*)"
EVENT_MATCHES_PATTERN = r"and when an event matches any of the following (.*)"
EVENT_MATCHES_NOT_PATTERN = r"and NOT when an event matches any of the following (.*)"
EVENT_IDENTITY_TRUE_PATTERN = r"and when the event matches Has Identity is (.*)"
EVENT_IDENTITY_TRUE_NOT_PATTERN = r"and NOT when the event matches Has Identity is (.*)"
EVENT_PAYLOAD_PATTERN = r"and when the Event Payload contains (.*)"
EVENT_PAYLOAD_NOT_PATTERN = r"and NOT when the Event Payload contains (.*)"
EVENT_RELEVANCE_PATTERN = r"and (?:where|when) the Event Relevance is (.*)"
EVENT_RELEVANCE_NOT_PATTERN = r"and NOT (?:where|when) the Event Relevance is (.*)"
EVENT_SEVERITY_PATTERN = r"and (?:where|when) the Event Severity is (.*)"
EVENT_SEVERITY_NOT_PATTERN = r"and NOT (?:where|when) the Event Severity is (.*)"
EVENT_TYPE_PATTERN = r"and when (?:the|an|we see an) event (?:matches|match) (?:any|all) of the following (.*)"
EVENT_TYPE_NOT_PATTERN = r"and NOT when (?:the|an|we see an) event (?:matches|match) (?:any|all) of the following (.*)"
FLOW_OR_EVENT_PATTERN = r"and when a flow or an event matches any of the following (.*)"
FLOW_OR_EVENT_NOT_PATTERN = r"and NOT when a flow or an event matches any of the following (.*)"
FLOW_OR_EVENT_OCCUR_AFTER_PATTERN = r"and when the flow\(s\) or event\(s\) occur after (.*)"
FLOW_OR_EVENT_OCCUR_AFTER_NOT_PATTERN = r"and NOT when the flow\(s\) or event\(s\) occur after (.*)"
FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN = r"and when the flow\(s\) or event\(s\) occur before (.*)"
FLOW_OR_EVENT_OCCUR_BEFORE_NOT_PATTERN = r"and NOT when the flow\(s\) or event\(s\) occur before (.*)"
FLOW_BIAS_PATTERN = r"and when the flow bias is (.*)"
FLOW_BIAS_NOT_PATTERN = r"and NOT when the flow bias is (.*)"
FLOW_TYPE_PATTERN = r"and when (?:the flow type|the flow|a flow|a flow or an event) (?:matches any of the following|is one of|matches Application is) (.*)"
FLOW_TYPE_NOT_PATTERN = r"and NOT when (?:the flow type|the flow|a flow|a flow or an event) (?:matches any of the following|is one of|matches Application is) (.*)"
FLOW_DURATION_PATTERN = r"and when the flow duration is (.*)"
FLOW_DURATION_NOT_PATTERN = r"and NOT when the flow duration is (.*)"
FLOW_CONTEXT_PATTERN = r"and when the flow context is (.*)"
FLOW_CONTEXT_NOT_PATTERN = r"and NOT when the flow context is (.*)"
IDENTITY_MAC_PATTERN = r"and when the identity MAC matches the following (.*)"
IDENTITY_MAC_NOT_PATTERN = r"and NOT when the identity MAC matches the following (.*)"
IP_PROTOCOL_PATTERN = r"and (?:when the|where) IP protocol is one of the following (.*)"
IP_PROTOCOL_NOT_PATTERN = r"and NOT (?:when the|where) IP protocol is one of the following (.*)"
LOCAL_NETWORK_PATTERN = r"and when the local network is (.*)"
LOCAL_NETWORK_NOT_PATTERN = r"and NOT when the local network is (.*)"
LOG_SOURCE_PATTERN = r"and when the event\(s\) were detected by one or more of (.*)"
LOG_SOURCE_NOT_PATTERN = r"and NOT when the event\(s\) were detected by one or more of (.*)"
NUMBER_OF_LOCALHOST_PATTERN = r"and when the number of local hosts is (.*)"
NUMBER_OF_LOCALHOST_NOT_PATTERN = r"and NOT when the number of local hosts is (.*)"
OBJECT_NAME_PATTERN = r"and when any of ObjectName \(custom\) are contained in any of (.*)"
OBJECT_NAME_NOT_PATTERN = r"and NOT when any of ObjectName \(custom\) are contained in any of (.*)"
SOURCE_BYTE_PACKET_RATIO_PATTERN = r"and when the source byte/packet ratio is (.*)"
SOURCE_BYTE_PACKET_RATIO_NOT_PATTERN = r"and NOT when the source byte/packet ratio is (.*)"
SOURCE_DESTINATION_PACKET_RATIO_PATTERN = r"and when the source/destination packet ratio is (.*)"
SOURCE_DESTINATION_PACKET_RATIO_NOT_PATTERN = r"and NOT when the source/destination packet ratio is (.*)"
SOURCE_BYTES_PATTERN = r"and when the source bytes is (.*)"
SOURCE_BYTES_NOT_PATTERN = r"and NOT when the source bytes is (.*)"
SOURCE_IP_PATTERN = r"and (?:when|where) the source IP is (?:a part of any|one) of the following (.*)"
SOURCE_IP_NOT_PATTERN = r"and NOT (?:when|where) the source IP is (?:a part of any|one) of the following (.*)"
SOURCE_OR_DESTINATION_IP_PATTERN = r"and (?:when|where) (?:either the source or destination IP is one of the following|any of Destination IP, Source IP are contained in any of|any of Source IP, Destination IP are contained in any of|the any IP is a part of any of the following) (.*)"
SOURCE_OR_DESTINATION_IP_NOT_PATTERN = r"and NOT (?:when|where) (?:either the source or destination IP is one of the following|any of Destination IP, Source IP are contained in any of|any of Source IP, Destination IP are contained in any of|the any IP is a part of any of the following) (.*)"
SOURCE_OR_DESTINATION_PORT_PATTERN = r"and when the source or destination port is any of (.*)"
SOURCE_OR_DESTINATION_PORT_NOT_PATTERN = r"and NOT when the source or destination port is any of (.*)"
SOURCE_PACKETS_PATTERN = r"and when the source packets is (.*)"
SOURCE_PACKETS_NOT_PATTERN = r"and NOT when the source packets is (.*)"
SOURCE_PATTERN = r"and when the source is (.*)"
SOURCE_NOT_PATTERN = r"and NOT when the source is (.*)"
SOURCE_PORT_PATTERN = r"and when the source port is one of the following (.*)"
SOURCE_PORT_NOT_PATTERN = r"and NOT when the source port is one of the following (.*)"
SOURCE_TCP_FLAG_PATTERN = r"and when the source TCP flags are any of (.*)"
SOURCE_TCP_FLAG_NOT_PATTERN = r"and NOT when the source TCP flags are any of (.*)"
USERNAME_PATTERN = r"and when any of Username are contained in any of (.*)"
USERNAME_NOT_PATTERN = r"and NOT when any of Username are contained in any of (.*)"
EVENT_AT_LEAST_SEEN_PATTERN = r"and when at least \d+ events are seen (.*)"
EVENT_AT_LEAST_SEEN_NOT_PATTERN = r"and NOT when at least \d+ events are seen (.*)"
ICMP_TYPE_PATTERN = r"and when the ICMP type is any of (.*)"
ICMP_TYPE_NOT_PATTERN = r"and NOT when the ICMP type is any of (.*)"


def extract(pattern, text):
    match = re.search(pattern, text)
    if match:
        return match.group(1).replace(", ", "\n")
    else:
        return ""

# Define extract functions
def extract_log_source(text):
    return extract(LOG_SOURCE_PATTERN, text)

def extract_not_log_source(text):
    return extract(LOG_SOURCE_NOT_PATTERN, text)

def extract_event_category(text):
    return extract(EVENT_CATEGORY_PATTERN, text)

def extract_not_event_category(text):
    return extract(EVENT_CATEGORY_NOT_PATTERN, text)

def extract_event_id_details(text):
    return extract(EVENT_ID_DETAILS_PATTERN, text)

def extract_event_id(event_id_details):
    match = re.search(r'EventID (\d+)', event_id_details)
    if match:
        return match.group(1)
    else:
        return None

def extract_event_qid_details(text):
    return extract(EVENT_QID_DETAILS_PATTERN, text)

def extract_not_event_qid_details(text):
    return extract(EVENT_QID_DETAILS_NOT_PATTERN, text)

def extract_ip_protocol(text):
    return extract(IP_PROTOCOL_PATTERN, text)

def extract_not_ip_protocol(text):
    return extract(IP_PROTOCOL_NOT_PATTERN, text)

def extract_event_matches(text):
    return extract(EVENT_MATCHES_PATTERN, text)

def extract_not_event_matches(text):
    return extract(EVENT_MATCHES_NOT_PATTERN, text)

def extract_flow_type(text):
    return extract(FLOW_TYPE_PATTERN, text)

def extract_not_flow_type(text):
    return extract(FLOW_TYPE_NOT_PATTERN, text)

def extract_flow_duration(text):
    return extract(FLOW_DURATION_PATTERN, text)

def extract_not_flow_duration(text):
    return extract(FLOW_DURATION_NOT_PATTERN, text)

def extract_flow_context(text):
    return extract(FLOW_CONTEXT_PATTERN, text)

def extract_not_flow_context(text):
    return extract(FLOW_CONTEXT_NOT_PATTERN, text)

def extract_event_payload(text):
    return extract(EVENT_PAYLOAD_PATTERN, text)

def extract_error_code(text):
    return extract(ERROR_CODE_PATTERN, text)

def extract_not_error_code(text):
    return extract(ERROR_CODE_NOT_PATTERN, text)

def extract_application(text):
    return extract(APPLICATION_PATTERN, text)

def extract_not_application(text):
    return extract(APPLICATION_NOT_PATTERN, text)

def extract_event_severity(text):
    return extract(EVENT_SEVERITY_PATTERN, text)

def extract_not_event_severity(text):
    return extract(EVENT_SEVERITY_NOT_PATTERN, text)

def extract_event_credibility(text):
    return extract(EVENT_CREDIBILITY_PATTERN, text)

def extract_not_event_credibility(text):
    return extract(EVENT_CREDIBILITY_NOT_PATTERN, text)

def extract_event_relevance(text):
    return extract(EVENT_RELEVANCE_PATTERN, text)

def extract_not_event_relevance(text):
    return extract(EVENT_RELEVANCE_NOT_PATTERN, text)

def extract_object_name(text):
    return extract(OBJECT_NAME_PATTERN, text)

def extract_not_object_name(text):
    return extract(OBJECT_NAME_NOT_PATTERN, text)

def extract_event_type(text):
    return extract(EVENT_TYPE_PATTERN, text)

def extract_not_event_type(text):
    return extract(EVENT_TYPE_NOT_PATTERN, text)

def extract_event_context(text):
    return extract(EVENT_CONTEXT_PATTERN, text)

def extract_not_event_context(text):
    return extract(EVENT_CONTEXT_NOT_PATTERN, text)

def extract_event_additional_condition(text):
    return extract(EVENT_ADDITIONAL_CONDITION_PATTERN, text)

def extract_not_event_additional_condition(text):
    return extract(EVENT_ADDITIONAL_CONDITION_NOT_PATTERN, text)

def extract_source_byte_packet_ratio(text):
    return extract(SOURCE_BYTE_PACKET_RATIO_PATTERN, text)

def extract_not_source_byte_packet_ratio(text):
    return extract(SOURCE_BYTE_PACKET_RATIO_NOT_PATTERN, text)

def extract_destination_byte_packet_ratio(text):
    return extract(DESTINATION_BYTE_PACKET_RATIO_PATTERN, text)

def extract_not_destination_byte_packet_ratio(text):
    return extract(DESTINATION_BYTE_PACKET_RATIO_NOT_PATTERN, text)

def extract_destination_bytes(text):
    return extract(DESTINATION_BYTES_PATTERN, text)

def extract_not_destination_bytes(text):
    return extract(DESTINATION_BYTES_NOT_PATTERN, text)

def extract_source_bytes(text):
    return extract(SOURCE_BYTES_PATTERN, text)

def extract_not_source_bytes(text):
    return extract(SOURCE_BYTES_NOT_PATTERN, text)

def extract_source_or_destination_ip(text):
    return extract(SOURCE_OR_DESTINATION_IP_PATTERN, text)

def extract_not_source_or_destination_ip(text):
    return extract(SOURCE_OR_DESTINATION_IP_NOT_PATTERN, text)

def extract_source_ip(text):
    return extract(SOURCE_IP_PATTERN, text)

def extract_not_source_ip(text):
    return extract(SOURCE_IP_NOT_PATTERN, text)

def extract_local_network(text):
    return extract(LOCAL_NETWORK_PATTERN, text)

def extract_not_local_network(text):
    return extract(LOCAL_NETWORK_NOT_PATTERN, text)

def extract_destination_ip(text):
    return extract(DESTINATION_IP_PATTERN, text)

def extract_not_destination_ip(text):
    return extract(DESTINATION_IP_NOT_PATTERN, text)

def extract_source_or_destination_port(text):
    return extract(SOURCE_OR_DESTINATION_PORT_PATTERN, text)

def extract_not_source_or_destination_port(text):
    return extract(SOURCE_OR_DESTINATION_PORT_NOT_PATTERN, text)

def extract_source_port(text):
    return extract(SOURCE_PORT_PATTERN, text)

def extract_not_source_port(text):
    return extract(SOURCE_PORT_NOT_PATTERN, text)

def extract_source_tcp_flag(text):
    return extract(SOURCE_TCP_FLAG_PATTERN, text)

def extract_not_source_tcp_flag(text):
    return extract(SOURCE_TCP_FLAG_NOT_PATTERN, text)

def extract_destination_port(text):
    return extract(DESTINATION_PORT_PATTERN, text)

def extract_not_destination_port(text):
    return extract(DESTINATION_PORT_NOT_PATTERN, text)

def extract_destination_packets(text):
    return extract(DESTINATION_PACKETS_PATTERN, text)

def extract_not_destination_packets(text):
    return extract(DESTINATION_PACKETS_NOT_PATTERN, text)

def extract_source_packets(text):
    return extract(SOURCE_PACKETS_PATTERN, text)

def extract_not_source_packets(text):
    return extract(SOURCE_PACKETS_NOT_PATTERN, text)

def extract_source_destination_packet_ratio(text):
    return extract(SOURCE_DESTINATION_PACKET_RATIO_PATTERN, text)

def extract_not_source_destination_packet_ratio(text):
    return extract(SOURCE_DESTINATION_PACKET_RATIO_NOT_PATTERN, text)

def extract_source(text):
    return extract(SOURCE_PATTERN, text)

def extract_not_source(text):
    return extract(SOURCE_NOT_PATTERN, text)

def extract_destination(text):
    return extract(DESTINATION_PATTERN, text)

def extract_not_destination(text):
    return extract(DESTINATION_NOT_PATTERN, text)

def extract_number_of_localhost(text):
    return extract(NUMBER_OF_LOCALHOST_PATTERN, text)

def extract_not_number_of_localhost(text):
    return extract(NUMBER_OF_LOCALHOST_NOT_PATTERN, text)

def extract_identity_mac(text):
    return extract(IDENTITY_MAC_PATTERN, text)

def extract_not_identity_mac(text):
    return extract(IDENTITY_MAC_NOT_PATTERN, text)

def extract_username(text):
    return extract(USERNAME_PATTERN, text)

def extract_not_username(text):
    return extract(USERNAME_NOT_PATTERN, text)

def extract_attack_context(text):
    return extract(ATTACK_CONTEXT_PATTERN, text)

def extract_not_attack_context(text):
    return extract(ATTACK_CONTEXT_NOT_PATTERN, text)

def extract_flow_bias(text):
    return extract(FLOW_BIAS_PATTERN, text)

def extract_not_flow_bias(text):
    return extract(FLOW_BIAS_NOT_PATTERN, text)

def extract_events_at_least_seen(text):
    return extract(EVENT_AT_LEAST_SEEN_PATTERN, text)

def extract_not_events_at_least_seen(text):
    return extract(EVENT_AT_LEAST_SEEN_NOT_PATTERN, text)

def extract_icmp_type(text):
    return extract(ICMP_TYPE_PATTERN, text)

def extract_not_icmp_type(text):
    return extract(ICMP_TYPE_NOT_PATTERN, text)

def extract_context(text):
    return extract(CONTEXT_PATTERN, text)

def extract_not_context(text):
    return extract(CONTEXT_NOT_PATTERN, text)

def extract_flow_or_event(text):
    return extract(FLOW_OR_EVENT_PATTERN, text)

def extract_not_flow_or_event(text):
    return extract(FLOW_OR_EVENT_NOT_PATTERN, text)

def extract_flow_or_event_occur_after(text):
    return extract(FLOW_OR_EVENT_OCCUR_AFTER_PATTERN, text)

def extract_not_flow_or_event_occur_after(text):
    return extract(FLOW_OR_EVENT_OCCUR_AFTER_NOT_PATTERN, text)

def extract_flow_or_event_occur_before(text):
    return extract(FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN, text)

def extract_not_flow_or_event_occur_before(text):
    return extract(FLOW_OR_EVENT_OCCUR_BEFORE_NOT_PATTERN, text)

def extract_event_identity_true(text):
    return extract(EVENT_IDENTITY_TRUE_PATTERN, text)

def extract_not_event_identity_true(text):
    return extract(EVENT_IDENTITY_TRUE_NOT_PATTERN, text)

def extract_used_by_building_blocks(text, data_dicts):
    used_by_building_blocks = []
    for other_dict in data_dicts:
        if (
            text["Rule Name"] in other_dict["Tests"]
            and other_dict["Building Block"] == "TRUE"
        ):
            used_by_building_blocks.append(other_dict["Rule Name"])
    return "\n".join(used_by_building_blocks)


def extract_used_by_use_cases(text, data_dicts):
    used_by_use_cases = []
    for other_dict in data_dicts:
        if (
            text["Rule Name"] in other_dict["Tests"]
            and other_dict["Building Block"] == "FALSE"
        ):
            used_by_use_cases.append(other_dict["Rule Name"])
    return "\n".join(used_by_use_cases)

# Define a list of tuples with column names and corresponding extract functions
extract_functions = [
    ("LogSource", extract_log_source),
    ("NotLogSource", extract_not_log_source),
    ("EventCategory", extract_event_category),
    ("NotEventCategory", extract_not_event_category),
    ("EventIDDetails", extract_event_id_details),
    ("EventQIDDetails", extract_event_qid_details),
    ("NotEventQIDDetails", extract_not_event_qid_details),
    ("IPProtocol", extract_ip_protocol),
    ("NotIPProtocol", extract_not_ip_protocol),
    ("EventMatches", extract_event_matches),
    ("NotEventMatches", extract_not_event_matches),
    ("FlowType", extract_flow_type),
    ("NotFlowType", extract_not_flow_type),
    ("FlowDuration", extract_flow_duration),
    ("NotFlowDuration", extract_not_flow_duration),
    ("FlowContext", extract_flow_context),
    ("NotFlowContext", extract_not_flow_context),
    ("EventPayload", extract_event_payload),
    ("ErrorCode", extract_error_code),
    ("NotErrorCode", extract_not_error_code),
    ("Application", extract_application),
    ("NotApplication", extract_not_application),
    ("EventSeverity", extract_event_severity),
    ("NotEventSeverity", extract_not_event_severity),
    ("EventCredibility", extract_event_credibility),
    ("NotEventCredibility", extract_not_event_credibility),
    ("EventRelevance", extract_event_relevance),
    ("NotEventRelevance", extract_not_event_relevance),
    ("ObjectName", extract_object_name),
    ("NotObjectName", extract_not_object_name),
    ("EventType", extract_event_type),
    ("NotEventType", extract_not_event_type),
    ("EventContext", extract_event_context),
    ("NotEventContext", extract_not_event_context),
    ("EventAdditionalCondition", extract_event_additional_condition),
    ("NotEventAdditionalCondition", extract_not_event_additional_condition),
    ("SourceBytePacketRatio", extract_source_byte_packet_ratio),
    ("NotSourceBytePacketRatio", extract_not_source_byte_packet_ratio),
    ("DestinationBytePacketRatio", extract_destination_byte_packet_ratio),
    ("NotDestinationBytePacketRatio", extract_not_destination_byte_packet_ratio),
    ("DestinationBytes", extract_destination_bytes),
    ("NotDestinationBytes", extract_not_destination_bytes),
    ("SourceBytes", extract_source_bytes),
    ("NotSourceBytes", extract_not_source_bytes),
    ("SourceOrDestinationIP", extract_source_or_destination_ip),
    ("NotSourceOrDestinationIP", extract_not_source_or_destination_ip),
    ("SourceIP", extract_source_ip),
    ("NotSourceIP", extract_not_source_ip),
    ("LocalNetwork", extract_local_network),
    ("NotLocalNetwork", extract_not_local_network),
    ("DestinationIP", extract_destination_ip),
    ("NotDestinationIP", extract_not_destination_ip),
    ("SourceOrDestinationPort", extract_source_or_destination_port),
    ("NotSourceOrDestinationPort", extract_not_source_or_destination_port),
    ("SourcePort", extract_source_port),
    ("NotSourcePort", extract_not_source_port),
    ("DestinationPort", extract_destination_port),
    ("NotDestinationPort", extract_not_destination_port),
    ("DestinationPackets", extract_destination_packets),
    ("NotDestinationPackets", extract_not_destination_packets),
    ("SourcePackets", extract_source_packets),
    ("NotSourcePackets", extract_not_source_packets),
    ("Source", extract_source),
    ("NotSource", extract_not_source),
    ("SourceTCPFlag", extract_source_tcp_flag),
    ("NotSourceTCPFlag", extract_not_source_tcp_flag),
    ("Destination", extract_destination),
    ("NotDestination", extract_not_destination),
    ("NumberOfLocalhost", extract_number_of_localhost),
    ("NotNumberOfLocalhost", extract_not_number_of_localhost),
    ("IdentityMAC", extract_identity_mac),
    ("NotIdentityMAC", extract_not_identity_mac),
    ("Username", extract_username),
    ("NotUsername", extract_not_username),
    ("AttackContext", extract_attack_context),
    ("NotAttackContext", extract_not_attack_context),
    ("FlowBias", extract_flow_bias),
    ("NotFlowBias", extract_not_flow_bias),
    ("EventAtLeastSeen", extract_events_at_least_seen),
    ("NotEventAtLeastSeen", extract_not_events_at_least_seen),
    ("ICMPType", extract_icmp_type),
    ("NotICMPType", extract_not_icmp_type),
    ("Context", extract_context),
    ("NotContext", extract_not_context),
    ("FlowOrEvent", extract_flow_or_event),
    ("NotFlowOrEvent", extract_not_flow_or_event),
    ("FlowOrEventOccurAfter", extract_flow_or_event_occur_after),
    ("NotFlowOrEventOccurAfter", extract_not_flow_or_event_occur_after),
    ("FlowOrEventOccurBefore", extract_flow_or_event_occur_before),
    ("NotFlowOrEventOccurBefore", extract_not_flow_or_event_occur_before),
    ("EventIdentityTrue", extract_event_identity_true),
    ("NotEventIdentityTrue", extract_not_event_identity_true),
    ("SourceDestinationPacketRatio", extract_source_destination_packet_ratio),
    ("NotSourceDestinationPacketRatio", extract_not_source_destination_packet_ratio),
]

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
            for column, extract_function in extract_functions:
                row[column] = extract_function(row["Tests"])

            row["Check Usage"] = ""
            row["Used by Building Blocks"] = extract_used_by_building_blocks(row, data_dicts)
            row["Used by Use Cases"] = extract_used_by_use_cases(row, data_dicts)
            row["Check Usage"] = ""
            row["Rule Name Contains UBA"] = ""
            row["Used BB or Use Cases Contains UBA"] = ""
            row["Not Used Tests"] = ""

            # Extract Not Used Test Lines
            tests_lines = row["Tests"].split("\n")
            extracted_lines = [
                APPLICATION_PATTERN,
                APPLICATION_NOT_PATTERN,
                ATTACK_CONTEXT_PATTERN,
                ATTACK_CONTEXT_NOT_PATTERN,
                CONTEXT_PATTERN,
                CONTEXT_NOT_PATTERN,
                DESTINATION_PATTERN,
                DESTINATION_NOT_PATTERN,
                DESTINATION_BYTE_PACKET_RATIO_PATTERN,
                DESTINATION_BYTE_PACKET_RATIO_NOT_PATTERN,
                DESTINATION_BYTES_PATTERN,
                DESTINATION_BYTES_NOT_PATTERN,
                DESTINATION_IP_PATTERN,
                DESTINATION_IP_NOT_PATTERN,
                DESTINATION_PACKETS_PATTERN,
                DESTINATION_PACKETS_NOT_PATTERN,
                DESTINATION_PORT_PATTERN,
                DESTINATION_PORT_NOT_PATTERN,
                ERROR_MATCHES_PATTERN,
                ERROR_MATCHES_NOT_PATTERN,
                ERROR_CODE_PATTERN,
                ERROR_CODE_NOT_PATTERN,
                EVENT_ADDITIONAL_CONDITION_PATTERN,
                EVENT_ADDITIONAL_CONDITION_NOT_PATTERN,
                EVENT_CATEGORY_PATTERN,
                EVENT_CATEGORY_NOT_PATTERN,
                EVENT_CONTEXT_PATTERN,
                EVENT_CONTEXT_NOT_PATTERN,
                EVENT_CREDIBILITY_PATTERN,
                EVENT_CREDIBILITY_NOT_PATTERN,
                EVENT_ID_DETAILS_PATTERN,
                EVENT_ID_DETAILS_NOT_PATTERN,
                EVENT_QID_DETAILS_PATTERN,
                EVENT_QID_DETAILS_NOT_PATTERN,
                EVENT_IDENTITY_TRUE_PATTERN,
                EVENT_IDENTITY_TRUE_NOT_PATTERN,
                EVENT_PAYLOAD_PATTERN,
                EVENT_PAYLOAD_NOT_PATTERN,
                EVENT_RELEVANCE_PATTERN,
                EVENT_RELEVANCE_NOT_PATTERN,
                EVENT_SEVERITY_PATTERN,
                EVENT_SEVERITY_NOT_PATTERN,
                EVENT_TYPE_PATTERN,
                EVENT_TYPE_NOT_PATTERN,
                FLOW_OR_EVENT_PATTERN,
                FLOW_OR_EVENT_NOT_PATTERN,
                FLOW_OR_EVENT_OCCUR_AFTER_PATTERN,
                FLOW_OR_EVENT_OCCUR_AFTER_NOT_PATTERN,
                FLOW_OR_EVENT_OCCUR_BEFORE_PATTERN,
                FLOW_OR_EVENT_OCCUR_BEFORE_NOT_PATTERN,
                FLOW_BIAS_PATTERN,
                FLOW_BIAS_NOT_PATTERN,
                FLOW_TYPE_PATTERN,
                FLOW_TYPE_NOT_PATTERN,
                FLOW_DURATION_PATTERN,
                FLOW_DURATION_NOT_PATTERN,
                FLOW_CONTEXT_PATTERN,
                FLOW_CONTEXT_NOT_PATTERN,
                IDENTITY_MAC_PATTERN,
                IDENTITY_MAC_NOT_PATTERN,
                IP_PROTOCOL_PATTERN,
                IP_PROTOCOL_NOT_PATTERN,
                LOCAL_NETWORK_PATTERN,
                LOCAL_NETWORK_NOT_PATTERN,
                LOG_SOURCE_PATTERN,
                LOG_SOURCE_NOT_PATTERN,
                NUMBER_OF_LOCALHOST_PATTERN,
                NUMBER_OF_LOCALHOST_NOT_PATTERN,
                OBJECT_NAME_PATTERN,
                OBJECT_NAME_NOT_PATTERN,
                SOURCE_BYTE_PACKET_RATIO_PATTERN,
                SOURCE_BYTE_PACKET_RATIO_NOT_PATTERN,
                SOURCE_DESTINATION_PACKET_RATIO_PATTERN,
                SOURCE_DESTINATION_PACKET_RATIO_NOT_PATTERN,
                SOURCE_BYTES_PATTERN,
                SOURCE_BYTES_NOT_PATTERN,
                SOURCE_IP_PATTERN,
                SOURCE_IP_NOT_PATTERN,
                SOURCE_OR_DESTINATION_IP_PATTERN,
                SOURCE_OR_DESTINATION_IP_NOT_PATTERN,
                SOURCE_OR_DESTINATION_PORT_PATTERN,
                SOURCE_OR_DESTINATION_PORT_NOT_PATTERN,
                SOURCE_PACKETS_PATTERN,
                SOURCE_PACKETS_NOT_PATTERN,
                SOURCE_PATTERN,
                SOURCE_NOT_PATTERN,
                SOURCE_PORT_PATTERN,
                SOURCE_PORT_NOT_PATTERN,
                SOURCE_TCP_FLAG_PATTERN,
                SOURCE_TCP_FLAG_NOT_PATTERN,
                USERNAME_PATTERN,
                USERNAME_NOT_PATTERN,
                EVENT_AT_LEAST_SEEN_PATTERN,
                EVENT_AT_LEAST_SEEN_NOT_PATTERN,
                ICMP_TYPE_PATTERN,
                ICMP_TYPE_NOT_PATTERN
            ]
            for line in tests_lines:
                if not any(re.search(pattern, line, re.IGNORECASE) for pattern in extracted_lines):
                    not_used_tests_lines.append(line.strip())

            event_id_details = row["EventIDDetails"]
            event_id = extract_event_id(event_id_details)
            row["EventID"] = event_id if event_id else ""

            # Check Usage
            if not row["Used by Building Blocks"] and not row["Used by Use Cases"]:
                row["Check Usage"] = ""
            elif row["Enabled"] == "True":
                row["Check Usage"] = "In Use"
            else:
                row["Check Usage"] = "In Use"

            # Check if Rule Name Contains UBA
            rule_name = row["Rule Name"]
            if rule_name.startswith("UBA :"):
                row["Rule Name Contains UBA"] = "Starts with UBA :"
            elif "UBA :" in rule_name:
                row["Rule Name Contains UBA"] = "Contains UBA :"
            else:
                row["Rule Name Contains UBA"] = ""

            # Check if Used BB or Use Cases Contains UBA
            used_by_building_blocks = row["Used by Building Blocks"]
            used_by_use_cases = row["Used by Use Cases"]
            if used_by_building_blocks.startswith("UBA :") or used_by_use_cases.startswith("UBA :"):
                row["Used BB or Use Cases Contains UBA"] = "Starts with UBA :"
            elif "UBA :" in used_by_building_blocks or "UBA :" in used_by_use_cases:
                row["Used BB or Use Cases Contains UBA"] = "Contains UBA :"
            else:
                row["Used BB or Use Cases Contains UBA"] = ""

            # Not extracted conditions
            row["Not Used Tests"] = "\n".join(not_used_tests_lines)

            # Add row to data_dicts
            data_dicts.append(row)

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


