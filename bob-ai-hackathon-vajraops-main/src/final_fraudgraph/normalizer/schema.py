from copy import deepcopy


SCHEMA_VERSION = "1.1"


MASTER_TEMPLATE = {
    "case": {
        "case_id": "",
        "case_title": "",
        "created_at": "",
        "schema_version": SCHEMA_VERSION,
        "normalization_status": "initialized",
        "fir_number": "",
        "complaint_date": "",
        "police_station": "",
        "incident_type": "",
        "reported_loss_inr": None,
        "description": "",
    },

    "persons": [],
    "phones": [],
    "sims": [],
    "sim_events": [],
    "devices": [],
    "accounts": [],
    "banking": [],
    "upi": [],
    "transactions": [],
    "calls": [],
    "sms": [],
    "ips": [],
    "locations": [],
    "web_activity": [],
    "evidence": [],
    "relationships": [],

    "normalization": {
        "files_processed": 0,
        "records_processed": 0,
        "records_normalized": 0,
        "records_rejected": 0,
        "duplicate_records": 0,
        "unmapped_fields": [],
        "warnings": [],
        "errors": [],
    },
}


TOPIC_SCHEMAS = {
    "persons": {
        "person_id": "",
        "name": "",
        "aliases": [],
        "role": "",
        "phone_ids": [],
        "phone_number": "",
        "account_ids": [],
        "account_number": "",
        "bank_name": "",
        "ifsc": "",
        "device_ids": [],
        "email": "",
        "date_of_birth": "",
        "gender": "",
        "address": "",
        "city": "",
        "state": "",
        "country": "",
        "account_open_date": "",
        "source_evidence_ids": [],
    },

    "phones": {
        "phone_id": "",
        "phone_number": "",
        "country_code": "",
        "person_ids": [],
        "sim_ids": [],
        "device_ids": [],
        "first_seen": "",
        "last_seen": "",
        "source_evidence_ids": [],
    },

    "sims": {
        "sim_id": "",
        "imsi": "",
        "msisdn": "",
        "iccid": "",
        "person_id": "",
        "device_ids": [],
        "activation_time": "",
        "deactivation_time": "",
        "status": "",
        "source_evidence_ids": [],
    },

    "sim_events": {
        "event_id": "",
        "timestamp": "",
        "phone_id": "",
        "event_type": "",
        "old_imsi": "",
        "new_imsi": "",
        "old_imei": "",
        "new_imei": "",
        "operator": "",
        "circle": "",
        "source_evidence_ids": [],
    },

    "devices": {
        "device_id": "",
        "imei": "",
        "device_type": "",
        "manufacturer": "",
        "model": "",
        "os": "",
        "person_ids": [],
        "phone_ids": [],
        "sim_ids": [],
        "ip_ids": [],
        "ip_address": "",
        "first_seen": "",
        "last_seen": "",
        "login_event": "",
        "source_evidence_ids": [],
    },

    "accounts": {
        "account_id": "",
        "account_number": "",
        "masked_account_number": "",
        "bank_name": "",
        "branch": "",
        "ifsc": "",
        "account_holder": "",
        "account_type": "",
        "opening_date": "",
        "status": "",
        "person_ids": [],
        "upi_ids": [],
        "transaction_ids": [],
        "source_evidence_ids": [],
    },

    "banking": {
        "banking_id": "",
        "account_id": "",
        "bank_name": "",
        "ifsc": "",
        "branch": "",
        "account_holder": "",
        "statement_date": "",
        "balance": None,
        "source_evidence_ids": [],
    },

    "upi": {
        "upi_id": "",
        "vpa": "",
        "linked_account_id": "",
        "bank_name": "",
        "person_id": "",
        "status": "",
        "first_seen": "",
        "last_seen": "",
        "transaction_ids": [],
        "source_evidence_ids": [],
    },

    "transactions": {
        "transaction_id": "",
        "timestamp": "",
        "sender_account_id": "",
        "receiver_account_id": "",
        "sender_upi_id": "",
        "receiver_upi_id": "",
        "upi_id": "",
        "amount": None,
        "currency": "INR",
        "transaction_type": "",
        "channel": "",
        "reference_number": "",
        "status": "",
        "merchant": "",
        "description": "",
        "source_evidence_ids": [],
    },

    "calls": {
        "call_id": "",
        "timestamp": "",
        "caller_phone_id": "",
        "receiver_phone_id": "",
        "duration_seconds": None,
        "call_type": "",
        "imei": "",
        "imsi": "",
        "cell_id": "",
        "location_id": "",
        "source_evidence_ids": [],
    },

    "sms": {
        "sms_id": "",
        "timestamp": "",
        "sender": "",
        "receiver": "",
        "message": "",
        "message_type": "",
        "phone_id": "",
        "device_id": "",
        "source_evidence_ids": [],
    },

    "ips": {
        "ip_id": "",
        "ip_address": "",
        "timestamp": "",
        "person_id": "",
        "device_id": "",
        "phone_id": "",
        "source": "",
        "location_id": "",
        "source_evidence_ids": [],
    },

    "locations": {
        "location_id": "",
        "latitude": None,
        "longitude": None,
        "accuracy": None,
        "cell_id": "",
        "address": "",
        "city": "",
        "state": "",
        "country": "",
        "source_evidence_ids": [],
    },

    "web_activity": {
        "web_activity_id": "",
        "timestamp": "",
        "url": "",
        "domain": "",
        "activity_type": "",
        "http_method": "",
        "status_code": "",
        "person_id": "",
        "device_id": "",
        "phone_id": "",
        "ip_id": "",
        "source_evidence_ids": [],
    },

    "relationships": {
        "relationship_id": "",
        "source_id": "",
        "source_type": "",
        "relationship_type": "",
        "target_id": "",
        "target_type": "",
        "timestamp": "",
        "source_evidence_ids": [],
    },
}


def create_case_template(case_id, title, created_at):
    case = deepcopy(MASTER_TEMPLATE)
    case["case"]["case_id"] = case_id
    case["case"]["case_title"] = title
    case["case"]["created_at"] = created_at
    return case


def create_topic_record(topic):
    if topic not in TOPIC_SCHEMAS:
        return {}
    return deepcopy(TOPIC_SCHEMAS[topic])
