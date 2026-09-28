ALIASES = {

    "persons": {

        "person_id": ["person_id", "person", "subject_id", "entity_id"],
        "name": [
            "name",
            "full_name",
            "person_name",
            "customer_name",
            "account_holder",
            "beneficiary_name",
            "accused_name",
        ],

        "address": [
            "address",
            "residential_address",
            "permanent_address",
            "location",
        ],
        "role": ["role", "person_role", "entity_role"],
        "phone_ids": ["phone_ids"],
        "phone_number": ["phone", "phone_number", "mobile", "mobile_number"],
        "account_ids": ["account_ids"],
        "account_number": ["account_number", "account_no", "bank_account", "bank_account_number"],
        "bank_name": ["bank_name", "bank"],
        "ifsc": ["ifsc", "ifsc_code"],
        "device_ids": ["device_ids"],
        "email": ["email", "email_address"],
        "date_of_birth": ["date_of_birth", "dob", "birth_date"],
        "gender": ["gender", "sex"],
        "city": ["city", "town"],
        "state": ["state", "province"],
        "country": ["country", "country_name"],
        "account_open_date": ["account_open_date", "account_opening_date", "opening_date"],
    },

    "phones": {

        "phone_number": [
            "phone",
            "mobile",
            "mobile_number",
            "phone_number",
            "telephone",
            "msisdn",
            "contact",
            "calling_number",
        ],
    },

    "sims": {

        "sim_id": ["sim_id", "sim", "event_id"],
        "person_id": ["person_id"],
        "device_ids": ["device_id", "device_ids"],
        "activation_time": ["activation_time", "activated_at"],
        "deactivation_time": ["deactivation_time", "deactivated_at"],
        "status": ["status", "sim_status"],
        "imsi": [
            "imsi",
            "subscriber_id",
            "subscriber_identity",
        ],

        "msisdn": [
            "msisdn",
            "mobile",
            "mobile_number",
            "phone",
            "phone_number",
        ],

        "iccid": [
            "iccid",
            "sim_number",
            "sim_serial",
            "sim_serial_number",
        ],
    },

    "devices": {

        "device_id": ["device_id", "device", "handset_id"],
        "person_ids": ["person_id", "person_ids"],
        "phone_ids": ["phone", "phone_id", "phone_number"],
        "ip_address": ["ip", "ip_address"],
        "first_seen": ["first_seen"],
        "last_seen": ["last_seen"],
        "login_event": ["login_event"],
        "imei": [
            "imei",
            "imei_number",
            "device_imei",
        ],

        "manufacturer": [
            "manufacturer",
            "brand",
            "device_brand",
        ],

        "model": [
            "model",
            "device_model",
            "handset_model",
        ],

        "os": [
            "os",
            "operating_system",
            "platform",
        ],
    },

    "accounts": {

        "account_number": [
            "account",
            "account_number",
            "account_no",
            "account_num",
            "bank_account",
            "bank_account_number",
        ],

        "bank_name": [
            "bank",
            "bank_name",
            "bank_name",
        ],

        "ifsc": [
            "ifsc",
            "ifsc_code",
        ],

        "account_holder": [
            "account_holder",
            "account_name",
            "holder",
            "customer_name",
        ],
    },

    "upi": {

        "vpa": [
            "upi",
            "upi_id",
            "upi_vpa",
            "vpa",
            "virtual_payment_address",
        ],
    },

    "transactions": {

        "transaction_id": [
            "transaction_id",
            "txn_id",
            "transaction",
            "txn",
            "transaction_reference",
            "reference_number",
            "utr",
            "rrn",
            "transaction_ref",
            "txn_ref",
        ],

        "timestamp": [
            "timestamp",
            "datetime",
            "date_time",
            "transaction_date",
            "transaction_datetime",
            "date",
            "time",
        ],

        "amount": [
            "amount",
            "transaction_amount",
            "txn_amount",
            "value",
            "total",
            "transaction_value",
            "debit",
            "credit",
        ],

        "sender_account_id": [
            "sender",
            "sender_account",
            "sender_account_number",
            "from_account",
            "debit_account",
        ],

        "receiver_account_id": [
            "receiver",
            "receiver_account",
            "receiver_account_number",
            "to_account",
            "credit_account",
        ],

        "sender_upi_id": [
            "sender_upi",
            "sender_vpa",
            "from_upi",
        ],

        "receiver_upi_id": [
            "receiver_upi",
            "receiver_vpa",
            "to_upi",
            "beneficiary_upi",
        ],

        "reference_number": [
            "reference",
            "reference_number",
            "ref_no",
            "utr",
            "rrn",
        ],

        "status": [
            "status",
            "transaction_status",
            "payment_status",
        ],

        "merchant": [
            "merchant",
            "merchant_name",
            "payee",
            "beneficiary",
        ],

        "description": [
            "description",
            "narration",
            "remarks",
            "details",
        ],
        "transaction_type": ["transaction_type", "txn_type", "payment_type"],
        "channel": ["channel", "payment_channel", "source_channel"],
        "upi_id": ["upi_id", "upi", "vpa"],
    },

    "calls": {

        "call_id": ["call_id", "cdr_id"],
        "caller_phone_id": [
            "caller",
            "calling_number",
            "caller_number",
            "a_party",
            "source",
            "from",
        ],

        "receiver_phone_id": [
            "receiver",
            "called_number",
            "receiver_number",
            "b_party",
            "destination",
            "to",
        ],

        "timestamp": [
            "timestamp",
            "datetime",
            "date_time",
            "call_time",
            "call_datetime",
            "date",
        ],

        "duration_seconds": [
            "duration",
            "duration_seconds",
            "call_duration",
            "duration_sec",
            "seconds",
        ],

        "call_type": [
            "call_type",
            "type",
            "direction",
            "call_direction",
        ],

        "imei": [
            "imei",
            "imei_number",
        ],

        "imsi": [
            "imsi",
            "subscriber_id",
        ],

        "cell_id": [
            "cell_id",
            "cell",
            "tower_id",
            "cell_tower",
        ],
    },

    "sms": {

        "timestamp": [
            "timestamp",
            "datetime",
            "date_time",
            "sms_time",
            "message_time",
            "date",
        ],

        "sender": [
            "sender",
            "sender_number",
            "from",
            "source",
        ],

        "receiver": [
            "receiver",
            "receiver_number",
            "to",
            "destination",
        ],

        "message": [
            "message",
            "sms",
            "text",
            "message_body",
            "body",
            "content",
        ],
    },

    "sim_events": {
        "event_id": ["event_id", "sim_event_id"],
        "timestamp": ["timestamp", "datetime", "date_time", "event_time"],
        "phone_id": ["phone", "phone_id", "msisdn", "mobile"],
        "event_type": ["event_type", "event", "type"],
        "old_imsi": ["old_imsi"],
        "new_imsi": ["new_imsi"],
        "old_imei": ["old_imei"],
        "new_imei": ["new_imei"],
        "operator": ["operator", "carrier", "telecom_operator"],
        "circle": ["circle", "telecom_circle"],
    },

    "web_activity": {
        "timestamp": ["timestamp", "datetime", "date_time", "visit_time", "access_time"],
        "url": ["url", "uri", "link", "website", "web_url"],
        "domain": ["domain", "host", "hostname", "website_domain"],
        "activity_type": ["activity_type", "action", "event_type"],
        "http_method": ["http_method", "method"],
        "status_code": ["status_code", "http_status", "response_code"],
        "person_id": ["person_id", "user_id"],
        "device_id": ["device_id"],
        "phone_id": ["phone", "phone_id", "phone_number"],
        "ip_id": ["ip_id"],
    },

    "ips": {

        "ip_address": [
            "ip",
            "ip_address",
            "source_ip",
            "destination_ip",
            "client_ip",
        ],

        "timestamp": [
            "timestamp",
            "datetime",
            "date_time",
            "login_time",
        ],
    },
}


TOPIC_ALIASES = {

    "transactions": [
        "transaction",
        "transactions",
        "txn",
        "txns",
        "payment",
        "payments",
        "transfer",
        "transfers",
        "upi transaction",
        "bank transaction",
    ],

    "calls": [
        "call",
        "calls",
        "cdr",
        "call detail record",
        "call logs",
        "call records",
    ],

    "sms": [
        "sms",
        "message",
        "messages",
        "text messages",
        "sms logs",
    ],

    "sims": [
        "sim",
        "sim records",
        "sim events",
        "subscriber",
        "subscriber records",
    ],

    "devices": [
        "device",
        "devices",
        "handset",
        "imei",
        "device records",
    ],

    "accounts": [
        "account",
        "accounts",
        "bank account",
        "bank accounts",
    ],

    "banking": [
        "bank",
        "banking",
        "bank statement",
        "statements",
    ],

    "upi": [
        "upi",
        "vpa",
        "upi records",
    ],

    "persons": [
        "person",
        "entity",
        "entities",
        "persons",
        "people",
        "customer",
        "customers",
        "accused",
        "suspect",
    ],

    "web_activity": [
        "web",
        "website",
        "websites",
        "browser history",
        "browsing history",
        "web logs",
        "url logs",
        "http logs",
    ],

    "sim_events": [
        "sim event",
        "sim events",
        "sim swap",
        "subscriber events",
    ],

    "ips": [
        "ip",
        "ip address",
        "ip logs",
        "network logs",
    ],

    "locations": [
        "location",
        "locations",
        "gps",
        "coordinates",
        "cell location",
    ],
}
