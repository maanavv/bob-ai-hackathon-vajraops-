from collections import defaultdict
from datetime import datetime
from hashlib import sha256

from .cleaner import (
    clean_column_name,
    clean_value,
)
from .detector import (
    detect_topic,
    map_fields,
)
from .readers import read_file
from .schema import (
    create_case_template,
)
from .validator import (
    validate_field,
)


class NormalizationEngine:

    def __init__(
        self,
        case_id,
        title,
    ):

        self.case = create_case_template(
            case_id=case_id,
            title=title,
            created_at=datetime.now().isoformat(),
        )

        self.seen_records = defaultdict(
            set
        )

    # --------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------

    def process_file(
        self,
        filename,
        file_bytes,
    ):

        self.case[
            "normalization"
        ]["files_processed"] += 1

        try:

            dataframe = read_file(
                filename,
                file_bytes,
            )

        except Exception as exc:

            self.case[
                "normalization"
            ]["errors"].append(
                {
                    "file": filename,
                    "error": str(exc),
                }
            )

            return

        if dataframe.empty:

            self.case[
                "normalization"
            ]["warnings"].append(
                f"{filename}: empty file"
            )

            return

        # Normalize column names internally

        original_columns = list(
            dataframe.columns
        )

        topic, topic_confidence = detect_topic(
            original_columns
        )

        # Deterministic source hints prevent mixed schemas such as entities.csv
        # from being classified as accounts merely because they contain account fields.
        source_hints = {
            "entities.csv": "persons",
            "devices.csv": "devices",
            "cdr.csv": "calls",
            "transactions.csv": "transactions",
            "sim_events.csv": "sim_events",
            "cases.csv": "case",
            "sms.csv": "sms",
            "web.csv": "web_activity",
            "websites.csv": "web_activity",
            "browser_history.csv": "web_activity",
        }
        hinted_topic = source_hints.get(filename.strip().lower())
        if hinted_topic:
            topic = hinted_topic
            topic_confidence = 1.0

        mappings, unmapped = map_fields(
            topic,
            original_columns,
        )

        # Case metadata is stored on the case object rather than discarded as an unknown topic.
        if topic == "case":
            self.case["normalization"]["records_processed"] += len(dataframe)
            if len(dataframe):
                for key, value in dataframe.iloc[0].items():
                    field = clean_column_name(key)
                    cleaned = clean_value(field, value)
                    if cleaned == "":
                        continue
                    case_field = {
                        "case_id": "case_id",
                        "fir_number": "fir_number",
                        "complaint_date": "complaint_date",
                        "police_station": "police_station",
                        "incident_type": "incident_type",
                        "reported_loss_inr": "reported_loss_inr",
                        "description": "description",
                    }.get(field)
                    if case_field:
                        self.case["case"][case_field] = cleaned
                self.case["normalization"]["records_normalized"] += 1
            return

        self.case[
            "normalization"
        ]["unmapped_fields"].extend(
            [
                {
                    "file": filename,
                    "field": field,
                }
                for field in unmapped
            ]
        )

        # Process each row

        for index, row in dataframe.iterrows():

            self.case[
                "normalization"
            ]["records_processed"] += 1

            try:

                self._process_record(
                    topic=topic,
                    topic_confidence=topic_confidence,
                    mappings=mappings,
                    row=row,
                    filename=filename,
                    row_number=index + 2,
                )

            except Exception as exc:

                self.case[
                    "normalization"
                ]["records_rejected"] += 1

                self.case[
                    "normalization"
                ]["errors"].append(
                    {
                        "file": filename,
                        "row": index + 2,
                        "error": str(exc),
                    }
                )

    # --------------------------------------------------------
    # RECORD PROCESSOR
    # --------------------------------------------------------

    def _process_record(
        self,
        topic,
        topic_confidence,
        mappings,
        row,
        filename,
        row_number,
    ):

        # Unknown topic

        if topic == "unknown":

            self.case[
                "normalization"
            ]["warnings"].append(
                f"{filename}: topic could not be determined"
            )

            return

        normalized = {}

        raw_data = {}

        # ----------------------------------------------
        # Map columns
        # ----------------------------------------------

        for column, value in row.items():

            original_column = str(
                column
            )

            raw_data[
                original_column
            ] = (
                ""
                if value is None
                else str(value)
            )

            mapping = mappings.get(
                column
            )

            if not mapping:
                continue

            field = mapping[
                "field"
            ]

            cleaned = clean_value(
                field,
                value,
            )

            if cleaned == "":
                continue

            # Validation

            if not validate_field(
                field,
                cleaned,
            ):

                self.case[
                    "normalization"
                ]["warnings"].append(
                    {
                        "file": filename,
                        "row": row_number,
                        "field": field,
                        "value": str(cleaned),
                        "message": "Validation failed",
                    }
                )

                continue

            normalized[
                field
            ] = cleaned

        # ----------------------------------------------
        # Evidence
        # ----------------------------------------------

        evidence_id = self._make_id(
            "EVD",
            filename,
            row_number,
        )

        evidence = {

            "evidence_id": evidence_id,

            "source_file": filename,

            "source_type": topic,

            "source_record": f"ROW-{row_number}",

            "source_location": (
                f"{filename}:row:{row_number}"
            ),

            "extracted_at": datetime.now().isoformat(),

            "extraction_method": "automatic_normalization",

            "confidence": round(
                topic_confidence,
                3,
            ),
        }

        self.case[
            "evidence"
        ].append(
            evidence
        )

        # ----------------------------------------------
        # Add evidence provenance
        # ----------------------------------------------

        normalized[
            "source_evidence_ids"
        ] = [evidence_id]

        # ----------------------------------------------
        # Add canonical ID
        # ----------------------------------------------

        topic_id = self._generate_record_id(
            topic,
            normalized,
            filename,
            row_number,
        )

        id_field = self._id_field(
            topic
        )

        if id_field and not normalized.get(id_field):
            normalized[id_field] = topic_id

        # ----------------------------------------------
        # Duplicate detection
        # ----------------------------------------------

        fingerprint = self._fingerprint(
            topic,
            normalized,
        )

        if fingerprint in self.seen_records[
            topic
        ]:

            self.case[
                "normalization"
            ]["duplicate_records"] += 1

            return

        self.seen_records[
            topic
        ].add(
            fingerprint
        )

        # ----------------------------------------------
        # Add canonical record
        # ----------------------------------------------

        self.case[
            topic
        ].append(
            normalized
        )

        self.case[
            "normalization"
        ]["records_normalized"] += 1

        # ----------------------------------------------
        # Relationships
        # ----------------------------------------------

        self._create_relationships(
            topic,
            normalized,
            evidence_id,
        )

    # --------------------------------------------------------
    # ID GENERATION
    # --------------------------------------------------------

    def _make_id(
        self,
        prefix,
        filename,
        row_number,
    ):

        raw = (
            f"{self.case['case']['case_id']}"
            f"|{filename}"
            f"|{row_number}"
        )

        digest = sha256(
            raw.encode()
        ).hexdigest()[:12]

        return f"{prefix}-{digest}"

    def _generate_record_id(
        self,
        topic,
        normalized,
        filename,
        row_number,
    ):

        raw = "|".join(
            str(value)
            for value in normalized.values()
            if value
        )

        if not raw:

            raw = (
                f"{filename}:{row_number}"
            )

        digest = sha256(
            raw.encode()
        ).hexdigest()[:12]

        prefix = topic.rstrip(
            "s"
        ).upper()

        return f"{prefix}-{digest}"

    def _id_field(self, topic):

        return {

            "persons": "person_id",

            "phones": "phone_id",

            "sims": "sim_id",

            "sim_events": "event_id",

            "devices": "device_id",

            "accounts": "account_id",

            "banking": "banking_id",

            "upi": "upi_id",

            "transactions": "transaction_id",

            "calls": "call_id",

            "sms": "sms_id",

            "ips": "ip_id",

            "locations": "location_id",

            "web_activity": "web_activity_id",

        }.get(topic)

    # --------------------------------------------------------
    # DUPLICATE FINGERPRINT
    # --------------------------------------------------------

    def _fingerprint(
        self,
        topic,
        record,
    ):

        important = {

            key: value

            for key, value in record.items()

            if key not in [
                "source_evidence_ids",
            ]
        }

        raw = repr(
            sorted(
                important.items()
            )
        )

        return sha256(
            raw.encode()
        ).hexdigest()

    # --------------------------------------------------------
    # RELATIONSHIP GENERATION
    # --------------------------------------------------------

    def _create_relationships(
        self,
        topic,
        record,
        evidence_id,
    ):

        relationships = []

        if topic == "transactions":

            sender = record.get(
                "sender_account_id"
            )

            receiver = record.get(
                "receiver_account_id"
            )

            if sender and receiver:

                relationships.append(
                    self._relationship(
                        sender,
                        "ACCOUNT",
                        "TRANSFERRED_TO",
                        receiver,
                        "ACCOUNT",
                        evidence_id,
                    )
                )

        elif topic == "calls":

            caller = record.get(
                "caller_phone_id"
            )

            receiver = record.get(
                "receiver_phone_id"
            )

            if caller and receiver:

                relationships.append(
                    self._relationship(
                        caller,
                        "PHONE",
                        "CALLED",
                        receiver,
                        "PHONE",
                        evidence_id,
                    )
                )

        elif topic == "upi":

            upi = record.get(
                "upi_id"
            )

            account = record.get(
                "linked_account_id"
            )

            if upi and account:

                relationships.append(
                    self._relationship(
                        upi,
                        "UPI",
                        "LINKED_TO",
                        account,
                        "ACCOUNT",
                        evidence_id,
                    )
                )

        elif topic == "sims":

            sim = record.get("sim_id")
            person = record.get("person_id")
            if sim and person:
                relationships.append(self._relationship(
                    sim, "SIM", "ASSIGNED_TO", person, "PERSON", evidence_id
                ))

        elif topic == "sim_events":
            phone = record.get("phone_id")
            if phone:
                event_type = str(record.get("event_type") or "SIM_EVENT").upper()
                relationships.append(self._relationship(
                    phone, "PHONE", event_type,
                    record.get("new_imsi") or record.get("old_imsi") or "SIM_EVENT",
                    "SIM", evidence_id
                ))

        elif topic == "web_activity":
            person = record.get("person_id")
            device = record.get("device_id")
            ip_id = record.get("ip_id")
            url = record.get("url") or record.get("domain")
            if person and url:
                relationships.append(self._relationship(
                    person, "PERSON", "VISITED", url, "WEBSITE", evidence_id
                ))
            if device and url:
                relationships.append(self._relationship(
                    device, "DEVICE", "VISITED", url, "WEBSITE", evidence_id
                ))
            if ip_id and url:
                relationships.append(self._relationship(
                    ip_id, "IP", "REQUESTED", url, "WEBSITE", evidence_id
                ))

        self.case[
            "relationships"
        ].extend(
            [
                r
                for r in relationships
                if r
            ]
        )

    def _relationship(
        self,
        source_id,
        source_type,
        relationship_type,
        target_id,
        target_type,
        evidence_id,
    ):

        raw = (
            f"{source_id}|"
            f"{relationship_type}|"
            f"{target_id}"
        )

        relationship_id = (
            "REL-"
            + sha256(
                raw.encode()
            ).hexdigest()[:12]
        )

        return {

            "relationship_id":
                relationship_id,

            "source_id":
                source_id,

            "source_type":
                source_type,

            "relationship_type":
                relationship_type,

            "target_id":
                target_id,

            "target_type":
                target_type,

            "timestamp": "",

            "source_evidence_ids":
                [evidence_id],
        }

    # --------------------------------------------------------
    # FINALIZE
    # --------------------------------------------------------

    def _link_identity_entities(self):
        """Create deterministic ownership links from shared source identifiers."""
        existing = {(
            r.get("source_id"), r.get("relationship_type"), r.get("target_id")
        ) for r in self.case["relationships"]}
        def add(src, stype, rtype, dst, dtype):
            if not src or not dst:
                return
            key = (src, rtype, dst)
            if key in existing:
                return
            self.case["relationships"].append({
                "relationship_id": "REL-" + sha256(f"{src}|{rtype}|{dst}".encode()).hexdigest()[:12],
                "source_id": src,
                "source_type": stype,
                "relationship_type": rtype,
                "target_id": dst,
                "target_type": dtype,
                "timestamp": "",
                "source_evidence_ids": [],
            })
            existing.add(key)

        # PERSON -> ACCOUNT / PHONE / DEVICE from direct canonical fields.
        accounts_by_number = {str(a.get("account_number")): a for a in self.case.get("accounts", []) if a.get("account_number")}
        phones_by_number = {str(p.get("phone_number")): p for p in self.case.get("phones", []) if p.get("phone_number")}
        devices_by_id = {str(d.get("device_id")): d for d in self.case.get("devices", []) if d.get("device_id")}
        for person in self.case.get("persons", []):
            pid = person.get("person_id")
            if not pid:
                continue
            account_number = person.get("account_number")
            account = accounts_by_number.get(str(account_number)) if account_number else None
            if account:
                add(pid, "PERSON", "OWNS", account.get("account_id"), "ACCOUNT")
            phone_value = person.get("phone_number")
            phone = phones_by_number.get(str(phone_value)) if phone_value else None
            if phone:
                add(pid, "PERSON", "USES", phone.get("phone_id"), "PHONE")
                for did in phone.get("device_ids", []) or []:
                    add(pid, "PERSON", "USES", did, "DEVICE")
            # Devices directly published with person_id are handled below.
        for device in self.case.get("devices", []):
            for pid in device.get("person_ids", []) or []:
                add(pid, "PERSON", "USES", device.get("device_id"), "DEVICE")
            if device.get("person_id"):
                add(device.get("person_id"), "PERSON", "USES", device.get("device_id"), "DEVICE")
            if device.get("phone_ids"):
                for pid in [p.get("person_id") for p in self.case.get("persons", []) if p.get("phone_number") and any(str(x) == str(p.get("phone_number")) for x in device.get("phone_ids", []))]:
                    add(pid, "PERSON", "USES", device.get("device_id"), "DEVICE")

    def finalize(self):

        self._link_identity_entities()
        self.case[
            "case"
        ][
            "normalization_status"
        ] = "completed"

        return self.case
