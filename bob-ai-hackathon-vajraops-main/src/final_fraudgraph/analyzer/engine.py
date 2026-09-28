from __future__ import annotations

from collections import defaultdict, Counter, deque
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Canonical profile fields. These are deliberately explicit so the output
# schema is stable and suitable for a frontend, export, or later ML layer.
# ---------------------------------------------------------------------------
PROFILE_FIELDS = {
    "subject_id": "",
    "subject_type": "PERSON",
    "name": "",
    "role": "",
    "role_hypotheses": [],
    "identifiers": {
        "person_ids": [],
        "account_ids": [],
        "account_numbers": [],
        "upi_ids": [],
        "upi_vpas": [],
        "phone_ids": [],
        "phone_numbers": [],
        "sim_ids": [],
        "imsis": [],
        "imeis": [],
        "observed_imsis": [],
        "observed_imeis": [],
        "device_ids": [],
        "ip_ids": [],
        "ip_addresses": [],
        "location_ids": [],
        "emails": [],
    },
    "identity_evidence": [],
    "evidence_ids": [],
    "statistics": {
        "transactions_count": 0,
        "calls_count": 0,
        "sms_count": 0,
        "web_activity_count": 0,
        "sim_events_count": 0,
        "devices_count": 0,
        "accounts_count": 0,
        "phones_count": 0,
        "unique_counterparties": 0,
        "money_in_inr": 0.0,
        "money_out_inr": 0.0,
        "call_duration_seconds": 0,
    },
    "transactions": [],
    "calls": [],
    "sms": [],
    "web_activity": [],
    "sim_events": [],
    "timeline": [],
    "relationships": [],
}


class AnalyzerEngine:
    """Second-stage forensic analysis over a normalized case JSON.

    Design goals:
      1. Preserve original normalized fields and evidence references.
      2. Resolve identifiers to people where the data supports it.
      3. Never silently claim ownership when the evidence is insufficient.
      4. Produce deterministic, JSON-serializable output.
    """

    WEB_TOPICS = {
        "web_activity", "websites", "website", "browser_history",
        "browsing_history", "urls", "url_logs", "http_logs", "web_logs",
    }

    def __init__(self, case: Dict[str, Any]):
        if not isinstance(case, dict):
            raise TypeError("case must be a dictionary loaded from normalized JSON")
        self.case = case
        self._records = self._collect_records()
        self._evidence = self._index(self._records.get("evidence", []), "evidence_id")
        self._ids = self._build_id_indices()
        self._entity_to_subjects: Dict[Tuple[str, str], set[str]] = defaultdict(set)
        self._warnings: List[Dict[str, Any]] = []
        self._subjects = self._build_subject_seeds()
        self._build_identity_links()
        self._attach_non_person_entities()
        self._attach_events()

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    def analyze(self) -> Dict[str, Any]:
        profiles = self._finalize_profiles()
        findings = self._detect_patterns(profiles)
        network = self._build_network(profiles, findings)
        network["entity_network"] = self._build_entity_network()
        case_brief = self._build_case_brief(profiles, findings)

        return {
            "analysis": {
                "analysis_version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "case_id": self.case.get("case", {}).get("case_id", ""),
                "case_title": self.case.get("case", {}).get("case_title", ""),
                "status": "completed",
            },
            "subject_profiles": profiles,
            "network": network,
            "findings": findings,
            "case_brief": case_brief,
            "data_quality": {
                "warnings": self._warnings,
                "unresolved_entities": self._unresolved_entities(),
            },
        }

    # ------------------------------------------------------------------
    # COLLECTION / INDEX HELPERS
    # ------------------------------------------------------------------
    def _collect_records(self) -> Dict[str, List[Dict[str, Any]]]:
        output = {}
        for key, value in self.case.items():
            if isinstance(value, list):
                output[key] = [x for x in value if isinstance(x, dict)]
        return output

    @staticmethod
    def _index(items: Iterable[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
        result = {}
        for item in items:
            value = item.get(key)
            if value not in (None, ""):
                result[str(value)] = item
        return result

    @staticmethod
    def _add_unique(target: List[Any], value: Any) -> None:
        if value in (None, "", []):
            return
        if value not in target:
            target.append(value)

    @staticmethod
    def _as_list(value: Any) -> List[Any]:
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _clean_phone(value: Any) -> str:
        if value in (None, ""):
            return ""
        digits = re.sub(r"\D", "", str(value))
        if len(digits) == 10:
            return "+91" + digits
        if len(digits) == 12 and digits.startswith("91"):
            return "+" + digits
        if digits:
            return "+" + digits if str(value).strip().startswith("+") is False and len(digits) >= 11 else digits
        return ""

    @staticmethod
    def _amount(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _timestamp(value: Any) -> Optional[datetime]:
        if value in (None, ""):
            return None
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            # Small fallback set; the normalizer normally emits ISO timestamps.
            for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    @classmethod
    def _sort_key(cls, record: Dict[str, Any]) -> datetime:
        return cls._timestamp(record.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)

    @staticmethod
    def _evidence_ids(record: Dict[str, Any]) -> List[str]:
        values = record.get("source_evidence_ids", [])
        return [str(x) for x in values if x not in (None, "")]

    def _display_name(self, subject: Dict[str, Any]) -> str:
        return subject.get("name") or subject.get("subject_id") or "Unknown Subject"

    # ------------------------------------------------------------------
    # ENTITY INDEX / SUBJECT SEEDS
    # ------------------------------------------------------------------
    def _build_id_indices(self) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
        index: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        field_map = {
            "persons": ["person_id"],
            "phones": ["phone_id", "phone_number"],
            "sims": ["sim_id", "imsi", "msisdn", "iccid"],
            "devices": ["device_id", "imei", "ip_address"],
            "accounts": ["account_id", "account_number"],
            "upi": ["upi_id", "vpa"],
            "ips": ["ip_id", "ip_address"],
            "locations": ["location_id", "cell_id"],
        }
        for topic, fields in field_map.items():
            for item in self._records.get(topic, []):
                for field in fields:
                    value = item.get(field)
                    if value in (None, ""):
                        continue
                    index[(topic, str(value))].append(item)
        return index

    def _new_profile(self, subject_id: str, name: str = "", role: str = "", subject_type: str = "PERSON") -> Dict[str, Any]:
        profile = deepcopy(PROFILE_FIELDS)
        profile["subject_id"] = subject_id
        profile["name"] = name
        profile["role"] = role
        profile["subject_type"] = subject_type
        return profile

    def _build_subject_seeds(self) -> Dict[str, Dict[str, Any]]:
        subjects: Dict[str, Dict[str, Any]] = {}
        persons = self._records.get("persons", [])

        for person in persons:
            pid = str(person.get("person_id") or "")
            if not pid:
                continue
            profile = self._new_profile(pid, str(person.get("name") or ""), str(person.get("role") or ""))
            profile["identifiers"]["person_ids"].append(pid)
            for field, out_key in [
                ("email", "emails"),
                ("city", "location_ids"),
            ]:
                # city is not an ID; it is added to the timeline/metadata only when useful.
                if field == "email" and person.get(field):
                    self._add_unique(profile["identifiers"][out_key], person[field])
            self._add_identity_fields(profile, person)
            profile["identity_evidence"].extend(self._evidence_ids(person))
            subjects[pid] = profile

        # Compatibility path: if persons are absent, derive a subject from accounts
        # only when the account record itself has a holder/person mapping.
        if not subjects:
            for account in self._records.get("accounts", []):
                person_ids = self._as_list(account.get("person_ids"))
                holder = account.get("account_holder")
                for pid in person_ids:
                    pid = str(pid)
                    subjects.setdefault(pid, self._new_profile(pid, str(holder or pid)))
                    self._add_identity_fields(subjects[pid], account)
            # Best-effort recovery from preserved raw evidence emitted by v1.1 normalizer.
            for ev in self._records.get("evidence", []):
                raw = ev.get("raw_data")
                if not isinstance(raw, dict) or not raw.get("person_id"):
                    continue
                pid = str(raw["person_id"])
                subjects.setdefault(pid, self._new_profile(pid, str(raw.get("name") or pid), str(raw.get("role") or "")))
                profile = subjects[pid]
                self._add_identity_fields(profile, raw, raw_keys=True)
                self._add_unique(profile["identity_evidence"], ev.get("evidence_id"))

        if not subjects:
            self._warnings.append({
                "type": "NO_PERSON_SEEDS",
                "message": "No person entities or recoverable person_id records were present in the normalized case. Entity-level subjects will be emitted instead where possible.",
            })
            # Entity-level fallback keeps the analyzer useful on imperfect JSON.
            for account in self._records.get("accounts", []):
                aid = str(account.get("account_id") or account.get("account_number") or "")
                if aid:
                    subjects[f"ENTITY-{aid}"] = self._new_profile(
                        f"ENTITY-{aid}", str(account.get("account_holder") or account.get("bank_name") or aid), "", "ENTITY"
                    )
                    self._add_identity_fields(subjects[f"ENTITY-{aid}"], account)

        return subjects

    def _add_identity_fields(self, profile: Dict[str, Any], item: Dict[str, Any], raw_keys: bool = False) -> None:
        # Handle both canonical and common source-field forms.
        def first(*keys):
            for key in keys:
                if item.get(key) not in (None, ""):
                    return item.get(key)
            return None

        for value in self._as_list(first("account_id")):
            self._add_unique(profile["identifiers"]["account_ids"], value)
        for value in self._as_list(first("account_number", "bank_account_number")):
            self._add_unique(profile["identifiers"]["account_numbers"], value)
        for value in self._as_list(first("upi_id")):
            self._add_unique(profile["identifiers"]["upi_ids"], value)
        for value in self._as_list(first("vpa")):
            self._add_unique(profile["identifiers"]["upi_vpas"], value)
        for value in self._as_list(first("phone_id")):
            self._add_unique(profile["identifiers"]["phone_ids"], value)
        for value in self._as_list(first("phone_number", "phone", "msisdn")):
            phone = self._clean_phone(value)
            if phone:
                self._add_unique(profile["identifiers"]["phone_numbers"], phone)
        for value in self._as_list(first("sim_id")):
            self._add_unique(profile["identifiers"]["sim_ids"], value)
        for value in self._as_list(first("imsi")):
            self._add_unique(profile["identifiers"]["imsis"], str(value))
        for value in self._as_list(first("imei")):
            self._add_unique(profile["identifiers"]["imeis"], str(value))
        for value in self._as_list(first("device_id")):
            self._add_unique(profile["identifiers"]["device_ids"], value)
        for value in self._as_list(first("ip_id")):
            self._add_unique(profile["identifiers"]["ip_ids"], value)
        for value in self._as_list(first("ip_address", "ip")):
            self._add_unique(profile["identifiers"]["ip_addresses"], value)
        for value in self._as_list(first("location_id")):
            self._add_unique(profile["identifiers"]["location_ids"], value)
        for value in self._as_list(first("email", "email_address")):
            self._add_unique(profile["identifiers"]["emails"], value)

    # ------------------------------------------------------------------
    # IDENTITY RESOLUTION
    # ------------------------------------------------------------------
    def _link(self, subject_id: str, entity_type: str, entity_value: Any) -> None:
        if entity_value in (None, ""):
            return
        value = str(entity_value)
        self._entity_to_subjects[(entity_type.upper(), value)].add(subject_id)

    def _build_identity_links(self) -> None:
        for sid, profile in self._subjects.items():
            ids = profile["identifiers"]
            for value in ids["person_ids"]:
                self._link(sid, "PERSON", value)
            for value in ids["account_ids"]:
                self._link(sid, "ACCOUNT", value)
            for value in ids["account_numbers"]:
                self._link(sid, "ACCOUNT", value)
            for value in ids["phone_ids"]:
                self._link(sid, "PHONE", value)
            for value in ids["phone_numbers"]:
                self._link(sid, "PHONE", value)
            for value in ids["sim_ids"]:
                self._link(sid, "SIM", value)
            for value in ids["imsis"]:
                self._link(sid, "SIM", value)
            for value in ids["imeis"]:
                self._link(sid, "DEVICE", value)
            for value in ids["device_ids"]:
                self._link(sid, "DEVICE", value)
            for value in ids["ip_ids"]:
                self._link(sid, "IP", value)
            for value in ids["ip_addresses"]:
                self._link(sid, "IP", value)
            for value in ids["upi_ids"]:
                self._link(sid, "UPI", value)
            for value in ids["upi_vpas"]:
                self._link(sid, "UPI", value)

        # Canonical entity relationships are additional identity evidence.
        for account in self._records.get("accounts", []):
            for pid in self._as_list(account.get("person_ids")):
                if str(pid) in self._subjects:
                    for key in ("account_id", "account_number"):
                        self._link(str(pid), "ACCOUNT", account.get(key))
        for phone in self._records.get("phones", []):
            for pid in self._as_list(phone.get("person_ids")):
                if str(pid) in self._subjects:
                    for key in ("phone_id", "phone_number"):
                        self._link(str(pid), "PHONE", phone.get(key))
        for device in self._records.get("devices", []):
            for pid in self._as_list(device.get("person_ids")):
                if str(pid) in self._subjects:
                    for key in ("device_id", "imei", "ip_address"):
                        self._link(str(pid), "DEVICE", device.get(key))
                    self._link(str(pid), "IP", device.get("ip_address"))
                    for ph in self._as_list(device.get("phone_ids")):
                        self._link(str(pid), "PHONE", ph)

    def _subjects_for_entity(self, entity_type: str, value: Any) -> set[str]:
        if value in (None, ""):
            return set()
        value = str(value)
        direct = set(self._entity_to_subjects.get((entity_type.upper(), value), set()))
        if entity_type.upper() == "PHONE":
            direct |= set(self._entity_to_subjects.get(("PHONE", self._clean_phone(value)), set()))
        return direct

    def _attach_non_person_entities(self) -> None:
        # Merge all explicit entity relationships into profiles.
        for account in self._records.get("accounts", []):
            for pid in self._as_list(account.get("person_ids")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(account))
                self._add_identity_fields(self._subjects[pid], account)
        for phone in self._records.get("phones", []):
            for pid in self._as_list(phone.get("person_ids")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(phone))
                self._add_identity_fields(self._subjects[pid], phone)
        for sim in self._records.get("sims", []):
            for pid in self._as_list(sim.get("person_id")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(sim))
                self._add_identity_fields(self._subjects[pid], sim)
        for device in self._records.get("devices", []):
            for pid in self._as_list(device.get("person_ids")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(device))
                self._add_identity_fields(self._subjects[pid], device)
        for upi in self._records.get("upi", []):
            for pid in self._as_list(upi.get("person_id")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(upi))
                self._add_identity_fields(self._subjects[pid], upi)
        for ip in self._records.get("ips", []):
            for pid in self._as_list(ip.get("person_id")):
                pid = str(pid)
                if pid not in self._subjects:
                    continue
                self._subjects[pid]["identity_evidence"].extend(self._evidence_ids(ip))
                self._add_identity_fields(self._subjects[pid], ip)

    # ------------------------------------------------------------------
    # EVENT PROJECTION
    # ------------------------------------------------------------------
    def _event_target_subjects(self, record: Dict[str, Any], source_fields: Iterable[Tuple[str, str]]) -> set[str]:
        subjects = set()
        for field, etype in source_fields:
            for value in self._as_list(record.get(field)):
                subjects |= self._subjects_for_entity(etype, value)
        return subjects

    def _append_event(self, profile: Dict[str, Any], topic: str, record: Dict[str, Any], direction: str = "RELATED") -> None:
        timestamp = record.get("timestamp")
        event_type = {
            "transactions": "TRANSACTION",
            "calls": "CALL",
            "sms": "SMS",
            "web_activity": "WEB_ACTIVITY",
            "sim_events": "SIM_EVENT",
        }.get(topic, topic.upper())
        event = {
            "event_id": record.get("transaction_id") or record.get("call_id") or record.get("sms_id") or record.get("web_activity_id") or record.get("event_id"),
            "timestamp": timestamp or "",
            "type": event_type,
            "direction": direction,
            "details": deepcopy(record),
            "evidence_ids": self._evidence_ids(record),
        }
        profile["timeline"].append(event)
        profile[topic].append(event)

    def _attach_events(self) -> None:
        # Transactions: account-number IDs in imperfect normalized data are
        # deliberately resolved against both canonical account_id and account_number.
        for txn in self._records.get("transactions", []):
            sender = txn.get("sender_account_id")
            receiver = txn.get("receiver_account_id")
            senders = self._subjects_for_entity("ACCOUNT", sender)
            receivers = self._subjects_for_entity("ACCOUNT", receiver)
            for sid in senders:
                self._append_event(self._subjects[sid], "transactions", txn, "OUTGOING")
            for sid in receivers:
                self._append_event(self._subjects[sid], "transactions", txn, "INCOMING")

        # Calls are associated to caller/receiver subjects independently.
        for call in self._records.get("calls", []):
            caller = self._event_target_subjects(call, [("caller_phone_id", "PHONE")])
            receiver = self._event_target_subjects(call, [("receiver_phone_id", "PHONE")])
            # IMEI/IMSI are evidence attached to the call, not proof that the device/SIM owner is the caller.
            for sid in caller:
                profile = self._subjects[sid]
                self._append_event(profile, "calls", call, "OUTGOING")
                self._add_unique(profile["identifiers"]["observed_imeis"], call.get("imei"))
                self._add_unique(profile["identifiers"]["observed_imsis"], call.get("imsi"))
            for sid in receiver - caller:
                self._append_event(self._subjects[sid], "calls", call, "INCOMING")

        # SMS supports both explicit phone_id and sender/receiver numbers.
        for sms in self._records.get("sms", []):
            senders = self._event_target_subjects(sms, [("phone_id", "PHONE"), ("sender", "PHONE")])
            receivers = self._event_target_subjects(sms, [("receiver", "PHONE")])
            for sid in senders:
                self._append_event(self._subjects[sid], "sms", sms, "OUTGOING")
            for sid in receivers - senders:
                self._append_event(self._subjects[sid], "sms", sms, "INCOMING")

        # SIM events.
        for ev in self._records.get("sim_events", []):
            # Resolve a SIM event by the affected phone first. Shared IMEI/IMSI
            # values are evidence, but are not sufficient on their own to assign
            # the event to every person who has ever been observed with the device.
            targets = self._event_target_subjects(ev, [("phone_id", "PHONE")])
            for sid in targets:
                profile = self._subjects[sid]
                self._append_event(profile, "sim_events", ev, "RELATED")
                for key in ("new_imsi", "old_imsi"):
                    self._add_unique(profile["identifiers"]["imsis"], ev.get(key))
                for key in ("new_imei", "old_imei"):
                    self._add_unique(profile["identifiers"]["observed_imeis"], ev.get(key))

        # Explicit normalized sim entities can be represented as timeline events too.
        for sim in self._records.get("sims", []):
            pid = str(sim.get("person_id") or "")
            if pid in self._subjects:
                self._append_event(self._subjects[pid], "sim_events", sim, "RELATED")

        # Dynamic web collections: support normalized web_activity and compatible names.
        for topic in self.WEB_TOPICS:
            for web in self._records.get(topic, []):
                targets = set()
                targets |= self._event_target_subjects(web, [("person_id", "PERSON"), ("phone_id", "PHONE"), ("device_id", "DEVICE"), ("ip_id", "IP")])
                for sid in targets:
                    self._append_event(self._subjects[sid], "web_activity", web, "RELATED")

    # ------------------------------------------------------------------
    # FINALIZE / STATISTICS / RELATIONSHIPS
    # ------------------------------------------------------------------
    def _finalize_profiles(self) -> List[Dict[str, Any]]:
        profiles = []
        for sid, profile in self._subjects.items():
            # Deduplicate evidence and timeline.
            profile["identity_evidence"] = sorted(set(profile["identity_evidence"]))
            profile["evidence_ids"] = sorted({
                eid
                for event in profile["timeline"]
                for eid in event.get("evidence_ids", [])
            } | set(profile["identity_evidence"]))
            profile["timeline"].sort(key=self._sort_key, reverse=True)
            for topic in ("transactions", "calls", "sms", "web_activity", "sim_events"):
                profile[topic].sort(key=self._sort_key, reverse=True)

            accounts = set(profile["identifiers"]["account_ids"]) or set(profile["identifiers"]["account_numbers"])
            phones = set(profile["identifiers"]["phone_ids"]) or set(profile["identifiers"]["phone_numbers"])
            devices = set(profile["identifiers"]["device_ids"]) or set(profile["identifiers"]["imeis"])

            st = profile["statistics"]
            st["transactions_count"] = len(profile["transactions"])
            st["calls_count"] = len(profile["calls"])
            st["sms_count"] = len(profile["sms"])
            st["web_activity_count"] = len(profile["web_activity"])
            st["sim_events_count"] = len(profile["sim_events"])
            st["devices_count"] = len(devices)
            st["accounts_count"] = len(accounts)
            st["phones_count"] = len(phones)

            counterparties = set()
            for event in profile["transactions"]:
                d = event["details"]
                if event["direction"] == "OUTGOING":
                    counterparties.add(str(d.get("receiver_account_id") or ""))
                    st["money_out_inr"] += self._amount(d.get("amount"))
                elif event["direction"] == "INCOMING":
                    counterparties.add(str(d.get("sender_account_id") or ""))
                    st["money_in_inr"] += self._amount(d.get("amount"))
            for event in profile["calls"]:
                d = event["details"]
                counterparties.add(str(d.get("caller_phone_id") or ""))
                counterparties.add(str(d.get("receiver_phone_id") or ""))
                st["call_duration_seconds"] += int(float(d.get("duration_seconds") or 0))
            counterparties.discard("")
            st["unique_counterparties"] = len(counterparties)
            st["money_in_inr"] = round(st["money_in_inr"], 2)
            st["money_out_inr"] = round(st["money_out_inr"], 2)

            # Build person-level relationship summary.
            rel_counter = Counter()
            rel_evidence = defaultdict(set)
            for txn_event in profile["transactions"]:
                d = txn_event["details"]
                other_account = d.get("receiver_account_id") if txn_event["direction"] == "OUTGOING" else d.get("sender_account_id")
                targets = self._subjects_for_entity("ACCOUNT", other_account)
                for other in targets:
                    if other == sid:
                        continue
                    rel_counter["TRANSFERRED_TO" if txn_event["direction"] == "OUTGOING" else "RECEIVED_FROM"] += 1
                    rel_evidence[(other, "TRANSFERRED_TO" if txn_event["direction"] == "OUTGOING" else "RECEIVED_FROM")].update(txn_event["evidence_ids"])
            for call_event in profile["calls"]:
                d = call_event["details"]
                other_values = [d.get("receiver_phone_id")] if call_event["direction"] == "OUTGOING" else [d.get("caller_phone_id")]
                for phone in other_values:
                    for other in self._subjects_for_entity("PHONE", phone):
                        if other == sid:
                            continue
                        rel_counter["CALLED"] += 1
                        rel_evidence[(other, "CALLED")].update(call_event["evidence_ids"])
            profile["relationships"] = [
                {
                    "target_subject_id": other,
                    "relationship_type": rtype,
                    "event_count": count,
                    "evidence_ids": sorted(rel_evidence[(other, rtype)]),
                }
                for (other, rtype), count in sorted(
                    self._relationship_counts(profile, sid).items(),
                    key=lambda kv: (-kv[1], kv[0][0], kv[0][1]),
                )
            ]
            # Keep existing role as ground truth from source data; hypotheses are added separately.
            profiles.append(profile)

        profiles.sort(key=lambda p: (p.get("name") or p.get("subject_id")))
        return profiles

    def _relationship_counts(self, profile: Dict[str, Any], sid: str) -> Counter:
        counts = Counter()
        for event in profile["transactions"]:
            d = event["details"]
            value = d.get("receiver_account_id") if event["direction"] == "OUTGOING" else d.get("sender_account_id")
            for other in self._subjects_for_entity("ACCOUNT", value):
                if other != sid:
                    counts[(other, "TRANSFERRED_TO" if event["direction"] == "OUTGOING" else "RECEIVED_FROM")] += 1
        for event in profile["calls"]:
            d = event["details"]
            value = d.get("receiver_phone_id") if event["direction"] == "OUTGOING" else d.get("caller_phone_id")
            for other in self._subjects_for_entity("PHONE", value):
                if other != sid:
                    counts[(other, "CALLED")] += 1
        return counts

    # ------------------------------------------------------------------
    # PATTERN DETECTION
    # ------------------------------------------------------------------
    def _profile_txn_events(self, profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        return profile["transactions"]

    def _detect_patterns(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        findings.extend(self._detect_rapid_fanout(profiles))
        findings.extend(self._detect_rapid_fanin(profiles))
        findings.extend(self._detect_shared_devices(profiles))
        findings.extend(self._detect_shared_ips(profiles))
        findings.extend(self._detect_sim_swap(profiles))
        findings.extend(self._detect_cycles(profiles))
        self._assign_role_hypotheses(profiles, findings)
        return sorted(findings, key=lambda x: (-float(x.get("confidence", 0)), x.get("subject_id", ""), x.get("pattern_type", "")))

    def _make_finding(self, pattern_type: str, subject_id: str, confidence: float, summary: str, evidence_ids: Iterable[str], details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "finding_id": "FIND-" + sha256(f"{pattern_type}|{subject_id}|{summary}".encode()).hexdigest()[:12],
            "pattern_type": pattern_type,
            "subject_id": subject_id,
            "confidence": round(max(0.0, min(1.0, confidence)), 3),
            "summary": summary,
            "evidence_ids": sorted(set(str(x) for x in evidence_ids if x)),
            "details": details,
        }

    def _detect_rapid_fanout(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for p in profiles:
            incoming = [e for e in p["transactions"] if e["direction"] == "INCOMING"]
            outgoing = [e for e in p["transactions"] if e["direction"] == "OUTGOING"]
            for inc in incoming:
                t0 = self._timestamp(inc["timestamp"])
                if not t0:
                    continue
                outs = [e for e in outgoing if self._timestamp(e["timestamp"]) and 0 <= (self._timestamp(e["timestamp"]) - t0).total_seconds() <= 30 * 60]
                if len(outs) < 2:
                    continue
                recipients = {str(e["details"].get("receiver_account_id")) for e in outs}
                evidence = inc["evidence_ids"] + [x for e in outs for x in e["evidence_ids"]]
                amount_in = self._amount(inc["details"].get("amount"))
                amount_out = sum(self._amount(e["details"].get("amount")) for e in outs)
                confidence = 0.75 + min(0.2, 0.04 * len(recipients))
                findings.append(self._make_finding(
                    "RAPID_FAN_OUT", p["subject_id"], confidence,
                    f"Inbound transfer followed by {len(outs)} outgoing transfers within 30 minutes",
                    evidence,
                    {"inbound_amount_inr": amount_in, "outbound_amount_inr": amount_out, "recipient_count": len(recipients), "window_minutes": 30},
                ))
        return findings

    def _detect_rapid_fanin(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for p in profiles:
            incoming = [e for e in p["transactions"] if e["direction"] == "INCOMING"]
            if len(incoming) < 3:
                continue
            clusters = []
            for anchor in incoming:
                t0 = self._timestamp(anchor["timestamp"])
                if not t0:
                    continue
                cluster = [e for e in incoming if self._timestamp(e["timestamp"]) and 0 <= (self._timestamp(e["timestamp"]) - t0).total_seconds() <= 30 * 60]
                if len(cluster) >= 3:
                    senders = {str(e["details"].get("sender_account_id")) for e in cluster}
                    if len(senders) >= 3:
                        clusters.append((cluster, senders))
                        break
            if clusters:
                cluster, senders = clusters[0]
                findings.append(self._make_finding(
                    "RAPID_FAN_IN", p["subject_id"], 0.82,
                    f"Funds received from {len(senders)} distinct accounts within 30 minutes",
                    [x for e in cluster for x in e["evidence_ids"]],
                    {"sender_count": len(senders), "transaction_count": len(cluster), "window_minutes": 30},
                ))
        return findings

    def _detect_shared_devices(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        device_to_subjects = defaultdict(set)
        for p in profiles:
            for did in p["identifiers"]["device_ids"]:
                device_to_subjects[str(did)].add(p["subject_id"])
        findings = []
        for device, subjects in device_to_subjects.items():
            if len(subjects) < 2:
                continue
            evidence = []
            for p in profiles:
                if p["subject_id"] in subjects:
                    evidence.extend(p["identity_evidence"])
            for sid in sorted(subjects):
                findings.append(self._make_finding(
                    "SHARED_DEVICE", sid, min(0.95, 0.78 + 0.05 * len(subjects)),
                    f"Device/IMEI {device} is associated with {len(subjects)} subjects",
                    evidence,
                    {"device_or_imei": device, "subject_count": len(subjects), "subjects": sorted(subjects)},
                ))
        return findings

    def _detect_shared_ips(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ip_to_subjects = defaultdict(set)
        for p in profiles:
            for ip in p["identifiers"]["ip_addresses"] + p["identifiers"]["ip_ids"]:
                ip_to_subjects[str(ip)].add(p["subject_id"])
        findings = []
        for ip, subjects in ip_to_subjects.items():
            if len(subjects) < 2:
                continue
            evidence = []
            for p in profiles:
                if p["subject_id"] in subjects:
                    evidence.extend(p["identity_evidence"])
            for sid in sorted(subjects):
                findings.append(self._make_finding(
                    "SHARED_IP", sid, min(0.9, 0.7 + 0.05 * len(subjects)),
                    f"IP address {ip} is associated with {len(subjects)} subjects",
                    evidence,
                    {"ip": ip, "subject_count": len(subjects), "subjects": sorted(subjects)},
                ))
        return findings

    def _detect_sim_swap(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for p in profiles:
            for event in p["sim_events"]:
                ev = event["details"]
                event_type = str(ev.get("event_type") or "").upper()
                if "SWAP" not in event_type:
                    continue
                t0 = self._timestamp(event["timestamp"])
                nearby_tx = []
                if t0:
                    for tx in p["transactions"]:
                        tt = self._timestamp(tx["timestamp"])
                        if tt and 0 <= (tt - t0).total_seconds() <= 24 * 3600:
                            nearby_tx.append(tx)
                evidence = event["evidence_ids"] + [x for tx in nearby_tx for x in tx["evidence_ids"]]
                findings.append(self._make_finding(
                    "SIM_SWAP_PRECEDES_TRANSACTION", p["subject_id"],
                    0.93 if nearby_tx else 0.8,
                    "SIM-swap event detected" + (" before one or more transactions within 24 hours" if nearby_tx else ""),
                    evidence,
                    {"sim_event": deepcopy(ev), "transaction_count_within_24h": len(nearby_tx)},
                ))
        return findings

    def _detect_cycles(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        graph = defaultdict(set)
        for p in profiles:
            for rel in p["relationships"]:
                if rel["relationship_type"] == "TRANSFERRED_TO":
                    graph[p["subject_id"]].add(rel["target_subject_id"])
        findings = []
        # Small bounded DFS. Hackathon-scale evidence is enough; avoids external dependency.
        for start in graph:
            stack = [(start, [start])]
            seen = set()
            while stack:
                node, path = stack.pop()
                if len(path) > 6:
                    continue
                for nxt in graph.get(node, set()):
                    if nxt == start and len(path) >= 3:
                        findings.append(self._make_finding(
                            "CIRCULAR_MONEY_FLOW", start, 0.86,
                            f"Transfer path forms a cycle of length {len(path)}",
                            [],
                            {"cycle": path},
                        ))
                        stack = []
                        break
                    state = (nxt, tuple(path))
                    if state not in seen:
                        seen.add(state)
                        if nxt not in path:
                            stack.append((nxt, path + [nxt]))
                if findings and findings[-1]["subject_id"] == start and findings[-1]["pattern_type"] == "CIRCULAR_MONEY_FLOW":
                    break
        # Deduplicate cycle findings.
        unique = {}
        for f in findings:
            unique[(f["subject_id"], str(f["details"].get("cycle")))] = f
        return list(unique.values())

    def _assign_role_hypotheses(self, profiles: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> None:
        by_subject = defaultdict(list)
        for f in findings:
            by_subject[f["subject_id"]].append(f)
        for p in profiles:
            existing = str(p.get("role") or "").upper()
            hypotheses = []
            ftypes = {f["pattern_type"] for f in by_subject.get(p["subject_id"], [])}
            if "RAPID_FAN_OUT" in ftypes and p["statistics"]["money_out_inr"] > 0:
                hypotheses.append({
                    "role": "MULE",
                    "confidence": 0.87,
                    "reasons": ["Rapid fan-out of received funds", "Multiple downstream transaction counterparties"],
                })
            transfer_edges = sum(1 for r in p["relationships"] if r["relationship_type"] in {"TRANSFERRED_TO", "RECEIVED_FROM"})
            if (transfer_edges >= 3 and p["statistics"]["money_out_inr"] >= 50000) or ("SHARED_DEVICE" in ftypes and transfer_edges >= 2):
                hypotheses.append({
                    "role": "COORDINATOR_CANDIDATE",
                    "confidence": 0.66,
                    "reasons": ["Multiple transaction relationships with significant outgoing value or shared infrastructure"],
                })
            if "SIM_SWAP_PRECEDES_TRANSACTION" in ftypes:
                hypotheses.append({
                    "role": "SIM_SWAP_ASSOCIATED",
                    "confidence": 0.9,
                    "reasons": ["SIM-swap event is linked to this subject's identifiers"],
                })
            merged = []
            if existing:
                merged.append({"role": existing, "confidence": 1.0, "reasons": ["Source-record role"]})
            seen_roles = {existing} if existing else set()
            for hypothesis in hypotheses:
                if hypothesis["role"] in seen_roles:
                    continue
                merged.append(hypothesis)
                seen_roles.add(hypothesis["role"])
            p["role_hypotheses"] = merged

    # ------------------------------------------------------------------
    # NETWORK / CASE BRIEF
    # ------------------------------------------------------------------
    def _build_network(self, profiles: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        edges = []
        subject_index = {p["subject_id"]: p for p in profiles}
        finding_types = defaultdict(set)
        for f in findings:
            finding_types[f["subject_id"]].add(f["pattern_type"])

        for p in profiles:
            nodes.append({
                "id": p["subject_id"],
                "type": p["subject_type"],
                "label": p["name"] or p["subject_id"],
                "role": p["role"],
                "role_hypotheses": [x["role"] for x in p["role_hypotheses"]],
                "finding_types": sorted(finding_types[p["subject_id"]]),
            })
        seen = set()
        for p in profiles:
            for rel in p["relationships"]:
                src = p["subject_id"]
                dst = rel["target_subject_id"]
                if dst not in subject_index:
                    continue
                edge_key = (src, dst, rel["relationship_type"])
                if edge_key in seen:
                    continue
                seen.add(edge_key)
                edges.append({
                    "source": src,
                    "target": dst,
                    "relationship_type": rel["relationship_type"],
                    "event_count": rel["event_count"],
                    "evidence_ids": rel["evidence_ids"],
                })
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def _build_entity_network(self) -> Dict[str, Any]:
        """Return the evidence/entity graph before collapsing it to people."""
        nodes: Dict[Tuple[str, str], Dict[str, Any]] = {}
        edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        def add_node(entity_type: str, value: Any, label: str = ""):
            if value in (None, ""):
                return
            key = (entity_type.upper(), str(value))
            nodes.setdefault(key, {
                "id": str(value),
                "type": entity_type.upper(),
                "label": label or str(value),
            })

        def add_edge(src_type: str, src: Any, relation: str, dst_type: str, dst: Any, evidence_ids: Iterable[str] = ()):
            if src in (None, "") or dst in (None, ""):
                return
            add_node(src_type, src)
            add_node(dst_type, dst)
            key = (str(src), relation, str(dst))
            edge = edges.setdefault(key, {
                "source": str(src),
                "source_type": src_type.upper(),
                "target": str(dst),
                "target_type": dst_type.upper(),
                "relationship_type": relation,
                "event_count": 0,
                "evidence_ids": [],
            })
            edge["event_count"] += 1
            for eid in evidence_ids:
                self._add_unique(edge["evidence_ids"], eid)

        # Canonical entity relationships from the normalizer.
        for rel in self.case.get("relationships", []):
            add_edge(rel.get("source_type", "ENTITY"), rel.get("source_id"), rel.get("relationship_type", "RELATED_TO"), rel.get("target_type", "ENTITY"), rel.get("target_id"), rel.get("source_evidence_ids", []))

        # Ownership/use edges reconstructed directly from normalized entity records.
        for person in self._records.get("persons", []):
            pid = person.get("person_id")
            if not pid:
                continue
            add_node("PERSON", pid, person.get("name") or pid)
            if person.get("account_number"):
                add_edge("PERSON", pid, "OWNS", "ACCOUNT", person.get("account_number"), self._evidence_ids(person))
            if person.get("phone_number"):
                add_edge("PERSON", pid, "USES", "PHONE", self._clean_phone(person.get("phone_number")), self._evidence_ids(person))
        for device in self._records.get("devices", []):
            did = device.get("device_id")
            for pid in self._as_list(device.get("person_ids")) + self._as_list(device.get("person_id")):
                add_edge("PERSON", pid, "USES", "DEVICE", did, self._evidence_ids(device))
            if device.get("imei"):
                add_edge("DEVICE", did or device.get("imei"), "IDENTIFIED_BY", "IMEI", device.get("imei"), self._evidence_ids(device))
            if device.get("ip_address"):
                add_edge("DEVICE", did or device.get("imei"), "OBSERVED_FROM", "IP", device.get("ip_address"), self._evidence_ids(device))
        for txn in self._records.get("transactions", []):
            add_edge("ACCOUNT", txn.get("sender_account_id"), "TRANSFERRED_TO", "ACCOUNT", txn.get("receiver_account_id"), self._evidence_ids(txn))
        for call in self._records.get("calls", []):
            add_edge("PHONE", call.get("caller_phone_id"), "CALLED", "PHONE", call.get("receiver_phone_id"), self._evidence_ids(call))
        for ev in self._records.get("sim_events", []):
            phone = ev.get("phone_id")
            sim_value = ev.get("new_imsi") or ev.get("old_imsi")
            if phone and sim_value:
                add_edge("PHONE", phone, str(ev.get("event_type") or "SIM_EVENT"), "IMSI", sim_value, self._evidence_ids(ev))

        edge_list = sorted(edges.values(), key=lambda x: (-x["event_count"], x["relationship_type"], x["source"], x["target"]))
        return {
            "nodes": list(nodes.values()),
            "edges": edge_list,
            "node_count": len(nodes),
            "edge_count": len(edge_list),
        }

    def _build_case_brief(self, profiles: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        case = deepcopy(self.case.get("case", {}))
        chronology = []
        all_events = []
        for p in profiles:
            for event in p["timeline"]:
                all_events.append((self._timestamp(event["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc), p["subject_id"], event))
        all_events.sort(key=lambda x: x[0], reverse=True)
        for _, sid, event in all_events[:50]:
            chronology.append({
                "subject_id": sid,
                "timestamp": event["timestamp"],
                "event_type": event["type"],
                "direction": event["direction"],
                "details": event["details"],
                "evidence_ids": event["evidence_ids"],
            })
        suspect_candidates = []
        for p in profiles:
            role = (p.get("role") or "").upper()
            hypotheses = {h["role"] for h in p.get("role_hypotheses", [])}
            if role in {"SUSPECT", "MULE", "KINGPIN", "ACCUSED"} or hypotheses & {"MULE", "COORDINATOR_CANDIDATE", "SIM_SWAP_ASSOCIATED"}:
                suspect_candidates.append({
                    "subject_id": p["subject_id"],
                    "name": p["name"],
                    "role": p["role"],
                    "role_hypotheses": p["role_hypotheses"],
                    "key_evidence_ids": p["identity_evidence"][:20],
                })
        recommended_actions = [
            "Preserve and correlate the source evidence referenced by each finding before taking enforcement action.",
            "Validate account ownership, SIM ownership, device custody, and telecom records against the original source records.",
        ]
        if any(f["pattern_type"] == "SIM_SWAP_PRECEDES_TRANSACTION" for f in findings):
            recommended_actions.append("Obtain telecom subscriber/SIM-change records around each detected SIM-swap event and correlate them to subsequent financial activity.")
        if any(f["pattern_type"] in {"RAPID_FAN_OUT", "RAPID_FAN_IN", "CIRCULAR_MONEY_FLOW"} for f in findings):
            recommended_actions.append("Trace the complete transaction chain and preserve the linked transaction/evidence identifiers for each hop.")
        if any(f["pattern_type"] == "SHARED_DEVICE" for f in findings):
            recommended_actions.append("Validate device/IMEI association history and determine whether device sharing is documented, legitimate, or unexplained.")
        return {
            "case_metadata": case,
            "summary": {
                "subject_count": len(profiles),
                "finding_count": len(findings),
                "pattern_types": sorted({f["pattern_type"] for f in findings}),
                "total_transaction_amount_inr": round(sum(self._amount(e["details"].get("amount")) for p in profiles for e in p["transactions"] if e["direction"] == "OUTGOING"), 2),
            },
            "subject_candidates": suspect_candidates,
            "chronology": chronology,
            "findings": findings,
            "recommended_actions": recommended_actions,
        }

    def _unresolved_entities(self) -> List[Dict[str, Any]]:
        unresolved = []
        for txn in self._records.get("transactions", []):
            for field, value in (("sender_account_id", txn.get("sender_account_id")), ("receiver_account_id", txn.get("receiver_account_id"))):
                if value not in (None, "") and not self._subjects_for_entity("ACCOUNT", value):
                    unresolved.append({"entity_type": "ACCOUNT", "value": str(value), "source_field": field, "evidence_ids": self._evidence_ids(txn)})
        # Deduplicate.
        seen = set()
        result = []
        for item in unresolved:
            key = (item["entity_type"], item["value"])
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result


def analyze_case(case: Dict[str, Any]) -> Dict[str, Any]:
    return AnalyzerEngine(case).analyze()


def load_and_analyze(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        case = json.load(handle)
    return analyze_case(case)
