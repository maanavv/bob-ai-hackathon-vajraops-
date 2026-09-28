import re
from datetime import datetime

import pandas as pd
from dateutil import parser


def clean_column_name(name):

    name = str(name).strip().lower()

    name = re.sub(
        r"[^a-z0-9]+",
        "_",
        name,
    )

    return name.strip("_")


def clean_string(value):

    if value is None:
        return ""

    if pd.isna(value):
        return ""

    value = str(value).strip()

    return value


def clean_phone(value):

    value = clean_string(value)

    if not value:
        return ""

    digits = re.sub(
        r"\D",
        "",
        value,
    )

    # Preserve Indian numbers in normalized form

    if len(digits) == 12 and digits.startswith("91"):

        return "+" + digits

    if len(digits) == 10:

        return "+91" + digits

    return digits


def clean_imei(value):

    value = clean_string(value)

    return re.sub(
        r"\D",
        "",
        value,
    )


def clean_ifsc(value):

    return clean_string(
        value
    ).upper()


def clean_upi(value):

    return clean_string(
        value
    ).lower()


def clean_amount(value):

    if value is None:
        return None

    value = clean_string(
        value
    )

    if not value:
        return None

    value = value.replace(
        ",",
        "",
    )

    value = re.sub(
        r"[₹$€£]",
        "",
        value,
    )

    value = re.sub(
        r"[^\d.\-]",
        "",
        value,
    )

    try:

        return float(value)

    except ValueError:

        return None


def clean_timestamp(value):

    value = clean_string(
        value
    )

    if not value:
        return ""

    try:

        # ISO-8601 / year-first input must remain year-first.
        # Legacy day-first parsing is used only for clearly non-ISO dates.
        iso_like = bool(re.match(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}", value))
        parsed = parser.parse(
            value,
            dayfirst=not iso_like,
        )

        return parsed.isoformat()

    except Exception:

        return value


def clean_ip(value):

    value = clean_string(
        value
    )

    return value


def clean_value(field, value):

    if field in [
        "phone_number",
        "msisdn",
    ]:

        return clean_phone(
            value
        )

    if field == "imei":

        return clean_imei(
            value
        )

    if field == "ifsc":

        return clean_ifsc(
            value
        )

    if field in [
        "upi_id",
        "vpa",
        "sender_upi_id",
        "receiver_upi_id",
    ]:

        return clean_upi(
            value
        )

    if field in [
        "amount",
        "reported_loss_inr",
        "balance",
        "accuracy",
        "latitude",
        "longitude",
    ]:

        return clean_amount(
            value
        )

    if field in [
        "timestamp",
        "first_seen",
        "last_seen",
        "activation_time",
        "deactivation_time",
        "opening_date",
        "statement_date",
    ]:

        return clean_timestamp(
            value
        )

    return clean_string(
        value
    )
