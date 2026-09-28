import re

from .cleaner import (
    clean_amount,
    clean_phone,
    clean_upi,
)


def validate_phone(value):

    value = clean_phone(value)

    if not value:
        return False

    digits = re.sub(
        r"\D",
        "",
        value,
    )

    return 10 <= len(digits) <= 15


def validate_imei(value):

    if not value:
        return False

    digits = re.sub(
        r"\D",
        "",
        str(value),
    )

    return len(digits) in [
        14,
        15,
    ]


def validate_upi(value):

    if not value:
        return False

    return bool(
        re.match(
            r"^[^@\s]+@[^@\s]+$",
            str(value),
        )
    )


def validate_amount(value):

    return (
        clean_amount(value)
        is not None
    )


def validate_ifsc(value):

    if not value:
        return False

    return bool(
        re.match(
            r"^[A-Z]{4}0[A-Z0-9]{6}$",
            str(value).upper(),
        )
    )


def validate_field(
    field,
    value,
):

    if not value:
        return True

    if field in [
        "phone_number",
        "msisdn",
    ]:

        return validate_phone(
            value
        )

    if field == "imei":

        return validate_imei(
            value
        )

    if field in [
        "vpa",
        "upi_id",
        "sender_upi_id",
        "receiver_upi_id",
    ]:

        return validate_upi(
            value
        )

    if field in [
        "amount",
        "balance",
    ]:

        return validate_amount(
            value
        )

    if field == "ifsc":

        return validate_ifsc(
            value
        )

    return True
