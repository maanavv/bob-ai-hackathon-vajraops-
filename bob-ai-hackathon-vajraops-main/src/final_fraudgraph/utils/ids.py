import re


def safe_case_id(case_id):

    case_id = str(
        case_id
    ).strip()

    case_id = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        case_id,
    )

    return case_id
