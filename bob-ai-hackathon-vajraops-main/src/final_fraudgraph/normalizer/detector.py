import re
from collections import defaultdict

from .aliases import ALIASES, TOPIC_ALIASES
from .cleaner import clean_column_name


def similarity(a, b):

    a = clean_column_name(a)
    b = clean_column_name(b)

    if a == b:
        return 1.0

    if a in b or b in a:
        return 0.85

    a_tokens = set(a.split("_"))
    b_tokens = set(b.split("_"))

    if not a_tokens or not b_tokens:
        return 0

    intersection = len(
        a_tokens & b_tokens
    )

    union = len(
        a_tokens | b_tokens
    )

    return intersection / union


def detect_topic(columns):

    scores = defaultdict(float)

    normalized_columns = [
        clean_column_name(c)
        for c in columns
    ]

    for topic, aliases in TOPIC_ALIASES.items():

        for column in normalized_columns:

            for alias in aliases:

                score = similarity(
                    column,
                    alias,
                )

                scores[topic] += score

    if not scores:

        return "unknown", 0.0

    topic = max(
        scores,
        key=scores.get,
    )

    # Normalize approximately by number of columns

    confidence = scores[topic] / max(
        len(columns),
        1,
    )

    confidence = min(
        confidence,
        1.0,
    )

    return topic, confidence


def map_fields(
    topic,
    columns,
):

    mappings = {}

    unmapped = []

    topic_aliases = ALIASES.get(
        topic,
        {},
    )

    for column in columns:

        normalized_column = clean_column_name(column)

        # Exact canonical field names always win over fuzzy aliases.
        if normalized_column in topic_aliases:
            mappings[column] = {
                "field": normalized_column,
                "confidence": 1.0,
            }
            continue

        best_field = None
        best_score = 0

        for field, aliases in topic_aliases.items():

            for alias in aliases:

                score = similarity(
                    normalized_column,
                    alias,
                )

                if score > best_score:

                    best_score = score
                    best_field = field

        if best_field and best_score >= 0.60:

            mappings[column] = {
                "field": best_field,
                "confidence": round(
                    best_score,
                    3,
                ),
            }

        else:

            unmapped.append(
                column
            )

    return mappings, unmapped
