import io
import json
from pathlib import Path

import pandas as pd

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


def read_csv(file_bytes):

    return pd.read_csv(
        io.BytesIO(file_bytes),
        dtype=str,
    )


def read_excel(file_bytes):

    return pd.read_excel(
        io.BytesIO(file_bytes),
        dtype=str,
    )


def read_json(file_bytes):

    data = json.loads(
        file_bytes.decode(
            "utf-8",
            errors="ignore",
        )
    )

    if isinstance(data, list):

        return pd.DataFrame(data)

    if isinstance(data, dict):

        # Common structure:
        #
        # {
        #   "transactions": [...]
        # }

        list_values = [
            value
            for value in data.values()
            if isinstance(value, list)
        ]

        if len(list_values) == 1:

            return pd.DataFrame(
                list_values[0]
            )

        return pd.DataFrame(
            [data]
        )

    return pd.DataFrame()


def read_text(file_bytes):

    text = file_bytes.decode(
        "utf-8",
        errors="ignore",
    )

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    # Try CSV-like text

    if lines and "," in lines[0]:

        try:

            return pd.read_csv(
                io.StringIO(text),
                dtype=str,
            )

        except Exception:
            pass

    # Generic text becomes one-column data

    return pd.DataFrame(
        {
            "raw_text": lines
        }
    )


def read_pdf(file_bytes):

    if PdfReader is None:

        raise RuntimeError(
            "pypdf is required for PDF processing."
        )

    reader = PdfReader(
        io.BytesIO(file_bytes)
    )

    pages = []

    for page in reader.pages:

        text = page.extract_text() or ""

        pages.append(text)

    return pd.DataFrame(
        {
            "raw_text": pages
        }
    )


def read_file(filename, file_bytes):

    extension = Path(
        filename
    ).suffix.lower()

    if extension == ".csv":
        return read_csv(file_bytes)

    if extension in [".xlsx", ".xls"]:
        return read_excel(file_bytes)

    if extension == ".json":
        return read_json(file_bytes)

    if extension == ".txt":
        return read_text(file_bytes)

    if extension == ".pdf":
        return read_pdf(file_bytes)

    raise ValueError(
        f"Unsupported file type: {extension}"
    )
