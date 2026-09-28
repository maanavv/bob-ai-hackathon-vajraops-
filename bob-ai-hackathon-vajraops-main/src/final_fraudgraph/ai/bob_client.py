from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


# IBM Bob inference API
DEFAULT_BASE_URL = "https://api.us-east.bob.ibm.com/inference/v1"

# Change this only if your Bob account provides a different model name.
DEFAULT_MODEL = "premium"


class BobAPIError(RuntimeError):
    pass


class BobClient:
    """
    Lightweight IBM Bob inference client.

    Reads the API key from:
        BOB_API_KEY
    or:
        BOBSHELL_API_KEY

    For General API keys, optionally set:
        BOB_TEAM_ID

    The API key is never written to output files.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        team_id: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 90,
    ) -> None:

        self.api_key = (
            api_key
            or os.getenv("BOB_API_KEY")
            or os.getenv("BOBSHELL_API_KEY")
            or ""
        ).strip()

        self.team_id = (
            team_id
            or os.getenv("BOB_TEAM_ID")
            or ""
        ).strip()

        self.base_url = (
            base_url
            or os.getenv("BOB_API_BASE_URL")
            or DEFAULT_BASE_URL
        ).rstrip("/")

        self.model = (
            model
            or os.getenv("BOB_MODEL")
            or DEFAULT_MODEL
        ).strip()

        self.timeout = timeout

    @property
    def configured(self) -> bool:
        """Return True when an API key is available."""
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        """
        Build authentication headers for IBM Bob.

        IMPORTANT:
        Bob inference uses:
            Authorization: Apikey <API_KEY>

        NOT:
            Authorization: Bearer <API_KEY>
        """

        if not self.api_key:
            raise BobAPIError(
                "IBM Bob API key is not configured. "
                "Set BOB_API_KEY before running the application."
            )

        headers = {
            "Authorization": f"Apikey {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Only send team ID when explicitly configured.
        # This is useful for General API keys.
        if self.team_id:
            headers["x-team-id"] = self.team_id

        return headers

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 2500,
    ) -> Dict[str, Any]:

        url = f"{self.base_url}/chat/completions"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }

        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                raw = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise BobAPIError(
                f"Bob inference HTTP {exc.code}: {detail[:2000]}"
            ) from exc

        except urllib.error.URLError as exc:
            raise BobAPIError(
                f"Could not reach IBM Bob: {exc.reason}"
            ) from exc

        except TimeoutError as exc:
            raise BobAPIError(
                "IBM Bob inference timed out."
            ) from exc

        try:
            return json.loads(raw)

        except json.JSONDecodeError as exc:
            raise BobAPIError(
                "IBM Bob returned a non-JSON response."
            ) from exc

    def chat_text(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 2500,
    ) -> str:

        data = self.chat(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        try:
            return str(
                data["choices"][0]["message"]["content"]
            )

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as exc:

            raise BobAPIError(
                "Unexpected Bob response shape: "
                + json.dumps(data)[:2000]
            ) from exc
