"""``urlopen`` for the command-line tools (replay, note, demo, evaluations, download).

The target URLs come from environment variables such as ``API_URL``. ``urllib`` would also open
``file:`` or ``ftp:`` URLs, so a mistyped or manipulated variable could read local files: only
http and https are accepted.
"""

import urllib.request
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")


def urlopen(url: str | urllib.request.Request, timeout: float):
    full_url = url.full_url if isinstance(url, urllib.request.Request) else url
    if urlsplit(full_url).scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"only http(s) URLs are allowed, got {full_url!r}")
    return urllib.request.urlopen(url, timeout=timeout)  # noqa: S310 - scheme checked above
