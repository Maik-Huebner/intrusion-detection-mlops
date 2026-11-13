"""Download the raw dataset and verify its SHA-256 checksum.

The archive (328 MB) is not stored in Git. Locally DVC tracks it (``data/raw/*.dvc``); a fresh clone
or a CI runner fetches it from the original source with this script. The checksum guarantees that
everyone trains on exactly the same bytes.

Usage::

    uv run python -m ids.data.download
"""

import hashlib
import sys
import urllib.request
from pathlib import Path

from ids.config import RAW_ARCHIVE

URL = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
SHA256 = "97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883"
CHUNK = 1 << 20


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "intrusion-detection-mlops"})
    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as fh:
        total = int(response.headers.get("Content-Length", 0))
        done = 0
        while block := response.read(CHUNK):
            fh.write(block)
            done += len(block)
            if total:
                print(f"\r  {done / 1e6:7.1f} / {total / 1e6:.1f} MB", end="", flush=True)
    print()
    partial.replace(target)  # atomic: the target never exists half-written


def main() -> None:
    if RAW_ARCHIVE.exists() and sha256sum(RAW_ARCHIVE) == SHA256:
        print(f"Raw data already present and verified: {RAW_ARCHIVE}")
        return

    print(f"Downloading {URL}")
    download(URL, RAW_ARCHIVE)

    actual = sha256sum(RAW_ARCHIVE)
    if actual != SHA256:
        sys.exit(f"Checksum mismatch for {RAW_ARCHIVE}\n  expected: {SHA256}\n  actual:   {actual}")
    print(f"Raw data downloaded and verified: {RAW_ARCHIVE}")


if __name__ == "__main__":
    main()
