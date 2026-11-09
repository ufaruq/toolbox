#!/usr/bin/env python3
"""Print a prefilled GitHub registration URL; never reads credentials."""
import json
from pathlib import Path
from urllib.parse import urlencode


def registration_url():
    settings = json.loads(Path(__file__).with_name("registration.json").read_text())
    return "https://github.com/settings/apps/new?" + urlencode(settings)


if __name__ == "__main__":
    print(registration_url())
