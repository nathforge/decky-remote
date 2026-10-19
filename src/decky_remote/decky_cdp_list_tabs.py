from typing import Any


def decky_cdp_list_tabs(cdp_url: str = "http://localhost:8080") -> list[dict[str, "Any"]]:
    """
    List CEF tabs currently open, via the Chrome DevTools Protocol's /json
    endpoint.

    This function can be sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import json
    from urllib.request import urlopen

    res = urlopen(f"{cdp_url}/json")
    if res.status != 200:
        raise Exception(f"Unexpected HTTP {res.status} from {cdp_url}/json")
    return json.loads(res.read().decode())
