from typing import Any


def decky_cdp_screenshot(tab_title: str, cdp_url: str = "http://localhost:8080") -> str:
    """
    Capture a screenshot of a CEF tab, returning base64-encoded PNG data.

    This talks directly to the Chrome DevTools Protocol, rather than through
    Decky Loader's websocket API - Decky only exposes Runtime.evaluate (via
    utilities/execute_in_tab), not Page.captureScreenshot.

    This function can be sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import asyncio
    import json
    import os
    import struct
    from typing import Any
    from urllib.parse import urlparse
    from urllib.request import urlopen

    async def request() -> str:
        tab = get_tab(tab_title)
        return await capture_screenshot(tab["webSocketDebuggerUrl"])

    def get_tab(tab_title: str) -> dict[str, Any]:
        res = urlopen(f"{cdp_url}/json")
        if res.status != 200:
            raise Exception(f"Unexpected HTTP {res.status} from {cdp_url}/json")
        tabs = json.loads(res.read().decode())
        for tab in tabs:
            if tab.get("title") == tab_title:
                return tab
        titles = [tab.get("title") for tab in tabs]
        raise Exception(f"Tab {tab_title!r} not found. Available tabs: {titles}")

    async def capture_screenshot(ws_url: str) -> str:
        parsed = urlparse(ws_url)
        host = parsed.hostname
        assert host
        port = parsed.port or 80
        path = parsed.path or "/"

        reader, writer = await asyncio.open_connection(host=host, port=port)

        try:
            await ws_handshake(reader, writer, host, path)
            req_id = 1
            await ws_send(
                writer,
                json.dumps(
                    {
                        "id": req_id,
                        "method": "Page.captureScreenshot",
                        "params": {"format": "png"},
                    }
                ),
            )
            while True:
                msg = await ws_receive(reader, writer)
                if not isinstance(msg, (str, bytes)):
                    continue
                dec_msg = json.loads(msg)
                if dec_msg.get("id") == req_id:
                    if "error" in dec_msg:
                        raise Exception(dec_msg["error"])
                    return dec_msg["result"]["data"]
                # Not our reply (CDP event notifications etc.) - keep waiting.
        finally:
            writer.close()
            await writer.wait_closed()

    async def ws_handshake(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        path: str,
    ):
        import base64

        websocket_key = base64.b64encode(os.urandom(16)).decode("utf-8")

        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )

        writer.write(handshake.encode("utf-8"))
        await writer.drain()

        response = await reader.readuntil(b"\r\n\r\n")

        header = response[:-4]  # strip the trailing \r\n\r\n
        header_lines = header.split(b"\r\n")
        _protocol, status_code, _status_text = header_lines[0].split(maxsplit=2)

        if status_code != b"101":
            raise Exception(f"Unexpected HTTP {status_code.decode()} from {path}")

    async def ws_receive(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str | bytes | None:
        b1b2 = await reader.readexactly(2)

        b1, b2 = b1b2[0], b1b2[1]
        opcode = b1 & 0x0F
        masked = (b2 >> 7) & 1
        payload_len = b2 & 0x7F

        if payload_len == 126:
            ext = await reader.readexactly(2)
            (payload_len,) = struct.unpack("!H", ext)
        elif payload_len == 127:
            ext = await reader.readexactly(8)
            (payload_len,) = struct.unpack("!Q", ext)

        mask_key = b""
        if masked:
            mask_key = await reader.readexactly(4)

        if payload_len:
            payload = await reader.readexactly(payload_len)
        else:
            payload = b""

        if masked:
            payload = bytearray(payload)
            for i in range(len(payload)):
                payload[i] ^= mask_key[i % 4]
            payload = bytes(payload)

        if opcode == 0x1:  # text
            return payload.decode("utf-8")
        elif opcode == 0x2:  # binary
            return payload
        elif opcode == 0x8:  # close
            await _ws_send_control(writer, 0x8, payload)
            return None
        elif opcode == 0x9:  # ping
            await _ws_send_control(writer, 0xA, payload)
            return None
        else:  # pong, or anything else
            return None

    async def ws_send(
        writer: asyncio.StreamWriter,
        message: str,
    ):
        payload = message.encode("utf-8")

        fin_and_opcode = 0x80 | 0x1
        mask_bit = 0x80

        length = len(payload)
        if length <= 125:
            header = struct.pack("!BB", fin_and_opcode, mask_bit | length)
        elif length <= 0xFFFF:
            header = struct.pack("!BBH", fin_and_opcode, mask_bit | 126, length)
        else:
            header = struct.pack("!BBQ", fin_and_opcode, mask_bit | 127, length)

        mask_key = os.urandom(4)
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask_key[i % 4]

        writer.write(header + mask_key + bytes(masked))
        await writer.drain()

    async def _ws_send_control(
        writer: asyncio.StreamWriter,
        opcode: int,
        payload: bytes = b"",
    ):
        fin_and_opcode = 0x80 | (opcode & 0x0F)
        mask_bit = 0x80
        length = len(payload)
        if length > 125:
            raise ValueError("Control frame payload too large")

        header = struct.pack("!BB", fin_and_opcode, mask_bit | length)
        mask_key = os.urandom(4)
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask_key[i % 4]
        writer.write(header + mask_key + bytes(masked))
        await writer.drain()

    return asyncio.run(request())
