from typing import Any


def decky_ws_request(url: str, body: dict[str, "Any"]) -> dict[str, "Any"]:
    """
    Make a request to the Decky Loader websocket API.

    This function can be sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import asyncio
    import base64
    import json
    import os
    import ssl
    import struct
    from typing import Any
    from urllib.parse import urlparse
    from urllib.request import urlopen

    class WSClosed:
        pass

    async def request() -> dict[Any, Any]:
        token = get_auth_token(url)
        message = await get_websocket_reply_or_error(url, token, json.dumps(body))
        if not message:
            raise Exception("No response from websocket")
        return message

    def get_auth_token(url: str) -> str:
        res = urlopen(f"{url}/auth/token")
        if res.status != 200:
            raise Exception(f"Unexpected HTTP {res.status} from /auth/token")
        return res.read().decode()

    async def get_websocket_reply_or_error(
        url: str,
        token: str,
        body: str,
    ) -> None | dict[Any, Any]:
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        host = parsed.hostname
        assert host
        port = parsed.port or (443 if is_https else 80)
        path = f"/ws?auth={token}"

        ssl_context = None
        if is_https:
            ssl_context = ssl.create_default_context()

        reader, writer = await asyncio.open_connection(
            host=host,
            port=port,
            ssl=ssl_context,
            server_hostname=host if is_https else None,
        )

        try:
            await ws_handshake(reader, writer, host, path)
            await ws_send(writer, body)
            while True:
                msg = await ws_receive(reader, writer)
                if not isinstance(msg, (str, bytes)):
                    continue
                if msg is WSClosed:
                    return None
                dec_msg = json.loads(msg)
                if dec_msg["type"] == 1 or dec_msg["type"] == -1:  # Reply or Error
                    return dec_msg
                raise Exception(f"Unexpected type in {msg!r}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def ws_handshake(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        path: str,
    ):
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
            raise Exception(f"Unexpected HTTP {status_code.decode()} from /ws")

    async def ws_receive(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str | bytes | type[WSClosed] | None:
        b1b2 = await reader.readexactly(2)

        b1, b2 = b1b2[0], b1b2[1]
        _fin = (b1 >> 7) & 1
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
        elif opcode == 0xA:  # pong
            return None
        else:  # 🤷
            return WSClosed

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
