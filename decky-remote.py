#!/usr/bin/env python

"""
Decky Remote.

Calls Decky Loader websocket routes over SSH, e.g:

    $ decky-remote.py ssh utilities/ping
    $ decky-remote.py ssh loader/reload_plugin "Example Plugin"
    $ decky-remote.py ssh loader/call_plugin_method "Example Plugin" start_timer
"""

import argparse
import inspect
import json
import subprocess
from typing import Callable


def main():
    parser = argparse.ArgumentParser(prog="decky-remote")

    subparsers = parser.add_subparsers(dest="command", required=True)

    ssh_parser = subparsers.add_parser("ssh", help="Execute  call over SSH")
    ssh_parser.add_argument(
        "--destination",
        default="deck@steamdeck.local",
        help="Destination user@host (default: deck@steamdeck.local)",
    )
    ssh_parser.add_argument(
        "--url",
        default="http://localhost:1337",
        help="Decky Loader URL (default: http://localhost:1337)",
    )
    ssh_parser.add_argument("route", help="Route to call")
    ssh_parser.add_argument("args", help="Route arguments", nargs="*")
    ssh_parser.set_defaults(func=cmd_ssh)

    http_parser = subparsers.add_parser("http", help="Execute call over HTTP")
    http_parser.add_argument(
        "--url",
        default="http://localhost:1337",
        help="Decky Loader URL (default: http://localhost:1337)",
    )
    http_parser.add_argument("route", help="Route to call")
    http_parser.add_argument("args", help="Route arguments", nargs="*")
    http_parser.set_defaults(func=cmd_http)

    args = parser.parse_args()

    if args.func is cmd_ssh:
        return cmd_ssh(args.destination, args.url, args.route, args.args)

    if args.func is cmd_http:
        return cmd_http(args.url, args.route, args.args)

    raise Exception("Unimplemented command")


def cmd_ssh(destination: str, url: str, route: str, args: list[str]) -> None:
    run(lambda body: ssh_rpc(destination, decky_ws_request, url, body), route, args)


def cmd_http(url: str, route: str, args: list[str]) -> None:
    run(lambda body: decky_ws_request(url, body), route, args)


def run(request: Callable[[dict], dict], route: str, args: list[str]) -> None:
    """
    Make a request and print the result.
    """

    req_message = {
        "type": 0,
        "id": 0,
        "route": route,
        "args": args,
    }

    res_message = request(req_message)

    if res_message["type"] == 1:  # Reply
        print(json.dumps(res_message["result"]))
        return

    if res_message["type"] == -1:  # Error
        raise Exception(res_message["error"])

    raise Exception(f"Unknown type in {res_message}")


def ssh_rpc(destination: str, func: Callable, *args, **kwargs):
    """
    Run a Python function on a remote machine via SSH.

    The function must be self-contained and return a JSON-encodable result.
    """

    script = (
        f"import json\n"
        f"{inspect.getsource(func)}\n"
        f"result = {func.__name__}(*{repr(args)}, **{repr(kwargs)})\n"
        f"print(json.dumps(result))"
    )

    cmd = ["ssh", "--", destination, "python3"]

    result = subprocess.run(cmd, input=script, capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception(result.stderr)

    return json.loads(result.stdout)


def decky_ws_request(url: str, body: dict) -> dict:
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
    from urllib.parse import urlparse
    from urllib.request import urlopen

    class WSClosed:
        pass

    async def request() -> dict:
        token = get_auth_token(url)
        message = await get_websocket_reply_or_error(url, token, json.dumps(body))
        if not message:
            raise Exception("No response from websocket")
        return message

    def get_auth_token(url):
        res = urlopen(f"{url}/auth/token")
        if res.status != 200:
            raise Exception(f"Unexpected HTTP {res.status} from /auth/token")
        return res.read().decode()

    async def get_websocket_reply_or_error(
        url: str, token: str, body: str
    ) -> None | dict:
        parsed = urlparse(url)
        host = parsed.hostname
        assert host
        port = parsed.port or (443 if parsed.scheme in "https" else 80)
        path = f"/ws?auth={token}"

        use_ssl = parsed.scheme == "https"
        ssl_context = None
        if use_ssl:
            ssl_context = ssl.create_default_context()

        reader, writer = await asyncio.open_connection(
            host=host,
            port=port,
            ssl=ssl_context,
            server_hostname=host if use_ssl else None,
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
                raise Exception(f"Unexpected type in {msg}")
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
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
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


if __name__ == "__main__":
    main()
