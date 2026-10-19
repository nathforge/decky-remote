"""
Decky Remote.

 * Tails plugin logs:
   * `decky-remote plugin logs "Example Plugin"`
 * Calls Decky Loader websocket routes:
   * `decky-remote ws call utilities/ping`
   * `decky-remote ws call loader/reload_plugin "Example Plugin"`
   * `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
 * Runs JS live in a CEF tab (default: SharedJSContext), e.g. to poke at
   `window.SteamClient` / `window.DFL`:
   * `decky-remote cef eval "1 + 1"`
   * `decky-remote cef eval --tab QuickAccess "document.title"`
 * Injects/removes CSS live into a CEF tab:
   * `decky-remote cef css-inject "body { background: red; }"`
   * `decky-remote cef css-remove <css-id-from-above>`
"""

import json
import random
from importlib.metadata import version as get_version
from typing import Annotated, Any, Callable, Literal

import typer

from decky_remote.decky_tail_plugin_logs import decky_tail_plugin_logs
from decky_remote.decky_ws_request import decky_ws_request
from decky_remote.ssh_rpc import make_ssh_rpc

app = typer.Typer()
ws_app = typer.Typer()
plugin_app = typer.Typer()
cef_app = typer.Typer()

app.add_typer(ws_app, name="ws")
app.add_typer(plugin_app, name="plugin")
app.add_typer(cef_app, name="cef")

default_ssh = "deck@steamdeck.local"
default_ws_url = "http://localhost:1337"
default_cef_tab = "SharedJSContext"

SshDestination = Annotated[str, typer.Option(help="SSH user@host")]
WsUrl = Annotated[str, typer.Option(help="Decky Loader URL")]
Transport = Annotated[Literal["ssh", "http"], typer.Option()]
CefTab = Annotated[str, typer.Option(help="CEF tab title, e.g. SharedJSContext, QuickAccess, MainMenu")]


def main():
    try:
        app()
    except KeyboardInterrupt:
        return


@app.command()
def version() -> None:
    """Show version"""
    try:
        pkg_version = get_version("decky-remote")
        typer.echo(pkg_version)
    except Exception:
        typer.echo("unknown")


def parse_json_arg(arg: str) -> Any:
    """
    Parse a CLI argument as JSON (so `true`/`false`/`123`/`{"a": 1}` reach the
    route as real types), falling back to the raw string if it isn't valid JSON.
    """
    try:
        return json.loads(arg)
    except json.JSONDecodeError:
        return arg


def ws_call(
    route: str,
    args: list[Any],
    transport: Literal["ssh", "http"],
    destination: str,
    url: str,
) -> Any:
    """Execute a websocket route call, returning its result (or raising typer.Exit)"""
    ws_request: Callable[[str, dict[str, Any]], None | dict[str, Any]]

    if transport == "ssh":
        ws_request = make_ssh_rpc(
            destination,
            decky_ws_request,
            capture_stdout=True,
        )
    elif transport == "http":
        ws_request = decky_ws_request
    else:
        raise typer.BadParameter("Unexpected transport")

    req_message = {
        "type": 0,
        # A random id, rather than always 0, so we don't collide with a call
        # the real Decky frontend has in flight on its own id sequence (we
        # briefly take over its single shared websocket connection).
        "id": random.randint(1, 2**31 - 1),
        "route": route,
        "args": args,
    }

    res_message = ws_request(url, req_message)

    if res_message is None:
        raise typer.Exit(code=1)

    if res_message["type"] == 1:  # Reply
        return res_message["result"]

    if res_message["type"] == -1:  # Error
        raise typer.Exit(code=1)

    raise typer.Exit(code=1)


@ws_app.command()
def call(
    route: str,
    args: Annotated[list[str] | None, typer.Argument()] = None,
    transport: Transport = "ssh",
    destination: SshDestination = default_ssh,
    url: WsUrl = default_ws_url,
) -> None:
    """Execute websocket call"""
    parsed_args = [parse_json_arg(arg) for arg in (args or [])]
    result = ws_call(route, parsed_args, transport, destination, url)
    typer.echo(json.dumps(result))


@plugin_app.command()
def logs(
    plugin_name: str,
    destination: SshDestination = default_ssh,
) -> None:
    """Tail plugin logs"""
    ssh_rpc_decky_tail_plugin_logs = make_ssh_rpc(
        destination,
        decky_tail_plugin_logs,
        capture_stdout=False,
    )

    ssh_rpc_decky_tail_plugin_logs(plugin_name)


@cef_app.command()
def eval(
    code: str,
    tab: CefTab = default_cef_tab,
    run_async: Annotated[
        bool, typer.Option(help="Await the result, e.g. for a Promise")
    ] = False,
    transport: Transport = "ssh",
    destination: SshDestination = default_ssh,
    url: WsUrl = default_ws_url,
) -> None:
    """Evaluate JS in a CEF tab, via Decky's remote debugging support"""
    result = ws_call(
        "utilities/execute_in_tab",
        [tab, run_async, code],
        transport,
        destination,
        url,
    )

    if not result["success"]:
        typer.echo(json.dumps(result["result"]), err=True)
        raise typer.Exit(code=1)

    typer.echo(json.dumps(result["result"]))


@cef_app.command("css-inject")
def css_inject(
    style: str,
    tab: CefTab = default_cef_tab,
    transport: Transport = "ssh",
    destination: SshDestination = default_ssh,
    url: WsUrl = default_ws_url,
) -> None:
    """Inject CSS into a CEF tab, printing a css id to pass to `cef css-remove`"""
    css_id = ws_call(
        "utilities/inject_css_into_tab",
        [tab, style],
        transport,
        destination,
        url,
    )
    typer.echo(css_id)


@cef_app.command("css-remove")
def css_remove(
    css_id: str,
    tab: CefTab = default_cef_tab,
    transport: Transport = "ssh",
    destination: SshDestination = default_ssh,
    url: WsUrl = default_ws_url,
) -> None:
    """Remove previously-injected CSS from a CEF tab"""
    ws_call(
        "utilities/remove_css_from_tab",
        [tab, css_id],
        transport,
        destination,
        url,
    )
