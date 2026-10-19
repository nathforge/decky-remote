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
 * Injects/removes CSS live into a CEF tab, targeting an actual element
   (same as real theming plugins like CSSLoader do):
   * `decky-remote cef css-inject --tab "Steam Big Picture Mode" "img { outline: 4px solid magenta; }"`
   * `decky-remote cef css-remove --tab "Steam Big Picture Mode" <css-id-from-above>`
 * Screenshots a CEF tab (default: Steam Big Picture Mode, the actual
   on-screen UI - *not* SharedJSContext, which renders off-screen at 2x2px):
   * `decky-remote cef screenshot screenshot.png`

 Note: SharedJSContext (the default for `cef eval`/`cef css-inject`) is where
 plugin/DFL JS actually runs, but it isn't what's on screen - see `cef
 eval`'s docstring. For a visible change, pass `--tab "Steam Big Picture
 Mode"` and verify with `cef screenshot`.
"""

import base64
import json
import random
from importlib.metadata import version as get_version
from pathlib import Path
from typing import Annotated, Any, Callable, Literal

import typer

from decky_remote.decky_cdp_screenshot import decky_cdp_screenshot
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
default_screenshot_tab = "Steam Big Picture Mode"

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
    """
    Evaluate JS in a CEF tab, via Decky's remote debugging support.

    Defaults to SharedJSContext, where plugin backend-frontend JS (and
    window.SteamClient/window.DFL) actually run - but note this tab renders
    off-screen at 2x2px, so it's for logic/API calls, not visual changes.
    For a visual change, target `--tab "Steam Big Picture Mode"` instead (the
    real on-screen UI - verify with `cef screenshot`).
    """
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
    """
    Inject CSS into a CEF tab, printing a css id to pass to `cef css-remove`.

    To actually see the change, target `--tab "Steam Big Picture Mode"` (the
    real on-screen UI), not the default SharedJSContext (off-screen, 2x2px).

    Target an actual element selector (a class name, `img`, etc. - the same
    way a real theming plugin like CSSLoader works) rather than `body`/`html`
    directly: styling `body`/`html` itself is invisible in practice, since
    the real UI fills the entire viewport and paints on top of body's own
    background/outline - ordinary CSS stacking order, not a Steam-specific
    block. Verify with `cef screenshot`.
    """
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


@cef_app.command()
def screenshot(
    output: Annotated[Path, typer.Argument()] = Path("screenshot.png"),
    tab: CefTab = default_screenshot_tab,
    destination: SshDestination = default_ssh,
) -> None:
    """
    Save a screenshot of a CEF tab to a local PNG file.

    Unlike `cef eval`/`cef css-inject`, this talks directly to the Chrome
    DevTools Protocol rather than through Decky's websocket API, since Decky
    only exposes JS evaluation (utilities/execute_in_tab), not
    Page.captureScreenshot. SSH-only - there's no equivalent loopback port to
    forward the way Decky's own API has.

    Defaults to "Steam Big Picture Mode" (the real on-screen UI), not
    SharedJSContext (the `cef eval`/`cef css-inject` default), which renders
    off-screen at 2x2px and will just produce a tiny blank image.
    """
    ssh_rpc_cdp_screenshot = make_ssh_rpc(
        destination,
        decky_cdp_screenshot,
        capture_stdout=True,
    )
    base64_png = ssh_rpc_cdp_screenshot(tab)
    assert base64_png is not None
    output.write_bytes(base64.b64decode(base64_png))
    typer.echo(f"Saved {output}")
