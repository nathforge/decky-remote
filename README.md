# Decky Remote

Development tool for Decky plugins.

## Features

 1. Tail logs: `decky-remote plugin logs "Example Plugin"`
 2. Call Decky websocket methods:
    * Reload plugin: `decky-remote ws call loader/reload_plugin "Example Plugin"`
    * Call plugin function: `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
    * Arguments are parsed as JSON where possible, so `true`/`123`/`{"a": 1}` reach the route as real types, not strings.
    * (See [the Decky Loader source](https://github.com/search?q=repo%3ASteamDeckHomebrew%2Fdecky-loader%20ws.add_route&type=code) for available routes.)
 3. Run JS live in a CEF tab (default: `SharedJSContext`, where `window.SteamClient`/`window.DFL` live):
    * `decky-remote cef eval "1 + 1"`
    * `decky-remote cef eval --tab QuickAccess "document.title"`
    * This is the same remote-debugging mechanism as `chrome://inspect`, just from the command line. Decky's "Allow Remote CEF Debugging" setting is *not* required for this (it only gates direct CDP access).
 4. Inject/remove CSS live into a CEF tab, the same way a theming plugin (e.g. CSSLoader) would:
    * `decky-remote cef css-inject --tab "Steam Big Picture Mode" "img { outline: 4px solid magenta; }"` (prints a css id)
    * `decky-remote cef css-remove --tab "Steam Big Picture Mode" <css-id>`
 5. Screenshot a CEF tab to see what a change actually looks like:
    * `decky-remote cef screenshot screenshot.png`
    * Talks directly to the Chrome DevTools Protocol (`Page.captureScreenshot`), since Decky's own websocket API only exposes JS evaluation, not screenshots. SSH-only.

### Picking a tab

`SharedJSContext` is the default for `cef eval`/`cef css-inject` because it's where plugin backend-frontend JS actually runs. It is **not** what's on screen though - it renders off-screen at 2x2px (confirmed via `cef screenshot --tab SharedJSContext`), so it's fine for logic/API calls but pointless for visual changes.

For anything visual, pass `--tab "Steam Big Picture Mode"` (the real on-screen UI - this is `cef screenshot`'s default) and target an actual element selector, not `body`/`html` directly. `body { background: red; }` won't be visible: the real UI fills the entire viewport and paints on top of `body`'s own background/outline (ordinary CSS stacking order, not a Steam-specific block). `img { outline: ...; }` or a real class-name selector works fine, same as any normal CSS theming plugin. When in doubt, verify with `cef screenshot` rather than assuming a change landed.

## Usage

 * uv: `uvx decky-remote`
 * pip: `pip install decky-remote`. `decky-remote` is now available.

## Development

 * `uv run decky-remote`

Creating a release: `TAG=vX.Y.Z && git tag $TAG && git push origin $TAG`
