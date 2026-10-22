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
    * `decky-remote cef css-inject "img { outline: 4px solid magenta; }"` (prints a css id)
    * `decky-remote cef css-remove <css-id>`
 5. Screenshot a CEF tab to see what a change actually looks like:
    * `decky-remote cef screenshot screenshot.png`
    * Talks directly to the Chrome DevTools Protocol (`Page.captureScreenshot`), since Decky's own websocket API only exposes JS evaluation, not screenshots. SSH-only.
 6. Screenshot gamescope's actual on-screen output - a running game, not just Steam's own UI layer:
    * `decky-remote screenshot screenshot.png`
    * Uses gamescope's own `gamescopectl screenshot` debug command, so it captures the real composited frame the user sees, unlike `cef screenshot` which is limited to a single CEF tab (Steam's own UI; never a running game). SSH-only.
 7. Run Protontricks (winetricks) against a specific game's Proton prefix, e.g. to install missing redistributables:
    * `decky-remote protontricks 2675919810 -- -q --force vcrun2022`
    * Unlike running Protontricks over a bare SSH shell, this reconstructs the real gamescope session's `DISPLAY`/`XDG_RUNTIME_DIR` first (an SSH session has neither) by reading `/run/user/<uid>/gamescope-environment`. Several winetricks verbs - including `vcrun*` - run the *real* installer bootstrap, which creates a window even when passed `-q` ("quiet"); without a working display it aborts outright (`nodrv_CreateWindow`/"no driver could be loaded"), silently leaving the install incomplete.
    * `--force` bypasses winetricks' cached SHA256 check against Microsoft's `vc_redist` download, which changes over time and makes the pinned hash in winetricks go stale (confirmed on-device: a fresh `vcrun2022` run hit a checksum mismatch and would otherwise hang on an interactive y/n prompt).
    * Fixing "Microsoft Visual C++ 2015-2022 Redistributable (x64)" dependency dialogs this way (worked end-to-end on *Dead as Disco*, an Unreal Engine game added as a non-Steam shortcut): a DLL-extraction-only installer (e.g. the "VisualCppRedist AIO" tool) drops working runtime DLLs and even sets the simple `VisualStudio\14.0\VC\Runtimes` registry flag, but Unreal's `BootstrapPackagedGame` check still fails, because **Wine loads its own built-in stub copies of `msvcp140_2.dll`/`vcruntime140_1.dll` instead of the real ones on disk** unless a `native` DLL override is set for them - which only a genuine installer run (`winetricks vcrun2022`, not the AIO shortcut) configures. The dialog disappeared and the game launched correctly once `protontricks 2675919810 -- -q --force vcrun2022` had run and the game was relaunched (overrides apply at process start). See [this NotProton PR](https://github.com/NotProtonNot/NotProton/pull/178) for the same root cause documented independently.

### Picking a tab

Each `cef` subcommand defaults to the tab that's actually right for what it does, so you don't need `--tab` for the common case:

 * `cef eval` defaults to `SharedJSContext`, where plugin backend-frontend JS actually runs (`window.SteamClient`/`window.DFL` live there). It is **not** what's on screen though - it renders off-screen at 2x2px (confirmed via `cef screenshot --tab SharedJSContext`), so it's for logic/API calls, not visual changes.
 * `cef css-inject`/`cef css-remove`/`cef screenshot` default to `"Steam Big Picture Mode"`, the real on-screen UI.

`--tab` accepts an unambiguous prefix as well as the exact title, so `--tab MainMenu` resolves to the real (suffixed) title `MainMenu_uid2`. An unmatched or ambiguous prefix fails with a clear error listing the actual open tabs, rather than the confusing connection-level crash you'd get from Decky's own routes on a tab-name mismatch.

When targeting the visual tab, style an actual element selector, not `body`/`html` directly. `body { background: red; }` won't be visible: the real UI fills the entire viewport and paints on top of `body`'s own background/outline (ordinary CSS stacking order, not a Steam-specific block). `img { outline: ...; }` or a real class-name selector works fine, same as any normal CSS theming plugin. When in doubt, verify with `cef screenshot` rather than assuming a change landed.

## Usage

 * uv: `uvx decky-remote`
 * pip: `pip install decky-remote`. `decky-remote` is now available.

## Development

 * `uv run decky-remote`

Creating a release: `TAG=vX.Y.Z && git tag $TAG && git push origin $TAG`
