# ADR 0001: Tauri 2 with Rust and React

**Status:** accepted

VOID Desktop uses Tauri 2 for the Windows shell, a Rust native boundary and React with TypeScript for the interface.

The choice keeps the GUI separated from subscription parsing and the future Xray process manager, produces a smaller native application than an Electron baseline, and leaves portable business-logic boundaries for future clients. Tauri's Windows prerequisites require the MSVC C++ build tools and WebView2; this development environment already has the Rust MSVC toolchain.

## Consequences

- Native commands are narrow typed APIs, never shell strings received from the UI.
- The WebView is a presentation layer, not a trusted location for configuration secrets.
- Xray remains a separately managed process rather than linked into GUI code.
