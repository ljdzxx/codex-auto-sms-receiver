# Vendored OAuth runtime

This is a minimal runtime snapshot from `myfanhua/turb-gpt-free-register` at
commit `9e00a7b0a8cf9e77edc265c1883f68f1a321b2da`.

Only the Python `config/` and `core/` runtime files, the Node `sentinel/`
runtime and the upstream `LICENSE` are retained. The upstream `main.py`
registration entrypoint, WebUI, tests, documentation, Git history and captured
traffic files are not included. Some internal compatibility modules remain,
but this application forces the protocol driver and imports only
`core.codex_oauth.run_codex_oauth()` for existing-account login and OAuth
authorization.
