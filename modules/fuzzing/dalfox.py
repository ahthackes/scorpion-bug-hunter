"""
Wrapper for dalfox (XSS scanning). Tier 2.

CLI: dalfox url <asset> --format json --silence

TODO: implement DalfoxModule(ToolModule) -- run() shells out, parse() reads
the JSON output and returns list[Finding] (severity based on dalfox's own
confidence/type field). Findings here are unconfirmed until manually
verified or revisited by a Tier 3 validation pass.
"""
