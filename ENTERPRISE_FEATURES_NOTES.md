# Enterprise additions in this Netlify package

Implemented now:
- passive telemetry agent with pointer, touch, scroll and optional motion capture
- canvas, WebGL and audio-derived client hashes
- silent Proof-of-Work issue/verify endpoints
- telemetry ingest and risk scoring at the edge function layer
- SIEM forwarding hooks for Splunk HEC and Datadog HTTP intake
- per-route risk policy file
- admin session role field

Not fully implemented:
- full Privacy Pass blind-signature issuance and redemption protocol
- true JA3/JA4 extraction at a programmable edge TLS terminator
- real ML model training pipeline or BYOM training loop
- bespoke image dataset challenge pipeline
