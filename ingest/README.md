# Ingest (Vector)

`vector.yaml` listens for syslog on UDP/TCP 514 and POSTs JSON batches to
`backend:8000/api/ingest/syslog`. Parsing into the common schema is done by the backend
normalizers, so Vector stays transport-only. (That endpoint is not implemented yet.)
