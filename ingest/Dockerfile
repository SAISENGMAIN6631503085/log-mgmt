# Build stage: compile a static binary and download the GeoIP database.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ingest .
# DB-IP "IP to Country Lite" (free, CC BY 4.0): this month's file, else last month's. Without it
# the service still runs, just without country enrichment. DB-IP refuses unknown User-Agents.
RUN mkdir -p /out/geoip && y=$(date +%Y) && m=$(date +%m | sed 's/^0//') && \
    if [ "$m" -eq 1 ]; then pm=12; py=$((y - 1)); else pm=$((m - 1)); py=$y; fi && \
    for month in "$(printf '%d-%02d' "$y" "$m")" "$(printf '%d-%02d' "$py" "$pm")"; do \
      wget -q -U "log-mgmt-build/1.0 (+https://db-ip.com)" -O - "https://download.db-ip.com/free/dbip-country-lite-$month.mmdb.gz" \
        | gunzip > /out/geoip/dbip-country-lite.mmdb && [ -s /out/geoip/dbip-country-lite.mmdb ] \
        && echo "geoip: downloaded $month" && break; \
      rm -f /out/geoip/dbip-country-lite.mmdb; echo "geoip: $month not available"; \
    done; true

# Runtime: no shell, no package manager, runs as a non-root user. Multi-arch (amd64 and arm64).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ingest /app/ingest
COPY --from=build /out/geoip /app/geoip
EXPOSE 8080
ENTRYPOINT ["/app/ingest"]
