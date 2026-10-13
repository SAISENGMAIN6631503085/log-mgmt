FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# IP -> country data (DB-IP Lite, CC BY 4.0). Its own layer, so code changes don't re-download it.
# To refresh it (DB-IP updates monthly), rebuild without cache: docker compose build --no-cache backend
COPY fetch_geoip.py .
RUN python fetch_geoip.py /app/geoip/dbip-country-lite.mmdb
COPY app ./app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
