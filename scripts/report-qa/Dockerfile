FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core poppler-utils && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir weasyprint==66.0
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python"]
