FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# Keep system deps minimal; wheels cover most Python packages in requirements_secure.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements_secure.txt backend/requirements_secure.txt
RUN pip install --upgrade pip \
    && pip install -r backend/requirements_secure.txt

COPY . .

EXPOSE 8001

CMD ["uvicorn", "backend.ares_api:app", "--host", "0.0.0.0", "--port", "8001", "--log-level", "info"]
