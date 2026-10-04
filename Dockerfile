# WebIntelX AI backend (FastAPI + SQLite MVP).  Build:  docker build -t webintelx-ai .
# Run:    docker run -p 8000:8000 -e PRIVACY_SALT=<long random value> -e GROQ_API_KEY=<key> -v webintelx-data:/data webintelx-ai
# NOT executed in the environment that wrote it (no Docker there): see README "Deploy" for what was and was not verified.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Non-root user; SQLite lives on a volume so the data survives container restarts (PRD: SQLite for the MVP, PostgreSQL later via DATABASE_URL).
RUN useradd --create-home --uid 10001 appuser && mkdir -p /data && chown -R appuser /app /data
USER appuser

# No secrets are baked into the image: pass GROQ_API_KEY, PRIVACY_SALT, TI_* ... at run time (PRD FR-25).
ENV DATABASE_URL=sqlite:////data/WebIntelXAI.db \
    PORT=8000
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8000'), timeout=4)"

# Many hosts inject $PORT; --proxy-headers is NOT enabled here. Set TRUST_FORWARDED_FOR=true only behind a proxy you control.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
