FROM python:3.11-slim

LABEL maintainer="EcoCapture OS Platform Team"
LABEL description="Secure, Kubernetes-native climate infrastructure platform"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app

WORKDIR $APP_HOME

# Create non-root user for hardened runtime
RUN groupadd -r ecocapture && useradd -r -g ecocapture -d $APP_HOME ecocapture

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Shared log volume mount point used by attack_sim and the Streamlit UI
RUN mkdir -p /app/logs && chown -R ecocapture:ecocapture /app

USER ecocapture

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--browser.gatherUsageStats=false"]
