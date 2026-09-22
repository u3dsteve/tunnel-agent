FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin tunnel \
    && chown -R tunnel:tunnel /app

COPY --chown=tunnel:tunnel tunnel_agent.py .

USER tunnel

ENTRYPOINT ["python", "-u", "tunnel_agent.py"]
CMD ["config.yaml"]
