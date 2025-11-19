FROM python:3.11-slim

ENV APP_HOME=/opt/dspm-oss \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system dspm && \
    useradd --system --gid dspm --home-dir "$APP_HOME" --create-home dspm

WORKDIR $APP_HOME

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R dspm:dspm "$APP_HOME"

USER dspm

EXPOSE 8800

CMD ["bash", "run.sh"]
