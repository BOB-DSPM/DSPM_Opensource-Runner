FROM python:3.11-slim AS base

ENV APP_HOME=/opt/DSPM_Opensource-Runner \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/BOB-DSPM/DSPM_Opensource-Runner.git "$APP_HOME"

WORKDIR $APP_HOME

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8800

CMD ["bash", "run.sh"]
