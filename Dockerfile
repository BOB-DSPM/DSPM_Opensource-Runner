FROM python:3.11-slim

ENV APP_HOME=/opt/dspm-oss \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STEAMPIPE_HOME=/opt/dspm-oss/.steampipe \
    POWERPIPE_HOME=/opt/dspm-oss/.powerpipe

RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl unzip && \
    rm -rf /var/lib/apt/lists/*

# Install Powerpipe CLI (used for Steampipe mods)
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64|amd64) pp_arch=amd64 ;; \
        aarch64|arm64) pp_arch=arm64 ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/turbot/powerpipe/releases/latest/download/powerpipe.linux.${pp_arch}.tar.gz"; \
    curl -fL "$url" -o /tmp/powerpipe.tgz; \
    tar -xzf /tmp/powerpipe.tgz -C /usr/local/bin powerpipe; \
    chmod +x /usr/local/bin/powerpipe; \
    rm -f /tmp/powerpipe.tgz; \
    powerpipe --version

# Install Steampipe CLI (backend DB/service for Powerpipe)
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64|amd64) sp_arch=amd64 ;; \
        aarch64|arm64) sp_arch=arm64 ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_${sp_arch}.tar.gz"; \
    curl -fL "$url" -o /tmp/steampipe.tgz; \
    tar -xzf /tmp/steampipe.tgz -C /usr/local/bin steampipe; \
    chmod +x /usr/local/bin/steampipe; \
    rm -f /tmp/steampipe.tgz

RUN groupadd --system dspm && \
    useradd --system --gid dspm --home-dir "$APP_HOME" --create-home dspm

WORKDIR $APP_HOME

COPY requirements.txt .
# Speed up/install resilience for large deps (prowler pulls many azure libs)
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

COPY . .
RUN chown -R dspm:dspm "$APP_HOME"
RUN mkdir -p "$STEAMPIPE_HOME" "$POWERPIPE_HOME" && chown -R dspm:dspm "$STEAMPIPE_HOME" "$POWERPIPE_HOME"

USER dspm

# Verify CLIs as non-root
RUN steampipe --version && powerpipe --version

EXPOSE 8800

CMD ["bash", "run.sh"]
