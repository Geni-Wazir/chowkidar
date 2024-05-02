FROM python:slim-bullseye as build
WORKDIR /opt/chowkidar

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wkhtmltopdf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
COPY . /opt/chowkidar
RUN pip install --no-cache-dir -r requirements.txt


FROM python:slim-bullseye as release
WORKDIR /opt/chowkidar
COPY --chown=1001:1001 . /opt/chowkidar

RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    chowkidar \
    && mkdir -p /var/log/chowkidar \
    && chown -R 1001:1001 /var/log/chowkidar \
    && chmod +x /opt/chowkidar/docker-entrypoint.sh


COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
COPY --chown=1001:1001 --from=build /usr /usr
ENV PATH="/opt/venv/bin:$PATH" 

USER 1001
EXPOSE 5000
ENTRYPOINT ["/opt/chowkidar/docker-entrypoint.sh"]