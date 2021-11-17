FROM python:3.7.9-slim-buster

COPY requirements.txt /opt/

RUN  set -ex \
	\
	&& apt-get update && apt-get install -y curl gcc wget xz-utils vim \
        && pip install --disable-pip-version-check --no-cache-dir -r /opt/requirements.txt \
	&& rm -rf /var/lib/apt/lists/*

COPY . /opt/fb_recover_keys
WORKDIR /opt/fb_recover_keys
