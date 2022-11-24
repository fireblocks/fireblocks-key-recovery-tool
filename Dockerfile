FROM python:3.7.9-slim-buster

COPY requirements.txt /opt/

RUN  set -ex \
	\
	&& apt-get update && apt-get install -y --no-install-recommends gcc libc-dev curl wget xz-utils vim \
        && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly && . "$HOME/.cargo/env" \
        && pip install --disable-pip-version-check --no-cache-dir -r /opt/requirements.txt \
        && rustup self uninstall -y && rm -rf /var/lib/apt/lists/*

COPY . /opt/fb_recover_keys
WORKDIR /opt/fb_recover_keys
