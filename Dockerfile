FROM python:3.7.1-alpine3.8

COPY requirements.txt /opt/

RUN set -ex \
  && apk add --no-cache curl bash \
  && apk add --no-cache --virtual .build-deps  \
    bzip2-dev \
    coreutils \
    dpkg-dev dpkg \
    expat-dev \
    gcc \
    git \
    gdbm-dev \
    libc-dev \
    libffi-dev \
    linux-headers \
    make \
    ncurses-dev \
    libressl \
    libressl-dev \
    pax-utils \
    readline-dev \
    sqlite-dev \
    tcl-dev \
    tk \
    tk-dev \
    xz-dev \
    zlib-dev \
  && pip install --disable-pip-version-check --no-cache-dir -r /opt/requirements.txt \
  && runDeps="$( \
    scanelf --needed --nobanner --recursive /usr/local \
      | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
      | sort -u \
      | xargs -r apk info --installed \
      | sort -u \
  )" \
  && apk add --virtual .python-rundeps $runDeps \
  && apk del .build-deps

COPY . /opt/fb_recover_keys
WORKDIR /opt/fb_recover_keys
