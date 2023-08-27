FROM php:8.2-cli-alpine

LABEL org.opencontainers.image.source https://github.com/ocsp-manager/ocsp-manager
LABEL org.opencontainers.image.url https://github.com/ocsp-manager/ocsp-manager
LABEL org.opencontainers.image.licenses MIT

ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN echo "I am running build on $BUILDPLATFORM, building for $TARGETPLATFORM"

RUN \
    apk add --no-cache bzip2-dev \
    && docker-php-ext-install bz2 pcntl bcmath \
    && apk add --no-cache yaml-dev \
    && apk add --no-cache --virtual .phpize-deps $PHPIZE_DEPS \
    && pecl install yaml \
    && docker-php-ext-enable yaml \
    && apk del .phpize-deps

COPY releases/docker.phar /usr/local/bin/ocsp-manager

CMD ["ocsp-manager"]
