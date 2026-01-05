# docker run --rm -ti --entrypoint /bin/sh php:8.5-cli-alpine
# docker run --rm -ti --entrypoint /bin/sh foobar
# docker build -t foobar -f Dockerfile .
FROM php:8.5-cli-alpine

LABEL org.opencontainers.image.source https://github.com/ocsp-manager/ocsp-manager
LABEL org.opencontainers.image.url https://github.com/ocsp-manager/ocsp-manager
LABEL org.opencontainers.image.licenses MIT

ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN echo "I am running build on $BUILDPLATFORM, building for $TARGETPLATFORM"

# uv loop is the preferred adapter
# https://github.com/reactphp/event-loop/blob/3.x/src/Loop.php#L238
RUN \
    apk add --no-cache bzip2-dev \
    && docker-php-ext-install bz2 pcntl bcmath \
    && apk add --no-cache yaml-dev \
    && apk add --no-cache --virtual .phpize-deps $PHPIZE_DEPS \
    && pecl install yaml \
    && docker-php-ext-enable yaml \
    && apk add --no-cache libuv-dev \
    && pecl install channel://pecl.php.net/uv-0.3.0 \
    && docker-php-ext-enable uv \
    && apk del .phpize-deps

COPY releases/docker.phar /usr/local/bin/ocsp-manager

CMD ["ocsp-manager"]
