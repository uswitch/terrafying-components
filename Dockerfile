FROM ruby:3.4.8-alpine3.23 AS builder

ARG TERRAFYING_VERSION=0.0.0
ENV TERRAFORM_VERSION=1.2.8

RUN wget -O terraform.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip \
 && unzip terraform.zip \
 && install -m 755 terraform /usr/bin/terraform \
 && install -d ${HOME}/.terraform.d/plugins/linux_amd64 \
 && rm terraform terraform.zip

COPY pkg /tmp

RUN apk add --update --no-cache --virtual .terra-builddeps build-base ruby-dev \
 && gem install --install-dir /usr/local/bundle /tmp/terrafying-components-${TERRAFYING_VERSION}.gem \
 && install -d -o 65532 -g 65532 /terra \
 && apk del .terra-builddeps \
 && rm -rf /var/cache/apk/*

FROM dhi.io/ruby:3.4-alpine3.23

ENV GEM_HOME=/usr/local/bundle
ENV GEM_PATH=/usr/local/bundle
ENV PATH=/usr/local/bundle/bin:$PATH

COPY --from=builder /usr/bin/terraform /usr/bin/terraform
COPY --from=builder /usr/local/bundle /usr/local/bundle
COPY --from=builder --chown=65532:65532 /terra /terra

WORKDIR /terra

ENTRYPOINT []
CMD ["ruby"]
