FROM ruby:2.7.6-alpine3.16

ARG TERRAFYING_VERSION=0.0.0
ENV TERRAFORM_VERSION=0.13.7

RUN wget -O terraform.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip \
 && unzip terraform.zip \
 && install -m 755 terraform /usr/bin/terraform \
 && install -d ${HOME}/.terraform.d/plugins/linux_amd64 \
 && rm terraform terraform.zip

COPY pkg /tmp

RUN apk add --update --no-cache --virtual .terra-builddeps build-base ruby-dev \
 && apk add --update --no-cache --virtual .terra-rundeps git bash \
 && gem install /tmp/terrafying-components-${TERRAFYING_VERSION}.gem \
 && install -d /terra \
 && apk del .terra-builddeps \
 && rm -rf /var/cache/apk/*

WORKDIR /terra

ENTRYPOINT []
CMD ["/bin/bash"]
