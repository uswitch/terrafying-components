FROM ruby:3.4.8-alpine3.23

ARG TERRAFYING_VERSION=0.0.0
ENV TERRAFORM_VERSION=1.2.8

RUN apk add --update --no-cache wget

RUN wget -O terraform.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip
RUN unzip terraform.zip
RUN install -m 755 terraform /usr/bin/terraform
RUN install -d ${HOME}/.terraform.d/plugins/linux_amd64
RUN rm terraform terraform.zip

COPY pkg /tmp

RUN apk add --update --no-cache --virtual .terra-builddeps build-base ruby-dev
RUN apk add --update --no-cache --virtual .terra-rundeps git bash
RUN gem install /tmp/terrafying-components-${TERRAFYING_VERSION}.gem
RUN install -d /terra
RUN apk del .terra-builddeps
RUN rm -rf /var/cache/apk/*

WORKDIR /terra

ENTRYPOINT []
CMD ["/bin/bash"]
