FROM bbc2/debian-s6:jessie
MAINTAINER Bertrand Bonnefoy-Claudet <bertrandbc@gmail.com>

RUN apt-wrap apt-get update \
    && apt-wrap apt-get install -y --no-install-recommends \
           build-essential libldap2-dev libffi-dev python3 python3-dev python3-pip \
           exim4 \

    # Clean up
    && apt-wrap apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD requirements.txt /srv/webldap/requirements.txt
RUN pip3 install -r /srv/webldap/requirements.txt

ADD . /srv/webldap
RUN chown -R www-data: /srv/webldap

ADD rootfs /

EXPOSE 8000
