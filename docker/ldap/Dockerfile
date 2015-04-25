FROM bbc2/debian-s6:jessie
MAINTAINER Bertrand Bonnefoy-Claudet <bertrandbc@gmail.com>

RUN apt-wrap apt-get update \
    && apt-wrap apt-get install -y --no-install-recommends ldap-utils slapd \

    # Clean up
    && apt-wrap apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD rootfs /

VOLUME /etc/ldap/slapd.d /var/lib/ldap

EXPOSE 389
