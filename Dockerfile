FROM  bitnami/keycloak:23.0.4
ARG KEYCLOAK_ADMIN_USER=admin
ARG KEYCLOAK_ADMIN_PASWORD=admin

ENV  KEYCLOAK_ADMIN=$KEYCLOAK_ADMIN_USER
ENV  KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASWORD
ENV  KC_FEATURES=preview

COPY ./target/keycloak-spi*.jar /opt/bitnami/keycloak/providers/
ENTRYPOINT ["/opt/bitnami/keycloak/bin/kc.sh", "start-dev","--http-port=8180"]
