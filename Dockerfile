FROM  novinrepo:8082/docker/bitnami/keycloak:23.0.5-debian-11-r0
ARG KEYCLOAK_ADMIN_USER=admin
ARG KEYCLOAK_ADMIN_PASWORD=admin

ENV  KEYCLOAK_ADMIN=$KEYCLOAK_ADMIN_USER
ENV  KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASWORD
ENV  KC_FEATURES=preview
ENV  KC_LOG="console,gelf"
ENV  KC_LOG_CONSOLE_COLOR=true
ENV  KC_LOG_CONSOLE_FORMAT="[%p] %d{yyyy-MM-dd HH:mm:ss,SSS} thread:[%-25.25t] [%c]  %s %n"
ENV  KC_LOG_CONSOLE_OUTPUT=json
ENV  KC_LOG_GELF_FACILITY=keycloak
ENV  KC_LOG_GELF_HOST=host.docker.internal
ENV  KC_LOG_GELF_INCLUDE_STACK_TRACE=true
ENV  KC_LOG_GELF_LEVEL=INFO
ENV  KC_LOG_GELF_MAX_MESSAGE_SIZE=8192
ENV  KC_LOG_GELF_PORT=12201
ENV  KC_LOG_LEVEL=INFO

COPY ./target/keycloak-spi*.jar /opt/bitnami/keycloak/providers/
ENTRYPOINT ["/opt/bitnami/keycloak/bin/kc.sh", "start-dev"]
