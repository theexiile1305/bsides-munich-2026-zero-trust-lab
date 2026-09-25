FROM dhi.io/maven:3.9-jdk21-alpine3.24-dev@sha256:2e77148752427a9c5c1e715c9998847f43ae0c4878f214dfb2b828446059ee6e AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c
COPY --from=build /src/target/keycloak-spiffe-client-auth-1.0.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
