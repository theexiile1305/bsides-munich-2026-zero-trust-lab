FROM dhi.io/maven:3.9-jdk21-alpine3.24-dev@sha256:2e77148752427a9c5c1e715c9998847f43ae0c4878f214dfb2b828446059ee6e AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:26.8.2@sha256:22f1cf60e26bed1808e45b838ddeac962075818fe97e0858b542308d2b91e83e
COPY --from=build /src/target/keycloak-spiffe-client-auth-1.0.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
