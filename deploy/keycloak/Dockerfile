# Keep the upstream distribution and licenses; replace only its runtime and Guava.
FROM quay.io/keycloak/keycloak:26.8.2@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b AS upstream
FROM eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474

COPY --from=upstream --chown=1000:0 /opt/keycloak /opt/keycloak
# Quarkus records this path in its application model. Keep the path, but retain
# the new JAR's unmodified manifest and Maven metadata (33.7.2-jre).
ADD --checksum=sha256:b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c --chown=1000:0 --chmod=0644 https://repo.maven.apache.org/maven2/com/google/guava/guava/33.7.2-jre/guava-33.7.2-jre.jar /opt/keycloak/lib/lib/main/com.google.guava.guava-33.6.0-jre.jar
RUN apk --no-network del gnupg \
    && unzip -p /opt/keycloak/lib/lib/main/com.google.guava.guava-33.6.0-jre.jar META-INF/maven/com.google.guava/guava/pom.properties | grep -Fx 'version=33.7.2-jre' \
    && ! apk --no-network info -e sqlite-libs \
    && chmod -R g=u /opt/keycloak
# Verify the affected roots are absent; fail if keytool cannot read the store.
RUN keytool -list -v -cacerts -storepass changeit > /tmp/truststore.txt \
    && ! grep -E 'Owner:.*(AAA Certificate Services|emSign ECC Root CA - G3)' /tmp/truststore.txt \
    && rm /tmp/truststore.txt

ENV KC_RUN_IN_CONTAINER=true
WORKDIR /opt/keycloak
USER 1000:0
RUN /opt/keycloak/bin/kc.sh build --db=dev-file
EXPOSE 8080 8443 9000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
