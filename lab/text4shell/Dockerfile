# Cible de labo : commons-text 1.9 (vulnérable) ou 1.10.0 (corrigée) selon COMMONS_TEXT.
FROM eclipse-temurin:17-jdk-alpine AS build
ARG COMMONS_TEXT=1.9
ARG COMMONS_LANG=3.12.0
WORKDIR /app
RUN wget -q https://repo1.maven.org/maven2/org/apache/commons/commons-text/${COMMONS_TEXT}/commons-text-${COMMONS_TEXT}.jar \
 && wget -q https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/${COMMONS_LANG}/commons-lang3-${COMMONS_LANG}.jar
COPY App.java .
RUN javac -cp "*" App.java

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app /app
EXPOSE 8080
CMD ["java", "-cp", ".:*", "App"]
