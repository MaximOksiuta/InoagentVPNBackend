FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app

COPY gradlew gradlew
COPY gradle gradle
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
RUN chmod +x gradlew

COPY src src
RUN ./gradlew installDist --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /app

COPY --from=builder /app/build/install/kotlin /app

RUN mkdir -p /app/data && useradd --system --create-home --uid 10001 appuser && chown -R appuser:appuser /app

USER appuser

ENV HOST=0.0.0.0
ENV PORT=8080
ENV SQLITE_PATH=/app/data/app.db

EXPOSE 8080

CMD ["/app/bin/kotlin"]
