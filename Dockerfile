FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app

ENV GRADLE_USER_HOME=/app/.gradle
ENV GRADLE_OPTS="-Dorg.gradle.daemon=false -Dorg.gradle.parallel=false -Dorg.gradle.workers.max=1 -Dorg.gradle.jvmargs='-Xmx512m -XX:MaxMetaspaceSize=256m -Dfile.encoding=UTF-8'"

COPY gradlew gradlew
COPY gradle gradle
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
RUN chmod +x gradlew
RUN ./gradlew --version --no-daemon

COPY src src
RUN ./gradlew installDist initAdminStartScripts repairDuplicateIpsStartScripts --no-daemon --max-workers=1 --stacktrace
RUN cp /app/build/init-admin-scripts/init_admin /app/build/install/kotlin/bin/init_admin \
    && cp /app/build/init-admin-scripts/init_admin.bat /app/build/install/kotlin/bin/init_admin.bat \
    && cp /app/build/repair-duplicate-ips-scripts/repair_duplicate_ips /app/build/install/kotlin/bin/repair_duplicate_ips \
    && cp /app/build/repair-duplicate-ips-scripts/repair_duplicate_ips.bat /app/build/install/kotlin/bin/repair_duplicate_ips.bat

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
