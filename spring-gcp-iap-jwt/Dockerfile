FROM maven:3.6.3 as maven

WORKDIR /usr/src/app
COPY ./ /usr/src/app
RUN mvn package

FROM openjdk:17.0.2-slim
EXPOSE 8008
RUN mkdir /app
COPY --from=maven /usr/src/app/target/spring-gcp-poc-1.0.0-SNAPSHOT.jar /app/spring-gcp-poc-1.0.0-SNAPSHOT.jar
CMD ["java", "-Dlogging.level.org.springframework=INFO", "-jar", "/app/spring-gcp-poc-1.0.0-SNAPSHOT.jar"]