FROM maven:3.9.11-eclipse-temurin-17
WORKDIR .
COPY . .
RUN mvn install
CMD ["mvn", "-pl", "api", "spring-boot:run"]
