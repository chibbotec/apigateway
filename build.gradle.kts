plugins {
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
    java
}

group = "com.ll.chibbo"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

extra["springCloudVersion"] = "2023.0.0"

dependencies {
    // Spring Cloud Gateway
    implementation("org.springframework.cloud:spring-cloud-starter-gateway")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.security:spring-security-config")
    implementation("org.springframework.security:spring-security-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")

    // JWT Support
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")

    // Lombok
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    // Spring Boot Test
    testImplementation("org.springframework.boot:spring-boot-starter-test")

    // webClient
    implementation ("org.springframework.boot:spring-boot-starter-webflux")

    //actuator 설정
    implementation ("org.springframework.boot:spring-boot-starter-actuator")

    //docker-compose
//    developmentOnly("org.springframework.boot:spring-boot-docker-compose")

    // Spring Boot Admin 클라이언트 의존성
    implementation ("de.codecentric:spring-boot-admin-starter-client:3.1.7")

    // 모니터링 도구들
    implementation ("io.micrometer:micrometer-registry-prometheus")

    // Zipkin 분산 추적을 위한 의존성 (Spring Boot 3.x)
    implementation("io.micrometer:micrometer-tracing-bridge-otel")
    implementation("io.opentelemetry:opentelemetry-exporter-zipkin")

    //redis
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("io.lettuce.core:lettuce-core")

    // JPA 쿼리 모니터링을 위한 도구들
//    implementation ("com.github.gavlyukovskiy:p6spy-spring-boot-starter:1.9.0")
//    implementation ("com.github.gavlyukovskiy:datasource-proxy-spring-boot-starter:1.9.0")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}