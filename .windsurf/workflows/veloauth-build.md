---
description: Builds VeloAuth using Maven with Java 21 Virtual Threads
auto_execution_mode: 0
---

1. Environment Setup
   - **Java 21** required (Virtual Threads support): `java -version`
   - **Maven** build system (`pom.xml`)
   - **Velocity API 3.4.0-SNAPSHOT** dependency

2. Build Commands
   - **Fast build** (skip tests): `mvnd clean package -DskipTests`
   - **Full build** (with tests): `mvnd clean test` or `mvnd clean package`
   - **Coverage report**: `mvnd clean test jacoco:report` (view at `target/site/jacoco/index.html`)
   - **Fallback**: Use `mvn` if `mvnd` not available

3. Build Output
   - **Shaded plugin JAR** (install this): `target/veloauth-<version>.jar`
   - **Original JAR** (reference): `target/original-veloauth-<version>.jar`
   - **Test reports**: `target/surefire-reports/`
   - **Coverage reports**: `target/site/jacoco/`

4. Dependency Shading (Maven Shade Plugin)
   The build relocates dependencies to prevent conflicts:
   - `org.bstats` → `net.rafalohaki.veloauth.libs.bstats`
   - `com.j256.ormlite` → `net.rafalohaki.veloauth.libs.ormlite`
   - `at.favre.lib.crypto` → `net.rafalohaki.veloauth.libs.bcrypt`
   - `com.fasterxml.jackson` → `net.rafalohaki.veloauth.libs.jackson`

5. Database Drivers Included
   - MySQL Connector J 9.5.0
   - PostgreSQL 42.7.8
   - H2 Database 2.4.240
   - SQLite 3.51.1.0

6. Development Notes
   - Uses **Virtual Threads** (Java 21) - all async operations use `VirtualThreadExecutorProvider`
   - **JaCoCo** coverage reporting enabled
   - **Compiler warnings**: deprecation and unchecked linting enabled
   - **Test JVM args**: includes opens for reflection and dynamic agent loading
   - **SQL Driver services**: automatically merged via shade plugin transformer
