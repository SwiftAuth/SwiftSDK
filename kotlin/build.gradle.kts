plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "net.swiftauth"
version = "1.0.0"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("AppKt")
}

sourceSets {
    main {
        kotlin.srcDirs("src/main/kotlin", "example")
    }
}
