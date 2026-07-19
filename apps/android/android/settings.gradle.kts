pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        // Some networks / caches flake on google() — direct path as fallback.
        maven(url = "https://maven.google.com/")
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven(url = "https://maven.google.com/")
    }
}
rootProject.name = "AetherNext"
include(":app")
