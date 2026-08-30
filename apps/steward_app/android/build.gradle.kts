val flutterStorageBaseUrl =
    System.getenv("FLUTTER_STORAGE_BASE_URL")?.trimEnd('/')
        ?: "https://storage.googleapis.com"

allprojects {
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "FlutterStorage"
                    url = uri("$flutterStorageBaseUrl/download.flutter.io")
                }
            }
            filter {
                includeGroup("io.flutter")
            }
        }
        maven {
            url = uri("https://maven.aliyun.com/repository/google")
        }
        maven {
            url = uri("https://maven.aliyun.com/repository/public")
        }
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
