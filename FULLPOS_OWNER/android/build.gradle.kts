import com.android.build.gradle.LibraryExtension
import org.gradle.api.JavaVersion

allprojects {
    repositories {
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

// AGP 8+ requiere `namespace` en módulos Android. Algunos plugins antiguos no lo declaran.
// Forzamos namespace para evitar fallo de compilación en release.
subprojects {
    plugins.withId("com.android.library") {
        if (project.name == "image_gallery_saver") {
            extensions.configure<LibraryExtension> {
                namespace = "com.fullpos.image_gallery_saver"
                compileOptions {
                    sourceCompatibility = JavaVersion.VERSION_17
                    targetCompatibility = JavaVersion.VERSION_17
                }
            }
        }
        if (project.name == "image_gallery_saver_plus") {
            extensions.configure<LibraryExtension> {
                namespace = "com.fullpos.image_gallery_saver_plus"
                compileOptions {
                    sourceCompatibility = JavaVersion.VERSION_17
                    targetCompatibility = JavaVersion.VERSION_17
                }
            }
        }
    }
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
