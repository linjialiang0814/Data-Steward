# Data Steward App

Flutter client for the multi-device data management assistant.

## Android debug build on the current Windows development environment

Direct access to Google Maven may time out on the current network. The build
entry point installs an opt-in Gradle init script under
`%USERPROFILE%/.gradle/init.d`. It injects the configured Google Maven, Gradle
Plugin, and Maven Central mirrors into both the application build and Flutter's
included Gradle build without modifying the Flutter SDK.

Run from PowerShell:

```powershell
cd <PROJECT_ROOT>\apps\steward_app
.\tool\build_android_debug.ps1
```

The script:

1. uses the default `%USERPROFILE%\.gradle` cache;
2. installs `android/gradle/repository-mirrors.init.gradle` into Gradle's
   user-level `init.d` directory;
3. activates it only for this command with
   `-DdataSteward.useGoogleMirror=true`, so other Gradle builds are unaffected;
4. uses `pub.flutter-io.cn` and `storage.flutter-io.cn` only when the
   corresponding Flutter mirror environment variables are not already set;
5. routes the `io.flutter` Gradle group exclusively through the selected
   Flutter storage repository, avoiding accidental fallback to Google Maven;
6. builds the debug APK once;
7. prints the APK path, size, and SHA-256 after successful verification.

Do not run a second build concurrently while dependencies are being
downloaded.
