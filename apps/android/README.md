# Android app

Release only. ABI splits produce:

- `app-arm64-v8a-release.apk`
- `app-armeabi-v7a-release.apk`
- `app-x86_64-release.apk`
- `app-universal-release.apk`

```text
cd apps\android
npm install
npm run sync-www
# stage libaether.so into jniLibs/arm64-v8a, armeabi-v7a, x86_64
cd android
gradlew assembleRelease
```
