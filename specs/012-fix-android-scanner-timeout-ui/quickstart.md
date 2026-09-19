# Quickstart: Validating Scanner Execution & Mobile Terminal Header UI

**Feature**: `012-fix-android-scanner-timeout-ui`
**Status**: Ready

This guide details steps to validate that standalone endpoint scans run indefinitely without premature connection timeouts, and that the mobile terminal window header renders without clipping or text wrapping.

---

## 1. Prerequisites & Environment Setup

- Node.js 18+ and npm installed.
- Android SDK & JDK 17 configured (for Android APK / Kotlin builds).
- Rust 1.88+ installed (for `aether` engine verification).

---

## 2. Verification Scenarios

### Scenario 1: Standalone Scan Endurance (Exceeding Connection Timeouts)

**Objective**: Ensure starting a scan does not trigger the 90s connection watchdog or terminate prematurely at 300s/600s.

1. **Start the Android App / Web Preview**:
   ```bash
   cd apps/android
   npm run dev
   ```
2. **Launch a Standalone Scan**:
   - Navigate to the **Scanner** tab.
   - Select protocol `MASQUE (H3)` or `WireGuard`.
   - Set concurrency to `250` and timeout to `3000ms`.
   - Tap **Start Scan**.
3. **Verify State & Timing**:
   - Observe the top status bar / header: it must NOT show a yellow `● CONNECTING` badge. It remains `● READY` or disconnected.
   - Keep the scan running for > 90 seconds (past the 90s `CONNECT_WATCHDOG_MS` limit) and > 300 seconds.
   - **Expected Outcome**: The scan continues uninterrupted, actively streaming discoveries (`scan_progress`, `scan_hit`) until completion or until the user taps **Stop Scan**. No "Connection timed out" alert appears.

---

### Scenario 2: Mobile Terminal Header Responsive Bounds & Layout

**Objective**: Verify that the terminal window chrome header in the Activity tab does not wrap words vertically or clip action buttons on mobile screens.

1. **Emulate Mobile Viewport**:
   - In Chrome DevTools (or on an Android device), set the device viewport to a standard mobile width (e.g. 360px × 800px, 390px × 844px, or 412px × 915px).
2. **Navigate to Activity Tab**:
   - Open the **Activity** tab while a scan is running or idle.
3. **Inspect the Header Chrome**:
   - **Controls (Left)**: Verify the window dots (red, yellow, green) and `aether@android:~# session-log` are on a single line without breaking.
   - **Telemetry (Right)**: Verify the stream counter (`2 shown / 15 buffer`) is displayed cleanly on a single line, with no individual words wrapped vertically.
   - **Action Buttons**: Verify the action buttons (`Follow`, `Copy Buffer`, `Clear`) are aligned neatly on the second row, fully within the card chassis, with no clipped text ("Copy Buffe") and comfortable touch heights (>= 30px).
4. **Test Copy Action**:
   - Tap **Copy Buffer**.
   - **Expected Outcome**: The button smoothly transitions to `Copied` with a checkmark icon, without shifting or wrapping neighboring elements out of bounds.

---

### Scenario 3: Scan Cancellation & Direct Connect

**Objective**: Verify that stopping a scan or connecting directly from a discovered endpoint transitions cleanly without error dialogs.

1. While a scan is running, tap **Stop Scan**.
   - **Expected Outcome**: The scan transitions to `Stopped`, keeping all discovered endpoints intact. No error alert is generated.
2. On any discovered endpoint card, tap **Connect Direct**.
   - **Expected Outcome**: The app initiates the tunnel connection, now appropriately setting `Connecting` and arming the connection handshake watchdog.

---

## 3. Build & Compilation Commands

- **Android Frontend Bundle**:
  ```bash
  cd apps/android && npm run build
  ```
- **Android Kotlin Compilation**:
  ```bash
  cd apps/android/android && ./gradlew compileDebugKotlin
  ```
- **Rust Engine Check**:
  ```bash
  cd aether && cargo check
  ```
