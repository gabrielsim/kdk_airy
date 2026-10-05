# KDK Airy for Home Assistant
Home Assistant custom integration to control KDK Airy fan (and light), locally over your network where possible and through the KDK cloud otherwise.

## Supported Devices
- KDK Airy E48HP (without light)
- KDK Airy E48GP (with light)
- KDK Airy H56GP (with light)
- KDK Airy F40GP (with light)
- KDK K12UC (with light)

## Installation
### Via HACS
1. [HACS](https://hacs.xyz/) > Add Custom Repositories

    Repository: `gabrielsim/kdk_airy`<br>
    Type: `Integration`

2. Add KDK Airy

### Manual installation
Manually copy `kdk_airy` folder from [latest release](https://github.com/gabrielsim/kdk_airy/releases/latest) to `/config/custom_components` folder.

## Configuration
1. Ensure that you have registered your KDK fans to the official KDK Ceiling Fan app.
2. Install the integration and login with the same username/password as your KDK Ceiling Fan app.
3. Supported devices (fan/light) will be added to Home Assistant. The default entity names will follow the ones set in the KDK Ceiling Fan app.

## Local control
Fans on the same network as Home Assistant are controlled directly over the LAN, the same way the official app does when your phone is on home Wi-Fi. That means:
- Commands take effect in well under a second instead of several seconds.
- Fan status is polled every 5s instead of 15s.
- No dependency on the KDK cloud for day-to-day control.

The KDK account is still used to find your fans and their names, and as a fallback: any fan that can't be reached locally is controlled through the cloud exactly as before. This happens automatically, per fan, with nothing to configure.

Requirements for local control:
- Home Assistant must be on the same subnet as the fans. It finds them with a UDP broadcast on port 50125; they don't advertise over mDNS.
- Home Assistant needs host networking (Home Assistant OS and Supervised have it; for Docker, use `--network host`).
- UDP port 3610 must be free on the Home Assistant host. If another integration (e.g. ECHONET Lite) is using it, a warning is logged and the integration runs cloud-only.

## Supported features
### Fan
- Fan speed can be set at 10% intervals, rounded up, i.e. 82% -> 90%.
- Fan direction can be set (forward/reverse).

### Light
- Light brightness can be set at 10% intervals, rounded up, i.e. 82% -> 90%.
- Light temperature can be changed.
- Light brightness at 10% / 20% / 30% is reserved for night light feature and corresponds to Low / Medium / High night light.

## Troubleshooting
- To see whether fans are being reached locally, enable debug logging for `custom_components.kdk_airy`; it logs how many fans were found on the LAN and any fallback to the cloud.
- If entity is marked as unavailable/no response, it likely means that switch is off or wi-fi is disconnected (press the wifi button on the remote control).

## Known issues / PR is welcome
- Light temperature (degrees of Kelvin _K_) is approximated.
- Close to (but not) realtime sync on fan status: the fans don't push changes, so status is polled every 5s (15s for any fan only reachable through the cloud). A change made with the remote control shows up at the next poll.