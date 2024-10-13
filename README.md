# KDK Airy for Home Assistant
Home Assistant custom integration to control KDK Airy fan (and light) over the internet.

## Supported Devices
- KDK Airy E48HP (without light)
- KDK Airy E48GP (with light)

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

## Supported features
### Fan
- Fan speed can be set at 10% intervals, rounded up, i.e. 82% -> 90%.
- Fan direction can be set (forward/reverse).

### Light
- Light brightness can be set at 10% intervals, rounded up, i.e. 82% -> 90%.
- Light temperature can be changed.
- Light brightness at 10% / 20% / 30% is reserved for night light feature and corresponds to Low / Medium / High night light.

## Troubleshooting
- If entity is marked as unavailable/no response, it likely means that switch is off or wi-fi is disconnected (press the wifi button on the remote control).

## Known issues / PR is welcome
- Light temperature (degrees of Kelvin _K_) is approximated.
- Close to (but not) realtime sync on fan status, polls for current fan status every 15s.