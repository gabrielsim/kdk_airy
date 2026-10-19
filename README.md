# KDK Airy for Home Assistant
Home Assistant custom integration to control KDK Airy fan (and light), locally over your network where possible and through the KDK cloud otherwise.

> [!NOTE]
> This is an unofficial, community-made integration. It is not affiliated with, endorsed by or supported by KDK or Panasonic. It uses the same cloud service and local protocol as the official KDK Ceiling Fan app, so a change on KDK's side can break it without notice. KDK and the KDK logo are trademarks of their owner.

## Requirements
- Home Assistant 2024.8 or newer. The integration icon shows from Home Assistant 2026.3.
- A KDK account with your fans registered in the official KDK Ceiling Fan app.

## Supported Devices
Tested models:
- KDK Airy E48HP (without light)
- KDK Airy E48GP (with light)
- KDK Airy H56GP (with light)
- KDK Airy F40GP (with light)
- KDK K12UC (with light)
- Product code `48INCH-LED` (with light)

Every other fan registered to your KDK account is added too. Whether it has a light is worked out from its first reply, and the light entity appears once that's known. An untested model logs a warning at startup; if it doesn't work, please [report it](#reporting-a-problem) with its product code.

## Installation
### Via HACS
[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=gabrielsim&repository=kdk_airy&category=integration)

Click the button above to open KDK Airy in HACS on your Home Assistant, then download it and restart Home Assistant. Or add it by hand:

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

The list of fans is read when the integration starts. After adding a fan in the KDK app, reload the integration: **Settings > Devices & services > KDK Airy > ⋮ > Reload**.

If you change your KDK password, Home Assistant asks for the new one under **Settings > Devices & services**.

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
- Fan speed can be set at 10% intervals, rounded up, i.e. 82% -> 90%. 0% turns the fan off.
- Fan direction can be set (forward/reverse).

### Light
- Light brightness can be set at 10% intervals, rounded up, i.e. 82% -> 90%.
- Light temperature can be changed.
- Light brightness at 10% / 20% / 30% is reserved for night light feature and corresponds to Low / Medium / High night light.

## Actions
### `kdk_airy.set_fan_and_light`
Changes a fan and its light together in **one** command: one round trip and one beep, where calling `fan.turn_on` and `light.turn_on` separately takes two. Target the fan entity. Any field left out keeps its current value; 0% turns that part off. The "last" settings come from the fan itself, which remembers them while off, so changes made with the remote control are included. An explicit speed or brightness wins over `fan_on` / `light_on`.

| Field | Values |
|---|---|
| `fan_on` | `true`: on at its last speed and direction. `false`: off |
| `light_on` | `true`: on exactly as last left (normal at its last brightness and colour, or night light at its last level). `false`: off |
| `fan_percentage` | 0-100, in 10% steps, rounded up. 0 turns the fan off |
| `fan_direction` | `forward` / `reverse` |
| `light_brightness_pct` | 0-100, in 10% steps, rounded up. 0 turns the light off; 10 / 20 / 30 are night light low / medium / high |
| `light_color_temp_kelvin` | 3000 (warm) - 7000 (white). Not available with night light |

For example, a wall switch that toggles a fan and its light together:

```yaml
actions:
  - if:
      - condition: state
        entity_id: light.bedroom
        state: "off"
      - condition: state
        entity_id: fan.bedroom
        state: "off"
    then:
      - action: kdk_airy.set_fan_and_light
        target:
          entity_id: fan.bedroom
        data:
          fan_on: true
          light_on: true
    else:
      - action: kdk_airy.set_fan_and_light
        target:
          entity_id: fan.bedroom
        data:
          fan_on: false
          light_on: false
```

## Troubleshooting
- To see what the integration is doing, including whether fans are reached locally, turn on debug logging. Add this to `configuration.yaml` and restart:

    ```yaml
    logger:
      logs:
        custom_components.kdk_airy: debug
    ```

    It logs how many fans were found on the LAN and any fallback to the cloud. Remove it again afterwards; it is verbose.
- If entity is marked as unavailable/no response, it likely means that switch is off or wi-fi is disconnected (press the wifi button on the remote control).

## Reporting a problem
Please [open an issue](https://github.com/gabrielsim/kdk_airy/issues) with:
- Your Home Assistant version and the integration version (**Settings > Devices & services > KDK Airy**).
- The fan's model or product code (logged at startup for untested models).
- Whether Home Assistant runs on Home Assistant OS, Docker or another install, and whether the fans are on the same network.
- What you did, what you expected, and what happened instead.
- The debug log around the problem (see [Troubleshooting](#troubleshooting)). Check it for anything personal, such as your email address, before posting.

## License
MIT, see [LICENSE](LICENSE). This covers the code only, not the KDK name or logo.

## Known issues / PR is welcome
- Light temperature (degrees of Kelvin _K_) is approximated.
- Close to (but not) realtime sync on fan status: the fans don't push changes, so status is polled every 5s (15s for any fan only reachable through the cloud). A change made with the remote control shows up at the next poll.
