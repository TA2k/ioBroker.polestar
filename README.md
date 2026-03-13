![Logo](admin/polestar.png)
# ioBroker.polestar

[![NPM version](https://img.shields.io/npm/v/iobroker.polestar.svg)](https://www.npmjs.com/package/iobroker.polestar)
[![Downloads](https://img.shields.io/npm/dm/iobroker.polestar.svg)](https://www.npmjs.com/package/iobroker.polestar)
![Number of Installations](https://iobroker.live/badges/polestar-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/polestar-stable.svg)

[![NPM](https://nodei.co/npm/iobroker.polestar.png?downloads=true)](https://nodei.co/npm/iobroker.polestar/)

**Tests:** ![Test and Release](https://github.com/TA2k/ioBroker.polestar/workflows/Test%20and%20Release/badge.svg)

## polestar adapter for ioBroker

ioBroker Adapter for Polestar vehicles.

## Features

- Vehicle information (model, VIN, battery capacity, etc.)
- Battery status (charge level, charging status, estimated range)
- Odometer data
- Health status (service warnings, days to service)
- Automatic token refresh
- Manual refresh via remote control state

## Configuration

| Setting | Description |
|---------|-------------|
| Email | Polestar account email |
| Password | Polestar account password |
| Interval | Update interval in seconds (minimum 60) |

## States

### Battery
- `batteryChargeLevelPercentage` - Current charge level (%)
- `chargingStatus` - Charging status (Idle, Charging, Done, etc.)
- `estimatedDistanceToEmptyKm` - Estimated range (km)
- `estimatedFullChargeRangeKm` - Calculated range at 100% (km)
- `estimatedChargingTimeToFullMinutes` - Time to full charge (min)
- `estimatedFullyChargedTime` - Estimated full charge timestamp

### Odometer
- `odometerMeters` - Odometer (m)
- `odometerKm` - Odometer (km)

### Health
- `daysToService` - Days until next service
- `distanceToServiceKm` - Distance until next service (km)
- `serviceWarning` - Service warning status
- `brakeFluidLevelWarning` - Brake fluid warning
- `engineCoolantLevelWarning` - Coolant level warning
- `oilLevelWarning` - Oil level warning

### Remote
- `refresh` - Trigger manual data refresh

## State Paths

All states are located under `polestar.0.<VIN>.*`. Example paths:

```text
polestar.0.YSMVSEGEXPL110548.battery.batteryChargeLevelPercentage
polestar.0.YSMVSEGEXPL110548.battery.chargingStatus
polestar.0.YSMVSEGEXPL110548.battery.estimatedDistanceToEmptyKm
polestar.0.YSMVSEGEXPL110548.odometer.odometerKm
polestar.0.YSMVSEGEXPL110548.health.daysToService
polestar.0.YSMVSEGEXPL110548.remote.refresh
```

## State Values

### chargingStatus

| Value | Description |
|-------|-------------|
| `CHARGING_STATUS_IDLE` | Not charging |
| `CHARGING_STATUS_CHARGING` | Currently charging |
| `CHARGING_STATUS_DONE` | Charging complete |
| `CHARGING_STATUS_SCHEDULED` | Scheduled charging |
| `CHARGING_STATUS_SMART_CHARGING` | Smart charging active |
| `CHARGING_STATUS_FAULT` | Charging fault |
| `CHARGING_STATUS_ERROR` | Charging error |

### serviceWarning

| Value | Description |
|-------|-------------|
| `SERVICE_WARNING_NO_WARNING` | No service needed |
| `SERVICE_WARNING_SERVICE_REQUIRED` | Service required |
| `SERVICE_WARNING_REGULAR_MAINTENANCE_ALMOST_TIME_FOR_SERVICE` | Service soon |
| `SERVICE_WARNING_REGULAR_MAINTENANCE_TIME_FOR_SERVICE` | Time for service |
| `SERVICE_WARNING_REGULAR_MAINTENANCE_OVERDUE_FOR_SERVICE` | Service overdue |

### Warning States (brakeFluidLevelWarning, engineCoolantLevelWarning, oilLevelWarning)

| Value | Description |
|-------|-------------|
| `*_NO_WARNING` | No warning |
| `*_TOO_LOW` | Level too low |
| `*_TOO_HIGH` | Level too high (oil only) |

## Scripting Examples

### JavaScript: Check Battery and Send Notification

```javascript
// Check battery level every hour and notify if low
on({ id: 'polestar.0.*.battery.batteryChargeLevelPercentage', change: 'ne' }, function (obj) {
    if (obj.state.val < 20) {
        sendTo('telegram.0', {
            text: `Polestar Akku niedrig: ${obj.state.val}%`
        });
    }
});
```

### JavaScript: Log Charging Status Changes

```javascript
on({ id: 'polestar.0.*.battery.chargingStatus', change: 'ne' }, function (obj) {
    const statusMap = {
        'CHARGING_STATUS_IDLE': 'Nicht laden',
        'CHARGING_STATUS_CHARGING': 'Laden',
        'CHARGING_STATUS_DONE': 'Vollgeladen',
        'CHARGING_STATUS_SCHEDULED': 'Geplant'
    };
    log(`Polestar Ladestatus: ${statusMap[obj.state.val] || obj.state.val}`);
});
```

### JavaScript: Calculate Daily Driving Distance

```javascript
// Save odometer at midnight and calculate daily distance
schedule('0 0 * * *', function () {
    const odometer = getState('polestar.0.YSMVSEGEXPL110548.odometer.odometerKm').val;
    const yesterday = getState('0_userdata.0.polestar.lastOdometer').val || odometer;
    const distance = odometer - yesterday;

    setState('0_userdata.0.polestar.lastOdometer', odometer, true);
    setState('0_userdata.0.polestar.dailyDistance', distance, true);

    log(`Heute gefahren: ${distance} km`);
});
```

### JavaScript: Charging Complete Notification with Time

```javascript
on({ id: 'polestar.0.*.battery.chargingStatus', val: 'CHARGING_STATUS_DONE' }, function (obj) {
    const battery = getState(obj.id.replace('chargingStatus', 'batteryChargeLevelPercentage')).val;
    const range = getState(obj.id.replace('chargingStatus', 'estimatedDistanceToEmptyKm')).val;

    sendTo('pushover.0', {
        message: `Polestar vollgeladen!\nAkku: ${battery}%\nReichweite: ${range} km`,
        title: 'Ladevorgang beendet'
    });
});
```

### JavaScript: Service Reminder

```javascript
// Check service status daily
schedule('0 8 * * *', function () {
    const daysToService = getState('polestar.0.YSMVSEGEXPL110548.health.daysToService').val;
    const kmToService = getState('polestar.0.YSMVSEGEXPL110548.health.distanceToServiceKm').val;

    if (daysToService < 30 || kmToService < 1000) {
        sendTo('email.0', {
            to: 'user@example.com',
            subject: 'Polestar Service bald faellig',
            text: `Service in ${daysToService} Tagen oder ${kmToService} km`
        });
    }
});
```

### Blockly: Battery Low Warning

Use the following trigger in Blockly:

- Trigger: `polestar.0.*.battery.batteryChargeLevelPercentage`
- Condition: Value < 20
- Action: Send notification

### VIS Widget Binding

```text
{polestar.0.YSMVSEGEXPL110548.battery.batteryChargeLevelPercentage} %
{polestar.0.YSMVSEGEXPL110548.battery.estimatedDistanceToEmptyKm} km
```

## Changelog
<!--
    Placeholder for the next version (at the beginning of the line):
    ### **WORK IN PROGRESS**
-->
### 1.0.1 (2026-03-13)

* (TA2k) Adapt to Polestar API changes - remove unavailable fields (fixes #13)
* (TA2k) Split vehicle fetch into minimal + full request for robustness
* (TA2k) Add Terms & Conditions auto-acceptance in login flow
* (TA2k) Detect GraphQL UNAUTHENTICATED errors in HTTP 200 responses

### 1.0.0 (2026-02-12)
* (TA2k) initial release based on website data

## License
MIT License

Copyright (c) 2026 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.