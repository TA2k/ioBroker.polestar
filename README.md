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

## Changelog
<!--
    Placeholder for the next version (at the beginning of the line):
    ### **WORK IN PROGRESS**
-->

### **WORK IN PROGRESS**
* (TA2k) initial release

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