'use strict';

const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const crypto = require('crypto');
const Json2iob = require('json2iob');
const descriptions = require('./lib/descriptions.json');
const states = require('./lib/states.json');

class Polestar extends utils.Adapter {
    constructor(options) {
        super({
            ...options,
            name: 'polestar',
        });

        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload', this.onUnload.bind(this));

        this.json2iob = new Json2iob(this);
        this.session = null;
        this.vehicles = [];
        this.updateInterval = null;
        this.refreshTokenInterval = null;

        const jar = new CookieJar();
        this.requestClient = wrapper(
            axios.create({
                withCredentials: true,
                timeout: 60000,
                jar,
                headers: {
                    'user-agent':
                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
                    'accept-language': 'de;q=0.8',
                },
            }),
        );
    }

    async onReady() {
        this.setState('info.connection', false, true);

        if (this.config.interval < 60) {
            this.log.info('Set interval to minimum 60');
            this.config.interval = 60;
        }

        if (!this.config.email || !this.config.password) {
            this.log.error('Please set email and password in the instance settings');
            return;
        }

        this.subscribeStates('*');

        await this.login();
        if (!this.session) {
            return;
        }

        await this.getVehicles();
        await this.updateVehicleData();

        this.updateInterval = setInterval(async () => {
            await this.updateVehicleData();
        }, this.config.interval * 1000);

        this.startRefreshTokenInterval();
    }

    startRefreshTokenInterval() {
        this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
        const refreshIn = ((this.session?.expires_in || 300) - 30) * 1000;
        this.log.debug(`Token refresh scheduled in ${Math.round(refreshIn / 1000)} seconds`);
        this.refreshTokenInterval = setInterval(async () => {
            await this.refreshToken();
        }, refreshIn);
    }

    async login() {
        try {
            const state = crypto.randomBytes(16).toString('hex');
            const codeVerifier = this.generateRandomString();
            const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

            const authResponse = await this.requestClient({
                method: 'get',
                url: 'https://polestarid.eu.polestar.com/as/authorization.oauth2',
                params: {
                    client_id: 'l3oopkc_10',
                    redirect_uri: 'https://www.polestar.com/sign-in-callback',
                    response_type: 'code',
                    scope: 'openid profile email customer:attributes customer:attributes:write',
                    state,
                    code_challenge: codeChallenge,
                    code_challenge_method: 'S256',
                    response_mode: 'query',
                    acr_values: 'urn:volvoid:aal:bronze:any',
                    language: 'de',
                    market: 'de',
                },
                headers: {
                    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                },
                maxRedirects: 0,
                validateStatus: () => true,
            });

            const pathToken = authResponse.data.match(/action: "\/as\/([^/]+)\/resume/)?.[1];
            if (!pathToken) {
                this.log.error('Failed to get login flow tokens');
                return;
            }

            const loginResponse = await this.requestClient({
                method: 'post',
                url: `https://polestarid.eu.polestar.com/as/${pathToken}/resume/as/authorization.ping`,
                params: { client_id: 'l3oopkc_10' },
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                },
                data: {
                    'pf.username': this.config.email,
                    'pf.pass': this.config.password,
                },
                maxRedirects: 0,
                validateStatus: () => true,
            });

            const code = loginResponse.headers.location?.match(/code=([^&]+)/)?.[1];
            if (!code) {
                this.log.error('Login failed - check credentials');
                return;
            }

            const tokenResponse = await this.requestClient({
                method: 'post',
                url: 'https://polestarid.eu.polestar.com/as/token.oauth2',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: {
                    grant_type: 'authorization_code',
                    redirect_uri: 'https://www.polestar.com/sign-in-callback',
                    code,
                    code_verifier: codeVerifier,
                    client_id: 'l3oopkc_10',
                },
            });

            this.session = tokenResponse.data;
            this.log.info('Login successful');
            this.setState('info.connection', true, true);
        } catch (error) {
            this.log.error(`Login error: ${error.message}`);
        }
    }

    async refreshToken() {
        if (!this.session?.refresh_token) {
            this.log.warn('No refresh token, logging in again');
            await this.login();
            return;
        }

        try {
            const response = await this.requestClient({
                method: 'post',
                url: 'https://polestarid.eu.polestar.com/as/token.oauth2',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: {
                    grant_type: 'refresh_token',
                    client_id: 'l3oopkc_10',
                    refresh_token: this.session.refresh_token,
                },
            });

            if (response.data?.access_token) {
                this.session = response.data;
                this.log.info(`Token refreshed, expires in ${this.session.expires_in}s`);
                this.startRefreshTokenInterval();
            } else {
                this.log.warn('Token refresh failed, logging in again');
                await this.login();
            }
        } catch (error) {
            this.log.error(`Token refresh error: ${error.message}`);
            await this.login();
        }
    }

    async getVehicles() {
        if (!this.session) {
            return;
        }

        try {
            const response = await this.requestClient({
                method: 'post',
                url: 'https://pc-api.polestar.com/eu-north-1/mystar-v2/',
                headers: {
                    'content-type': 'application/json',
                    Authorization: `Bearer ${this.session.access_token}`,
                },
                data: {
                    operationName: 'GetConsumerCarsV2',
                    variables: {},
                    query: `query GetConsumerCarsV2 {
                        getConsumerCarsV2 {
                            vin
                            internalVehicleIdentifier
                            salesType
                            currentPlannedDeliveryDate
                            market
                            originalMarket
                            pno34
                            modelYear
                            registrationNo
                            metaOrderNumber
                            factoryCompleteDate
                            registrationDate
                            deliveryDate
                            serviceHistory {
                                claimType
                                market
                                mileage
                                mileageUnit
                                operations { id code description quantity performedDate }
                                orderEndDate
                                orderNumber
                                orderStartDate
                                parts { id code description quantity performedDate }
                                statusDMS
                                symptomCode
                                vehicleAge
                                workshopId
                            }
                            content {
                                exterior { code name description excluded }
                                exteriorDetails { code name description excluded }
                                interior { code name description excluded }
                                performancePackage { code name description excluded }
                                performanceOptimizationSpecification {
                                    power { value unit }
                                    torqueMax { value unit }
                                    acceleration { value unit description }
                                }
                                wheels { code name description excluded }
                                plusPackage { code name description excluded }
                                pilotPackage { code name description excluded }
                                motor { name description excluded }
                                model { name code }
                                specification {
                                    battery
                                    bodyType
                                    brakes
                                    combustionEngine
                                    electricMotors
                                    performance
                                    suspension
                                    tireSizes
                                    torque
                                    totalHp
                                    totalKw
                                    trunkCapacity { label value }
                                }
                                dimensions {
                                    wheelbase { label value }
                                    groundClearanceWithPerformance { label value }
                                    groundClearanceWithoutPerformance { label value }
                                    dimensions { label value }
                                }
                                towbar { code name description excluded }
                            }
                            primaryDriver
                            primaryDriverRegistrationTimestamp
                            owners { id registeredAt information { polestarId ownerType } }
                            wltpNedcData {
                                wltpCO2Unit
                                wltpElecEnergyConsumption
                                wltpElecEnergyUnit
                                wltpElecRange
                                wltpElecRangeUnit
                                wltpWeightedCombinedCO2
                                wltpWeightedCombinedFuelConsumption
                                wltpWeightedCombinedFuelConsumptionUnit
                            }
                            energy {
                                elecRange
                                elecRangeUnit
                                elecEnergyConsumption
                                elecEnergyUnit
                                weightedCombinedCO2
                                weightedCombinedCO2Unit
                                weightedCombinedFuelConsumption
                                weightedCombinedFuelConsumptionUnit
                            }
                            fuelType
                            drivetrain
                            numberOfDoors
                            numberOfSeats
                            motor { description code }
                            maxTrailerWeight { value unit }
                            curbWeight { value unit }
                            hasPerformancePackage
                            numberOfCylinders
                            cylinderVolume
                            cylinderVolumeUnit
                            transmission
                            numberOfGears
                            structureWeek
                            software {
                                version
                                versionTimestamp
                                performanceOptimization { value description timestamp }
                            }
                            latestClaimStatus { mileage mileageUnit registeredDate vehicleAge }
                            internalCar { origin registeredAt }
                            edition
                            commonStatusPoint { code timestamp description }
                            brandStatus { code timestamp description }
                            intermediateDestinationCode
                            partnerDestinationCode
                            features {
                                type
                                code
                                name
                                description
                                excluded
                                galleryImage { url alt }
                                thumbnail { url alt }
                            }
                            electricalEngineNumbers { number placement }
                        }
                    }`,
                },
            });

            this.log.debug(`getVehicles response: ${JSON.stringify(response.data)}`);
            this.vehicles = response.data.data?.getConsumerCarsV2 || [];
            if (!this.vehicles.length) {
                this.log.error('No vehicles found');
                this.log.error(`Response was: ${JSON.stringify(response.data)}`);
                return;
            }

            this.log.info(`Found ${this.vehicles.length} vehicle(s)`);

            for (const vehicle of this.vehicles) {
                await this.extendObject(vehicle.vin, {
                    type: 'device',
                    common: { name: vehicle.content?.model?.name || vehicle.vin },
                    native: {},
                });

                await this.setObjectNotExistsAsync(`${vehicle.vin}.remote`, {
                    type: 'channel',
                    common: { name: 'Remote Controls' },
                    native: {},
                });

                await this.extendObject(`${vehicle.vin}.remote.refresh`, {
                    type: 'state',
                    common: {
                        name: 'Refresh Data',
                        type: 'boolean',
                        role: 'button',
                        def: false,
                        write: true,
                        read: true,
                    },
                    native: {},
                });

                this.json2iob.parse(`${vehicle.vin}.general`, vehicle, { forceIndex: true, descriptions, states });
            }
        } catch (error) {
            this.log.error(`Get vehicles error: ${error.message}`);
        }
    }

    async updateVehicleData(retry = true) {
        if (!this.vehicles.length || !this.session) {
            return;
        }

        const vins = this.vehicles.map(v => v.vin);

        try {
            const response = await this.requestClient({
                method: 'post',
                url: 'https://pc-api.polestar.com/eu-north-1/mystar-v2/',
                headers: {
                    'content-type': 'application/json',
                    Authorization: `Bearer ${this.session.access_token}`,
                },
                data: {
                    operationName: 'CarTelematicsV2',
                    variables: { vins },
                    query: `query CarTelematicsV2($vins: [String!]!) {
  carTelematicsV2(vins: $vins) {
    battery {
      vin
      timestamp { seconds nanos }
      batteryChargeLevelPercentage
      chargingStatus
      estimatedChargingTimeToFullMinutes
      estimatedDistanceToEmptyKm
      estimatedDistanceToEmptyMiles
    }
    health {
      vin
      timestamp { seconds nanos }
      daysToService
      distanceToServiceKm
      serviceWarning
      brakeFluidLevelWarning
      engineCoolantLevelWarning
      oilLevelWarning
    }
    odometer {
      vin
      timestamp { seconds nanos }
      odometerMeters
    }
  }
}`,
                },
            });

            const data = response.data.data?.carTelematicsV2;
            if (data) {
                for (const battery of data.battery || []) {
                    // Add calculated fields
                    if (battery.batteryChargeLevelPercentage > 0 && battery.estimatedDistanceToEmptyKm > 0) {
                        battery.estimatedFullChargeRangeKm = Math.round(
                            (battery.estimatedDistanceToEmptyKm / battery.batteryChargeLevelPercentage) * 100,
                        );
                    }
                    if (battery.estimatedChargingTimeToFullMinutes > 0 && battery.batteryChargeLevelPercentage < 100) {
                        const fullChargeTime = new Date(
                            Date.now() + battery.estimatedChargingTimeToFullMinutes * 60000,
                        );
                        battery.estimatedFullyChargedTime = fullChargeTime.toISOString();
                    }
                    if (battery.timestamp?.seconds) {
                        battery.lastUpdate = new Date(battery.timestamp.seconds * 1000).toISOString();
                    }
                    this.json2iob.parse(`${battery.vin}.battery`, battery, { forceIndex: true, descriptions, states });
                }
                for (const odometer of data.odometer || []) {
                    // Add odometer in km
                    if (odometer.odometerMeters) {
                        odometer.odometerKm = Math.round(odometer.odometerMeters / 1000);
                    }
                    if (odometer.timestamp?.seconds) {
                        odometer.lastUpdate = new Date(odometer.timestamp.seconds * 1000).toISOString();
                    }
                    this.json2iob.parse(`${odometer.vin}.odometer`, odometer, {
                        forceIndex: true,
                        descriptions,
                        states,
                    });
                }
                for (const health of data.health || []) {
                    if (health.timestamp?.seconds) {
                        health.lastUpdate = new Date(health.timestamp.seconds * 1000).toISOString();
                    }
                    this.json2iob.parse(`${health.vin}.health`, health, { forceIndex: true, descriptions, states });
                }
            }
        } catch (error) {
            if (error.response?.status === 401 && retry) {
                this.log.warn('Token expired, refreshing...');
                await this.refreshToken();
                return this.updateVehicleData(false);
            }
            this.log.error(`Update vehicle data error: ${error.message}`);
        }
    }

    generateRandomString(length = 43) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    async onStateChange(id, state) {
        if (!state || state.ack) {
            return;
        }

        if (id.endsWith('.remote.refresh')) {
            this.log.info('Manual refresh triggered');
            await this.updateVehicleData();
            await this.setStateAsync(id, false, true);
        }
    }

    onUnload(callback) {
        try {
            this.setState('info.connection', false, true);
            this.updateInterval && clearInterval(this.updateInterval);
            this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
            callback();
        } catch {
            callback();
        }
    }
}

if (require.main !== module) {
    module.exports = options => new Polestar(options);
} else {
    new Polestar();
}
