'use strict';

const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const crypto = require('crypto');
const Json2iob = require('json2iob');
const descriptions = require('./lib/descriptions.json');
const states = require('./lib/states.json');
const GrpcClient = require('./lib/grpcClient');

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
        this.grpcClient = null;
        this.grpcAvailable = false;

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

        try {
            this.grpcClient = new GrpcClient(this.log);
            await this.grpcClient.connect();
            this.grpcAvailable = true;
            this.log.debug('gRPC client ready (TargetSoc)');
        } catch (e) {
            this.log.warn(`gRPC init failed (non-fatal, charge limit unavailable): ${e.message}`);
        }

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

            let code = loginResponse.headers.location?.match(/code=([^&]+)/)?.[1];

            // Handle Terms & Conditions acceptance
            if (!code) {
                const uid = loginResponse.headers.location?.match(/uid=([^&]+)/)?.[1];
                if (uid) {
                    this.log.info('Accepting updated Terms & Conditions...');
                    const tcResponse = await this.requestClient({
                        method: 'post',
                        url: `https://polestarid.eu.polestar.com/as/${pathToken}/resume/as/authorization.ping`,
                        params: { client_id: 'l3oopkc_10' },
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        data: { 'pf.submit': true, subject: uid },
                        maxRedirects: 0,
                        validateStatus: () => true,
                    });
                    code = tcResponse.headers.location?.match(/code=([^&]+)/)?.[1];
                }
            }

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
                this.log.debug(`Token refreshed, expires in ${this.session.expires_in}s`);
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

        // Step 1: Minimal request to get VINs - ensures adapter can start
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
                            registrationNo
                            modelYear
                            modelName
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
                    common: { name: vehicle.modelName || vehicle.vin },
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
            }
        } catch (error) {
            this.log.error(`Get vehicles error: ${error.message}`);
            return;
        }

        // Step 2: Full vehicle details - non-blocking, adapter continues if this fails
        await this.getVehicleDetails();
    }

    async getVehicleDetails() {
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
                            registrationNo
                            market
                            originalMarket
                            currentPlannedDeliveryDate
                            deliveryDate
                            edition
                            pno34
                            modelYear
                            modelName
                            commercialModelYear
                            computedModelYear
                            structureWeek
                            primaryDriver
                            userIsPrimaryDriver
                        }
                    }`,
                },
            });

            const vehicles = response.data.data?.getConsumerCarsV2 || [];
            for (const vehicle of vehicles) {
                this.json2iob.parse(`${vehicle.vin}.general`, vehicle, { forceIndex: true, descriptions, states });
            }
            this.log.debug('Vehicle details loaded');
        } catch (error) {
            this.log.warn(`Get vehicle details error (non-blocking): ${error.message}`);
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
      chargingStatusV2
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

            // Check for GraphQL UNAUTHENTICATED error in 200 response
            const gqlError = response.data.errors?.[0];
            if (gqlError?.extensions?.code === 'UNAUTHENTICATED' && retry) {
                this.log.warn('GraphQL UNAUTHENTICATED, refreshing token...');
                await this.refreshToken();
                return this.updateVehicleData(false);
            }

            const data = response.data.data?.carTelematicsV2;
            if (data) {
                for (const battery of data.battery || []) {
                    // Map new V2 field/enum back to legacy state name to keep user scripts working.
                    // Polestar renamed `chargingStatus` -> `chargingStatusV2` and prefixed the
                    // enum values (e.g. CHARGING_STATUS_CHARGING -> CHARGING_STATUS_V2_CHARGING).
                    if (battery.chargingStatusV2 !== undefined) {
                        battery.chargingStatus =
                            typeof battery.chargingStatusV2 === 'string'
                                ? battery.chargingStatusV2.replace('_V2_', '_')
                                : battery.chargingStatusV2;
                        delete battery.chargingStatusV2;
                    }
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

        if (this.grpcAvailable) {
            await this.updateGrpcData();
        }
    }

    async updateGrpcData() {
        if (!this.grpcClient || !this.session) {
            return;
        }
        for (const vehicle of this.vehicles) {
            try {
                const resp = await this.grpcClient.getTargetSoc(vehicle.vin, this.session.access_token);
                if (!resp) {
                    continue;
                }
                const out = {
                    batteryChargeTargetLevel: resp.target_soc?.battery_charge_target_level ?? null,
                    chargeTargetLevelSettingType: resp.target_soc?.charge_target_level_setting_type ?? null,
                    pendingBatteryChargeTargetLevel: resp.pending_target_soc?.battery_charge_target_level ?? null,
                    pendingChargeTargetLevelSettingType:
                        resp.pending_target_soc?.charge_target_level_setting_type ?? null,
                };
                if (resp.updated_at) {
                    out.lastUpdate = new Date(Number(resp.updated_at)).toISOString();
                }
                this.json2iob.parse(`${vehicle.vin}.targetSoc`, out, { forceIndex: true, descriptions, states });
            } catch (e) {
                this.log.debug(`gRPC getTargetSoc failed for ${vehicle.vin}: ${e.message}`);
            }
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
            this.grpcClient?.close();
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
