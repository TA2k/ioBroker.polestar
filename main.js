"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");

const axios = require("axios");
const qs = require("qs");
const crypto = require("crypto");
const Json2iob = require("./lib/json2iob");
const axiosCookieJarSupport = require("axios-cookiejar-support").default;
const tough = require("tough-cookie");
const { v4: uuidv4 } = require("uuid");

class Polestar extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "polestar",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        axiosCookieJarSupport(axios);
        this.cookieJar = new tough.CookieJar();
        this.requestClient = axios.create();
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.json2iob = new Json2iob(this);
        this.vinArray = [];
        this.session = {};

        this.subscribeStates("*");
        this.userId = uuidv4();
        await this.login();
        if (this.session.access_token) {
            await this.getVehicles();
            await this.updateVehicles();
            this.updateInterval = setInterval(async () => {
                await this.updateVehicles();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, this.session.expires_in * 1000);
        }
    }
    async login() {
        const [code_verifier, codeChallenge] = this.getCodeChallenge();
        const headers = {
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "de-de",
        };
        const resumePath = await this.requestClient({
            method: "get",
            url:
                "https://polestarid.eu.polestar.com/as/authorization.oauth2?market=DE&nonce=" +
                this.randomString(43) +
                "&response_type=code&code_challenge_method=S256&scope=openid%20profile%20customer:attributes&code_challenge=" +
                codeChallenge +
                "&language=de&redirect_uri=polestar-explore://explore.polestar.com&access_token_manager_id=JWTpolxplore&client_id=polxplore&state=" +
                this.randomString(43),
            headers: headers,
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                return res.response.headers.location.split("resumePath=")[1].split("&client")[0];
            })
            .catch((error) => {
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error(error);
            });
        const authCode = await this.requestClient({
            method: "post",
            url: "https://polestarid.eu.polestar.com/as/" + resumePath + "/resume/as/authorization.ping?client_id=polxplore",
            headers: {
                accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "content-type": "application/x-www-form-urlencoded",
                "accept-language": "de-de",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
            },
            data: qs.stringify({ "pf.username": this.config.username, "pf.password": this.config.password }),
            jar: this.cookieJar,
            withCredentials: true,
            maxRedirects: 0,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return error.response.data.split("polestar-explore://explore.polestar.com?code=")[1].split("&state=")[0];
                } else {
                    error.response && this.log.error(JSON.stringify(error.response.data));
                    this.log.error(error);
                }
            });
        if (!authCode) {
            return;
        }

        await this.requestClient({
            method: "post",
            url: "https://polestarid.eu.polestar.com/as/token.oauth2",

            headers: {
                accept: "*/*",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                authorization: "Basic cG9seHBsb3JlOlhhaUtvb0hlaXJlaXNvb3NhaDBFdjZxdW9oczhjb2hGZUtvaHdpZTFhZTdraWV3b2hkb295ZWk5QWVZZWlXb2g=",
                "user-agent": "Polestar/711 CFNetwork/1240.0.4 Darwin/20.6.0",
                "accept-language": "de-de",
            },
            data: "code=" + authCode + "&code_verifier=" + code_verifier + "&redirect_uri=polestar-explore://explore.polestar.com&grant_type=authorization_code",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
                this.log.info("Login successful");
                return res.data;
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });
    }
    async getVehicles() {
        const headers = {
            "content-type": "application/json",
            accept: "*/*",
            "x-polestarid-authorization": "Bearer " + this.session.access_token,
        };
        await this.requestClient({
            method: "post",
            url: "https://pc-api.polestar.com/eu-north-1/mesh/",
            headers: headers,
            data: JSON.stringify({
                operationName: "GetConsumerInformation",
                query: "query GetConsumerInformation {\n  myStar {\n    __typename\n    getConsumer {\n      __typename\n      ...MyStarConsumerDetails\n    }\n    getOrders {\n      __typename\n      ...MyStarOrderDetails\n    }\n    getConsumerCars {\n      __typename\n      ...MyStarCarDetails\n    }\n  }\n}\nfragment MyStarConsumerDetails on MyStarConsumer {\n  __typename\n  birthdate\n  city\n  country\n  countryCode\n  email\n  firstName\n  lastName\n  mobilePhone\n  salesforceId\n  streetAddress\n  zipCode\n  additionalCustomerIds {\n    __typename\n    code\n    id\n  }\n}\nfragment MyStarOrderDetails on MyStarOrder {\n  __typename\n  type\n  address\n  city\n  configurationId\n  consumerId\n  country\n  countryCode\n  deposit\n  district\n  downPayment\n  externalOrderId\n  orderId\n  orderState\n  packageId\n  placedAt\n  province\n  redirectUrl\n  totalPrice\n  zipCode\n  car {\n    __typename\n    ...MyStarCarDetails\n  }\n  items {\n    __typename\n    ...MyStarOrderItemDetails\n  }\n}\nfragment MyStarCarDetails on MyStarCar {\n  __typename\n  id\n  consumerId\n  engine\n  exterior\n  exteriorCode\n  exteriorImageUrl\n  gearbox\n  interior\n  interiorCode\n  interiorImageUrl\n  model\n  modelYear\n  package\n  packageCode\n  pdfUrl\n  status\n  steering\n  vin\n  wheels\n  wheelsCode\n}\nfragment MyStarOrderItemDetails on MyStarOrderItem {\n  __typename\n  id\n  currency\n  deposit\n  downPayment\n  price\n  quantity\n  title\n  type\n}",
                variables: null,
            }),
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                for (const vehicle of res.data.data.myStar.getConsumerCars) {
                    this.vinArray.push(vehicle.vin);
                    await this.setObjectNotExistsAsync(vehicle.vin, {
                        type: "device",
                        common: {
                            name: vehicle.model,
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(vehicle.vin + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(vehicle.vin + ".general", {
                        type: "channel",
                        common: {
                            name: "General Car Information",
                        },
                        native: {},
                    });

                    // const remoteArray = [{ command: "engine/start" }, { command: "doors/lock" }];
                    const remoteArray = [];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(vehicle.vin + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });
                    this.json2iob.parse(vehicle.vin + ".general", vehicle);
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateVehicles() {
        // const statusArray = [{ path: "status", url: "https://pc-api.polestar.com/eu-north-1/mesh/", desc: "Current status of the car" }];
        const statusArray = [];
        const headers = {
            "content-type": "application/json",
            accept: "*/*",
            "x-polestarid-authorization": "Bearer " + this.session.access_token,
        };
        this.vinArray.forEach((vin) => {
            statusArray.forEach(async (element) => {
                const url = element.url.replace("$vin", vin);

                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        let data = res.data;
                        const keys = Object.keys(res.data);
                        if (keys.length === 1) {
                            data = res.data[keys[0]];
                        }
                        const forceIndex = null;
                        const preferedArrayName = null;

                        this.json2iob.parse(vin + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response && error.response.status === 401) {
                            error.response && this.log.debug(JSON.stringify(error.response.data));
                            this.log.info(element.path + " receive 401 error. Refresh Token in 30 seconds");
                            clearTimeout(this.refreshTokenTimeout);
                            this.refreshTokenTimeout = setTimeout(() => {
                                this.refreshToken();
                            }, 1000 * 30);

                            return;
                        }

                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            });
        });
    }

    async refreshToken() {
        await this.requestClient({
            method: "post",
            url: "https://polestarid.eu.polestar.com/as/token.oauth2",

            headers: {
                accept: "*/*",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                authorization: "Basic cG9seHBsb3JlOlhhaUtvb0hlaXJlaXNvb3NhaDBFdjZxdW9oczhjb2hGZUtvaHdpZTFhZTdraWV3b2hkb295ZWk5QWVZZWlXb2g=",
                "user-agent": "Polestar/711 CFNetwork/1240.0.4 Darwin/20.6.0",
                "accept-language": "de-de",
            },
            data: "refresh_token=" + this.session.refresh_token + "&grant_type=refresh_token",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
                return res.data;
            })
            .catch((error) => {
                this.log.error("refresh token failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
                }, 1000 * 60 * 1);
            });
    }
    getCodeChallenge() {
        let hash = "";
        let result = "";
        const chars = "0123456789abcdef";
        result = "";
        for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
        hash = crypto.createHash("sha256").update(result).digest("base64");
        hash = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        return [result, hash];
    }
    randomString(length) {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            clearTimeout(this.refreshTimeout);
            clearTimeout(this.reLoginTimeout);
            clearTimeout(this.refreshTokenTimeout);
            clearInterval(this.updateInterval);
            clearInterval(this.refreshTokenInterval);
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    async onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                const vin = id.split(".")[2];

                const command = id.split(".")[4];

                const headers = {
                    accept: "*/*",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",

                    "user-agent": "Polestar/711 CFNetwork/1240.0.4 Darwin/20.6.0",
                    "accept-language": "de-de",
                };

                const url = "https://pc-api.polestar.com/eu-north-1/mesh/";

                await this.requestClient({
                    method: "post",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        return res.data;
                    })
                    .catch((error) => {
                        this.log.error(error);
                        if (error.response) {
                            this.log.error(JSON.stringify(error.response.data));
                        }
                    });
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateVehicles();
                }, 10 * 1000);
            } else {
                // const resultDict = { chargingStatus: "CHARGE_NOW", doorLockState: "DOOR_LOCK" };
                // const idArray = id.split(".");
                // const stateName = idArray[idArray.length - 1];
                const vin = id.split(".")[2];
                // if (resultDict[stateName]) {
                //     let value = true;
                //     if (!state.val || state.val === "INVALID" || state.val === "NOT_CHARGING" || state.val === "ERROR" || state.val === "UNLOCKED") {
                //         value = false;
                //     }
                //     await this.setStateAsync(vin + ".remote." + resultDict[stateName], value, true);
                // }
            }
        }
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Polestar(options);
} else {
    // otherwise start the instance directly
    new Polestar();
}
