"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");

const axios = require("axios").default;
const fs = require("fs");
const qs = require("qs");
const https = require("https");
const crypto = require("crypto");
const Json2iob = require("./lib/json2iob");
const mqtt = require("mqtt");
const { HttpsCookieAgent } = require("http-cookie-agent/http");

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
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({
        rejectUnauthorized: false,
        cert: fs.readFileSync(__dirname + "/certs/decryptedPfxFile.tmp"),
        key: fs.readFileSync(__dirname + "/certs/decryptedPfxFile.tmp"),
        passphrase: "siuox3GxNazmVKRTXUPk7kcL",
        cookies: {
          jar: this.cookieJar,
        },
      }),
    });

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.json2iob = new Json2iob(this);
    this.vinArray = [];
    this.session = {};
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

    this.subscribeStates("*");
    this.userId = uuidv4();
    await this.login();
    if (this.session.access_token) {
      await this.getVehicles();
      await this.testUrls();
      await this.connectMqtt();
      /*
      await this.updateVehicles();
      this.updateInterval = setInterval(async () => {
        await this.updateVehicles();
      }, this.config.interval * 60 * 1000);
      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, this.session.expires_in * 1000);
    */
    }
  }
  async login() {
    const [code_verifier, codeChallenge] = this.getCodeChallenge();
    const headers = {
      "user-agent":
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
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
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.request.path.split("resumePath=")[1].split("&client")[0];
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
        "user-agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
      },
      data: qs.stringify({ "pf.username": this.config.username, "pf.pass": this.config.password }),
      jar: this.cookieJar,
      withCredentials: true,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
      })
      .catch((error) => {
        if (error.message.includes("Unsupported protocol")) {
          return qs.parse(error.request._options.path.slice(1)).code;
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
      data:
        "code=" +
        authCode +
        "&code_verifier=" +
        code_verifier +
        "&redirect_uri=polestar-explore://explore.polestar.com&grant_type=authorization_code",
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
  async testUrls() {
    //https://cepmob.eu.prod.c3.volvocars.com/aee/ducs/released/internet/ducs-appsettings-external/caraccess-settings/
    //https://cepmob.eu.prod.c3.volvocars.com/aee/telematics-base/released/internet/remote-vehicle-services-internet/
    //https://cepmob.eu.prod.c3.volvocars.com/aee/ducs/released/internet/ducs-services-internet/services/VIN
    /*
    https://cnepmob.volvocars.com/appentrypoint/EU
"host": "mqtts://cepmobsig.eu.c3.volvocars.com",
	"port": 8883,
	"services": [{
		"name": "Signaling Service",
		"description": null,
		"uri": ""
	}]

  Client Id: 74c9c259-6f67-47e5-9c21-c82884edca05
Will Topic: None
Will Message: None
User Name: None
Password: None
[SUBSCRIBE] sent topic filters: 'CA/DL/ROU/DEFAULT'
[SUBSCRIBE] sent topic filters: 'CA/DL/ROU/DEFAULT/ACK'
    */
    const headers = {
      accept: "*/*",
      "user-agent": "Polestar/1708 CFNetwork/1240.0.4 Darwin/20.6.0",
      "accept-language": "de-de",
      authorization: "Bearer " + this.session.access_token,
    };
    await this.requestClient({
      method: "get",
      url: "https://cepmob.eu.prod.c3.volvocars.com/aee/ducs/released/internet/ducs-appsettings-external/caraccess-settings/",
      headers: headers,
    })
      .then((res) => {
        this.log.info(JSON.stringify(res.data));
      })
      .catch((error) => {
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error(error);
      });

    await this.requestClient({
      method: "get",
      url: "https://cepmob.eu.prod.c3.volvocars.com/aee/telematics-base/released/internet/remote-vehicle-services-internet",
      headers: {
        accept: "application/volvo.cloud.RemoteVehicleServices.v1+json",
        volvoid: this.config.username,
        vin: this.config.vin,
        ecu: "TCAM1",
        market: "DE",
        "x-app-name": "Volvo",
        authorization: "Bearer " + this.session.access_token,
        "user-agent": "okhttp/4.9.0",
      },
    })
      .then((res) => {
        this.log.info(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("aee remote");
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error(error);
      });

    await this.requestClient({
      method: "get",
      url: "https://cepmob.eu.prod.c3.volvocars.com/aee/ducs/released/internet/ducs-services-internet/services/" + this.config.vin,
      headers: headers,
    })
      .then((res) => {
        this.log.info("ducs vin:");
        this.log.info(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("ducs vin");
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error(error);
      });
    await this.requestClient({
      method: "get",
      url: "https://cepmob.eu.prod.c3.volvocars.com/car-mdapi/car/" + this.config.vin,
      headers: headers,
    })
      .then((res) => {
        this.log.info(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("ducs vin");
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error(error);
      });
  }
  async connectMqtt() {
    const client = mqtt.connect("mqtts://cepmobsig.eu.c3.volvocars.com", {
      rejectUnauthorized: false,
      clientId: "74c9c259-5f67-47e5-9d21-c82884edca06",
      reconnectPeriod: 0,
      cert: fs.readFileSync(__dirname + "/certs/decryptedPfxFile.tmp"),
      key: fs.readFileSync(__dirname + "/certs/decryptedPfxFile.tmp"),
      passphrase: "siuox3GxNazmVKRTXUPk7kcL",
    });

    client.on("connect", () => {
      this.log.info("Connected to MQTT");
      client.subscribe("CA/DL/ROU/DEFAULT", (err) => {
        if (!err) {
          this.log.info("Subscribed to CA/DL/ROU/DEFAULT");
        }
      });
      client.subscribe("CA/DL/ROU/DEFAULT/ACK", (err) => {
        if (!err) {
          this.log.info("Subscribed to CA/DL/ROU/DEFAULT");
        }
      });
      const rawHex = Buffer.from("", "hex");
      // client.publish("CA/DL/ROU/DEFAULT", rawHex);
    });

    client.on("message", (topic, message) => {
      // message is Buffer
      this.log.info("Received message on topic: " + topic);
      this.log.info(message.toString());
    });
    client.on("error", (message) => {
      this.log.info("Received error");
      this.log.info(message.toString());
    });
    client.on("close", (message) => {
      this.log.info("Received close");
      this.log.info(message);
    });
    client.on("offline", () => {
      this.log.info("Received offline");
    });
    client.on("reconnect", () => {
      this.log.info("Received reconnect");
    });
    client.on("disconnect", () => {
      this.log.info("Received disconnect");
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
        query:
          "query GetConsumerInformation {\n  myStar {\n    __typename\n    getConsumer {\n      __typename\n      ...MyStarConsumerDetails\n    }\n    getOrders {\n      __typename\n      ...MyStarOrderDetails\n    }\n    getConsumerCars {\n      __typename\n      ...MyStarCarDetails\n    }\n  }\n}\nfragment MyStarConsumerDetails on MyStarConsumer {\n  __typename\n  birthdate\n  city\n  country\n  countryCode\n  email\n  firstName\n  lastName\n  mobilePhone\n  salesforceId\n  streetAddress\n  zipCode\n  additionalCustomerIds {\n    __typename\n    code\n    id\n  }\n}\nfragment MyStarOrderDetails on MyStarOrder {\n  __typename\n  type\n  address\n  city\n  configurationId\n  consumerId\n  country\n  countryCode\n  deposit\n  district\n  downPayment\n  externalOrderId\n  orderId\n  orderState\n  packageId\n  placedAt\n  province\n  redirectUrl\n  totalPrice\n  zipCode\n  car {\n    __typename\n    ...MyStarCarDetails\n  }\n  items {\n    __typename\n    ...MyStarOrderItemDetails\n  }\n}\nfragment MyStarCarDetails on MyStarCar {\n  __typename\n  id\n  consumerId\n  engine\n  exterior\n  exteriorCode\n  exteriorImageUrl\n  gearbox\n  interior\n  interiorCode\n  interiorImageUrl\n  model\n  modelYear\n  package\n  packageCode\n  pdfUrl\n  status\n  steering\n  vin\n  wheels\n  wheelsCode\n}\nfragment MyStarOrderItemDetails on MyStarOrderItem {\n  __typename\n  id\n  currency\n  deposit\n  downPayment\n  price\n  quantity\n  title\n  type\n}",
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
          const data = {
            operationName: "GetVDMSCarDetails",
            query:
              "query GetVDMSCarDetails($vin: String!, $locale: String!) {\n  vdms {\n    __typename\n    vehicleInformation(vin: $vin, locale: $locale) {\n      __typename\n      ...VdmsExtendedCarDetails\n    }\n  }\n}\nfragment VdmsExtendedCarDetails on VehicleInformation {\n  __typename\n  belongsToFleet\n  content {\n    __typename\n    dimensions {\n      __typename\n      ...VdmsDimensionsDetails\n    }\n    exterior {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    images {\n      __typename\n      ...VdmsCarImageDetails\n    }\n    interior {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    model {\n      __typename\n      ...VdmsModelDetails\n    }\n    motor {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    performancePackage {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    pilotPackage {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    plusPackage {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    specification {\n      __typename\n      ...VdmsSpecificationDetails\n    }\n    towbar {\n      __typename\n      ...VdmsFeatureDetails\n    }\n    wheels {\n      __typename\n      ...VdmsFeatureDetails\n    }\n  }\n  curbWeight {\n    __typename\n    ...VdmsWeightDetails\n  }\n  cylinderVolume\n  cylinderVolumeUnit\n  drivetrain\n  factoryCompleteDate\n  fuelType\n  hasPerformancePackage\n  market\n  maxTrailerWeight {\n    __typename\n    ...VdmsWeightDetails\n  }\n  metaOrderNumber\n  modelYear\n  motor {\n    __typename\n    ...VdmsMotorDetails\n  }\n  numberOfCylinders\n  numberOfDoors\n  numberOfGears\n  numberOfSeats\n  pno34\n  primaryDriver\n  registrationNo\n  serviceHistory {\n    __typename\n    ...VdmsWorkOrderDetails\n  }\n  transmission\n  vin\n  wltpNedcData {\n    __typename\n    ...VdmsWltpDetails\n  }\n}\nfragment VdmsDimensionsDetails on VdmsDimensions {\n  __typename\n  bodyDimensions {\n    __typename\n    ...VdmsLabelValueDetails\n  }\n  groundClearanceWithPerformance {\n    __typename\n    ...VdmsLabelValueDetails\n  }\n  groundClearanceWithoutPerformance {\n    __typename\n    ...VdmsLabelValueDetails\n  }\n  wheelbase {\n    __typename\n    ...VdmsLabelValueDetails\n  }\n}\nfragment VdmsLabelValueDetails on VdmsLabelValue {\n  __typename\n  label\n  value\n}\nfragment VdmsFeatureDetails on VdmsFeature {\n  __typename\n  code\n  description\n  excluded\n  galleryImage {\n    __typename\n    alt\n    url\n  }\n  name\n  thumbnail {\n    __typename\n    alt\n    url\n  }\n}\nfragment VdmsCarImageDetails on VdmsCarImages {\n  __typename\n  interior {\n    __typename\n    ...VdmsImageDetails\n  }\n  location {\n    __typename\n    ...VdmsImageDetails\n  }\n  studio {\n    __typename\n    ...VdmsImageDetails\n  }\n}\nfragment VdmsImageDetails on VdmsImage {\n  __typename\n  angles\n  resolutions\n  url\n}\nfragment VdmsModelDetails on VdmsModel {\n  __typename\n  code\n  name\n}\nfragment VdmsSpecificationDetails on VdmsSpecification {\n  __typename\n  battery\n  electricMotors\n  performance\n  torque\n  totalHp\n  totalKw\n  trunkCapacity {\n    __typename\n    ...VdmsLabelValueDetails\n  }\n}\nfragment VdmsWeightDetails on VdmsWeight {\n  __typename\n  unit\n  value\n}\nfragment VdmsMotorDetails on VdmsMotor {\n  __typename\n  code\n  description\n}\nfragment VdmsWorkOrderDetails on VdmsWorkOrder {\n  __typename\n  market\n  operations {\n    __typename\n    ...VdmsOperationDetails\n  }\n  orderEndDate\n  orderNumber\n  orderStartDate\n  parts {\n    __typename\n    ...VdmsPartDetails\n  }\n  status\n  statusDMS\n  workshopId\n}\nfragment VdmsOperationDetails on VdmsOperation {\n  __typename\n  code\n  description\n  id\n  performedDate\n  quantity\n}\nfragment VdmsPartDetails on VdmsPart {\n  __typename\n  code\n  description\n  id\n  performedDate\n  quantity\n}\nfragment VdmsWltpDetails on VdmsWltpNedcData {\n  __typename\n  wltpCO2Unit\n  wltpElecEnergyConsumption\n  wltpElecEnergyUnit\n  wltpElecRange\n  wltpElecRangeUnit\n  wltpWeightedCombinedCO2\n}",
            variables: {
              locale: "de_DE",
              vin: vehicle.vin,
            },
          };
          this.sendRequest(vehicle.vin, data, "vdms");
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

            this.json2iob.parse(vin + "." + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
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

  async sendRequest(vin, data, path) {
    const headers = {
      "content-type": "application/json",
      accept: "*/*",
      "explore-protocol-version": "4.2",
      "x-polestarid-authorization": "Bearer " + this.session.access_token,
    };
    await this.requestClient({
      method: "post",
      url: "https://pc-api.polestar.com/eu-north-1/mesh/",
      headers: headers,
      data: JSON.stringify(data),
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));

        let result = res.data.data[Object.keys(res.data.data)[0]];
        result = result[Object.keys(result)[1]];
        this.json2iob.parse(vin + "." + path, result);
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
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
