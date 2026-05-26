'use strict';

const path = require('path');
const crypto = require('crypto');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

// Polestar Connected Car Services (PCCS) gRPC backend.
// Used to fetch the configured charge limit (Target SoC), which is not
// exposed via the public GraphQL API.
const PCCS_HOST = 'api.pccs-prod.plstr.io';
const PCCS_PORT = 443;
const GRPC_TIMEOUT_MS = 30000;
const TARGET_SOC_SERVICE_PATH = '/pccs.chronos.services.v1.TargetSocService/GetTargetSoc';

class GrpcClient {
    /**
     * @param {object} [log] ioBroker logger or console-compatible object.
     */
    constructor(log) {
        this.log = log || console;
        /** @type {any} */
        this.pccsChannel = null;
        /** @type {any} */
        this.targetSocMethod = null;
    }

    /**
     * Load proto definitions and open the TLS channel to the PCCS backend.
     */
    async connect() {
        const protoDir = path.join(__dirname, 'proto');
        const packageDef = /** @type {any} */ (
            protoLoader.loadSync('polestar_target_soc_service.proto', {
                keepCase: true,
                longs: Number,
                enums: String,
                defaults: true,
                oneofs: true,
                includeDirs: [protoDir],
            })
        );

        const targetSocSvc = packageDef['pccs.chronos.services.v1.TargetSocService'];
        if (!targetSocSvc || !targetSocSvc.GetTargetSoc) {
            throw new Error('proto-loader missing TargetSocService.GetTargetSoc');
        }
        this.targetSocMethod = targetSocSvc.GetTargetSoc;

        const creds = grpc.credentials.createSsl();
        this.pccsChannel = new grpc.Client(`${PCCS_HOST}:${PCCS_PORT}`, creds);
    }

    /**
     * @param {string} accessToken
     * @param {string} vin
     * @returns {grpc.Metadata}
     */
    _metadata(accessToken, vin) {
        const md = new grpc.Metadata();
        md.add('authorization', `Bearer ${accessToken}`);
        md.add('vin', vin);
        return md;
    }

    /**
     * Server-streaming GetTargetSoc — read first message, then cancel.
     *
     * @param {string} vin
     * @param {string} accessToken
     * @returns {Promise<any>}
     */
    async getTargetSoc(vin, accessToken) {
        const channel = this.pccsChannel;
        const method = this.targetSocMethod;
        if (!channel || !method) {
            throw new Error('gRPC PCCS channel not connected');
        }

        return new Promise((resolve, reject) => {
            const deadline = new Date(Date.now() + GRPC_TIMEOUT_MS);
            const call = channel.makeServerStreamRequest(
                TARGET_SOC_SERVICE_PATH,
                method.requestSerialize,
                method.responseDeserialize,
                { request: { id: crypto.randomUUID(), vin, source: 'mobile' } },
                this._metadata(accessToken, vin),
                { deadline },
            );

            let settled = false;
            call.on('data', (/** @type {any} */ msg) => {
                if (settled) {
                    return;
                }
                settled = true;
                resolve(msg);
                call.cancel();
            });
            call.on('error', (/** @type {any} */ err) => {
                if (settled && err.code === grpc.status.CANCELLED) {
                    return;
                }
                if (settled) {
                    return;
                }
                settled = true;
                reject(err);
            });
            call.on('end', () => {
                if (!settled) {
                    settled = true;
                    resolve(null);
                }
            });
        });
    }

    close() {
        try {
            if (this.pccsChannel) {
                this.pccsChannel.close();
            }
        } catch {
            // ignore
        }
        this.pccsChannel = null;
    }
}

module.exports = GrpcClient;
