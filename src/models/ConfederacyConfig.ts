/* eslint-disable @typescript-eslint/no-empty-function */
export class ConfederacyConfig {
    constructor( 
        public confederacyHost?: string,
        public protocolID?: [number, string],
        public keyID?: string,
        public tokenAmount?: number,
        public topics?: string[],
        public authriteConfig?: object,
        public counterparty?: string,
        public receiveFromCounterparty?: boolean,
        public sendToCounterparty?: boolean,
        public viewpoint?: string
    ) {}
}