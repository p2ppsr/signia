# signia

A versatile key registry package that empowers users to seamlessly link their MetaNet identity across various applications.

## API
<!--#region ts2md-api-merged-here-->

Links: [API](#api), [Classes](#classes)

### Classes

| |
| --- |
| [ConfederacyConfig](#class-confederacyconfig) |
| [Signia](#class-signia) |

Links: [API](#api), [Classes](#classes)

---

#### Class: ConfederacyConfig

```ts
export class ConfederacyConfig {
    constructor(public confederacyHost?: string, public protocolID?: [
        number,
        string
    ], public keyID?: string, public tokenAmount?: number, public topics?: string[], public authriteConfig?: object, public counterparty?: string, public receiveFromCounterparty?: boolean, public sendToCounterparty?: boolean, public viewpoint?: string) 
}
```

Links: [API](#api), [Classes](#classes)

---
#### Class: Signia

A system for decentralized identity attribute attestation and lookup

```ts
export class Signia {
    constructor(public config = new ConfederacyConfig("https://confederacy.babbage.systems", [1, "signia"], "1", 1000, ["Signia"], undefined, undefined, false, false, "localToSelf")) 
    async publiclyRevealAttributes(fieldsToReveal: object, certifierUrl: string, certifierPublicKey: string, certificateType: string, newCertificate = false, preVerifiedData: object, updateProgress = async (message) => { }): Promise<object> 
    async getNameFromKey(identityKey: string, certifiers: string[]): Promise<object> 
    async discoverByAttributes(attributes: object, certifiers: string[]): Promise<object[]> 
    async discoverByIdentityKey(identityKey: string, certifiers: string[]): Promise<object[]> 
    async discoverByCertifier(certifiers: string[]): Promise<object[]> 
}
```

<details>

<summary>Class Signia Details</summary>

##### Constructor

Constructs a new Signia instance

```ts
constructor(public config = new ConfederacyConfig("https://confederacy.babbage.systems", [1, "signia"], "1", 1000, ["Signia"], undefined, undefined, false, false, "localToSelf")) 
```

Argument Details

+ **config**
  + the configuration object required by Confederacy

##### Method discoverByAttributes

Query the lookup service for the given attribute (and optional certifiers) and parseResults

```ts
async discoverByAttributes(attributes: object, certifiers: string[]): Promise<object[]> 
```

##### Method discoverByCertifier

Query the lookup service for the given certifiers, returning all results for the certifiers parseResults

```ts
async discoverByCertifier(certifiers: string[]): Promise<object[]> 
```

##### Method discoverByIdentityKey

Query the lookup service for the given identity key (and optional certifiers) parseResults

```ts
async discoverByIdentityKey(identityKey: string, certifiers: string[]): Promise<object[]> 
```

##### Method getNameFromKey

Example higher level lookup function

```ts
async getNameFromKey(identityKey: string, certifiers: string[]): Promise<object> 
```

Returns

- with identity information

##### Method publiclyRevealAttributes

Publicly reveal attributes to the Signia overlay.

```ts
async publiclyRevealAttributes(fieldsToReveal: object, certifierUrl: string, certifierPublicKey: string, certificateType: string, newCertificate = false, preVerifiedData: object, updateProgress = async (message) => { }): Promise<object> 
```

Returns

A promise that resolves with the results of the submission to the overlay.

Argument Details

+ **fieldsToReveal**
  + The fields to reveal.
+ **certifierUrl**
  + The URL of the certifier.
+ **certifierPublicKey**
  + The public key of the certifier.
+ **certificateType**
  + The type of certificate.
+ **newCertificate**
  + Indicates if a new certificate should be created. Default is false.
+ **preVerifiedData**
  + Verification data to send to the certifier if the attributes have been preVerified. Can be undefined.
+ **updateProgress**
  + A callback function to update progress. Default is an empty asynchronous function.

</details>

Links: [API](#api), [Classes](#classes)

---

<!--#endregion ts2md-api-merged-here-->

## License

The license for the code in this repository is the Open BSV License
