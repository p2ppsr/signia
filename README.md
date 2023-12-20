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

A system for decentralized identity management

```ts
export class Signia {
    constructor(public config: ConfederacyConfig = defaultConfig) 
    async publiclyRevealIdentityAttributes(fieldsToReveal: object, certifierUrl: string, certifierPublicKey: string, certificateType: string, verificationId = "notVerified", newCertificate?: boolean, updateProgress = async (message) => { }): Promise<object> 
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
constructor(public config: ConfederacyConfig = defaultConfig) 
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

##### Method publiclyRevealIdentityAttributes

Publicly reveal identity attributes to the Signia overlay

```ts
async publiclyRevealIdentityAttributes(fieldsToReveal: object, certifierUrl: string, certifierPublicKey: string, certificateType: string, verificationId = "notVerified", newCertificate?: boolean, updateProgress = async (message) => { }): Promise<object> 
```

Returns

- submission confirmation from the overlay

</details>

Links: [API](#api), [Classes](#classes)

---

<!--#endregion ts2md-api-merged-here-->

## License

The license for the code in this repository is the Open BSV License
