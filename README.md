# signia

A versatile key registry package that empowers users to seamlessly link their MetaNet identity across various applications.

## API
<!--#region ts2md-api-merged-here-->

Links: [API](#api), [Classes](#classes)

### Classes

| |
| --- |
| [ConfederacyConfig](#class-confederacyconfig) |
| [ERR_SIGNIA_CERT_NOT_FOUND](#class-err_signia_cert_not_found) |
| [ERR_SIGNIA_MISSING_PARAM](#class-err_signia_missing_param) |
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
#### Class: ERR_SIGNIA_CERT_NOT_FOUND

```ts
export class ERR_SIGNIA_CERT_NOT_FOUND extends CwiError {
    constructor(description?: string) 
}
```

Links: [API](#api), [Classes](#classes)

---
#### Class: ERR_SIGNIA_MISSING_PARAM

```ts
export class ERR_SIGNIA_MISSING_PARAM extends CwiError {
    constructor(description?: string) 
}
```

Links: [API](#api), [Classes](#classes)

---
#### Class: Signia

A system for decentralized identity management

```ts
export class Signia {
    constructor(public config: ConfederacyConfig = defaultConfig, public certifierUrl: string, public certifierPublicKey: string, public certificateType: string) 
    async publiclyRevealIdentityAttributes(fieldsToReveal: object, newCertificate?: boolean, verificationId = "notVerified", updateProgress = async (message) => { }): Promise<object> 
    async getNameFromKey(identityKey: string): Promise<object> 
    async discoverByAttributes(attributes: object, certifier: string = this.certifierPublicKey): Promise<object[]> 
    async discoverByIdentityKey(identityKey: string, certifier: string = this.certifierPublicKey): Promise<object[]> 
    async discoverByCertifier(certifier: string = this.certifierPublicKey): Promise<object[]> 
}
```

<details>

<summary>Class Signia Details</summary>

##### Constructor

Constructs a new Signia instance

```ts
constructor(public config: ConfederacyConfig = defaultConfig, public certifierUrl: string, public certifierPublicKey: string, public certificateType: string) 
```

Argument Details

+ **config**
  + the configuration object required by Confederacy
+ **certifierUrl**
  + the URL of the certificate certifier
+ **certifierPublicKey**
  + the public key of the certifier
+ **certificateType**
  + denotes the type of the certificate being created or queried

##### Method discoverByAttributes

Query the lookup service for the given attribute (and optional certifier) and parseResults

```ts
async discoverByAttributes(attributes: object, certifier: string = this.certifierPublicKey): Promise<object[]> 
```

##### Method discoverByCertifier

Query the lookup service for the given certifier, returning all results for the certifier parseResults

```ts
async discoverByCertifier(certifier: string = this.certifierPublicKey): Promise<object[]> 
```

##### Method discoverByIdentityKey

Query the lookup service for the given identity key (and optional certifier) parseResults

```ts
async discoverByIdentityKey(identityKey: string, certifier: string = this.certifierPublicKey): Promise<object[]> 
```

##### Method getNameFromKey

Example higher level lookup function

```ts
async getNameFromKey(identityKey: string): Promise<object> 
```

Returns

- with identity information

##### Method publiclyRevealIdentityAttributes

Publicly reveal identity attributes to the Signia overlay

```ts
async publiclyRevealIdentityAttributes(fieldsToReveal: object, newCertificate?: boolean, verificationId = "notVerified", updateProgress = async (message) => { }): Promise<object> 
```

Returns

- submission confirmation from the overlay

</details>

Links: [API](#api), [Classes](#classes)

---

<!--#endregion ts2md-api-merged-here-->

## License

The license for the code in this repository is the Open BSV License
