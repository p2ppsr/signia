# signia

Streamlining MetaNet Identity and Attribute Certification Across Applications

## Overview

Signia is a cutting-edge npm package designed for seamless integration with the Confederacy Signia overlay network. It offers a robust framework for developers to manage and verify user's identities and attributes in a decentralized manner.

This package simplifies the complexities of identity / attribute verification, certification, and certificate management, making it easier to onboard new users and provide a seamless and secure user experience.

## Key Features

- **Versatile Identity Management:** Manage and publish diverse user attributes, including but not limited to, personal identifiers, professional skills, and certifications.
- **Seamless Integration with Certifiers:** Interact with various Babbage-compatible Certificate Authorities (CAs) for user identity and attribute verification.
- **Efficient Certificate Handling:** Simplify the process of obtaining and managing certificates for MetaNet identities, enhancing user experience.
- **Streamlined Authentication Process:** Leverage existing certificates to bypass redundant verification steps in different applications, promoting a more unified user experience.
- **Economic Incentives for Certifiers:** Encourage certifiers to perform diligent verification through a micropayment-based incentive structure.

## Getting Started

To begin using Signia in your project, install it via npm:

```bash
npm i babbage-signia
```

After installation, initialize Signia with a Confederacy node details, or use the defaults, and start building your application with enhanced identity and attribute management capabilities.

## Example Usage

If a user wants to publicly reveal some generic identity attributes to an example certifier called GenericCert, they could use the following example code.

```ts
/**
 * This function call will request the creation and signing of a certificate
 * with the following fields by the given certifier (GenericCert).
 * 
 * The required params are:
 * - fieldsToReveal
 * - certifierUrl
 * - certifierPublicKey
 * - certificateType
 * */
await signia.publiclyRevealAttributes(
  { firstName: 'John', lastName: 'Smith', skill: 'TypeScript' }, 
  'https://genericcert-backend.babbage.systems', 
  '036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528', 
  'eakpG20OQruUQ9yjd5htr4LrrzMsifjffJJ9g9y1nfk='
)
```

If someone wants to find someone certified in TypeScript by the GenericCert certifier, they could use the following code.

```ts
/**
 * This function call will perform a lookup request to the Confederacy 
 * Signia overlay network to look for a matching result.
 * 
 * The required params are:
 * - attributes given in an object as key/value pairs
 * - the acceptable certifiers given as an array of certifier public keys.
 * */
await signia.discoverByAttributes(
  {
    skill: 'TypeScript'
  },
  ['036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528']
)

// Example response
[
  {
    type: 'eakpG20OQruUQ9yjd5htr4LrrzMsifjffJJ9g9y1nfk=',
    subject: '024c0175179387843f2bf58e2b7411a0e3f5b7934132f8383a802cf6cb6f69eb6b',
    validationKey: '0G+4gZwRn6FcSjnUkQ4JyYTrGJO1Z5jvedfyXXqIdug=',
    serialNumber: 'S3ClsmcbzhHotrJ84Vc6lhTLbJMDKERh9HVhLumDj3E=',
    fields: {
      firstName: 'Uw5ep0dSIuGb8DIj/Ee7528+90EO1XLHiwBEv2StdmCcVa/XTKwQYrX1dnWFh3+4h+SWXVq0q33KKP8=',
      lastName: 'Kbkfkn4JO5gK+35rQxGhNMY87+EJnEIavrp6Qg9XiX8PwM9yoLxxWe1fkSa+cr+gfszmSwfq',
      skill: '7WdNIteakuEABpDGD0VZzJSElo3NIhyXc9lRdRfyW5ksfXInhtpSCgWsbwzceszKQ7PQ4mnsKnifiXXQRpu/Lv2G1JUbTdAdfRHOJFihq9VZ1UQbEEvGQ8WrZwqh3NNl7tqt0Q=='
    },
    certifier: '036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528',
    revocationOutpoint: '3fc5498bd648671e316e07bb7037985ff54d9e04a255e405239fc4e97af1c10500000000',
    signature: '3044022004b7ce99ea1a112de2b3b3d029809bb1fa850110c04815d320f0fbd954aac0e902203b6c8c9eda1dc85e75357238d01cbefa4709c5132baf2a728da26a27c6b1c040',
    keyring: {
      firstName: 'Lxjj21iR0Shna6b1uv6WEZVMWcrD4HhzjZwTiEGwdeRQVnmOv0K/GQ7SuLWBTcQn9gJIXK7782DD4tbl+yUWEN2rjQal8JCmydmTB5F5Lkk=',
      lastName: 'cF0hqXENrYdx3w+4qCjD6hWNnKTzZ6YZSv0vAn446d5Dj7C7LmVjl38H9JRf8iNNMN+lT/Fdohbh39F4McrObwZRY2sBY9AmUi3i8FkjHME=',
      skill: 'NiAcX25xEGHC8j0zMVTPZSSAeHKk/sT2U9yShlpGekgrcuShc6prKiuNxRUkdf5tavAbH4sw6xyrM9nDdvUBTOhn5RcwY3UVW349x0dMyhk='
    },
    decryptedFields: {
      firstName: 'John',
      lastName: 'Smith',
      skill: 'TypeScript'
    }
  }
]

```

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
    async certifyPeer(peer: string, fieldsToAttest: Record<string, string>, certificateType: string, updateProgress = async (message) => { }): Promise<object> 
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

##### Method certifyPeer

Publicly attest attributes of a peer.

```ts
async certifyPeer(peer: string, fieldsToAttest: Record<string, string>, certificateType: string, updateProgress = async (message) => { }): Promise<object> 
```

Returns

A promise that resolves when the attestation has been made.

Argument Details

+ **peer**
  + The public key of the peer to certify.
+ **fieldsToAttest**
  + The fields to attest about a peer.
+ **certificateType**
  + The type of certification to make about this peer (based on the fields).
+ **updateProgress**
  + A callback function to update progress. Default is an empty asynchronous function.

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
