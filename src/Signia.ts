/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-empty-function */
import SDK from '@babbage/sdk'
import pushdrop from 'pushdrop'
import bsv from 'babbage-bsv'
import { Authrite, AuthriteClient } from 'authrite-js'
import { decryptCertificateFields, verifyCertificateSignature } from 'authrite-utils'
import { ConfederacyConfig } from './utils/ConfederacyConfig'
import { Output } from 'confederacy-base'
import { CwiError, ERR_BAD_REQUEST } from 'cwi-base'
import stringify from 'json-stable-stringify'
import * as CWICrypto from 'cwi-crypto'
import nodeCrypto from 'crypto'
import { getPaymentPrivateKey, getPaymentAddress } from 'sendover'

/**
 * A system for decentralized identity attribute attestation and lookup
 * @public
 */
export class Signia {
  private authrite: AuthriteClient
  /**
   * Constructs a new Signia instance
   * @param {ConfederacyConfig} config - the configuration object required by Confederacy
   */
  constructor(
    public config = new ConfederacyConfig(
      'https://confederacy.babbage.systems',
      [1, 'signia'],
      '1',
      1000,
      ['Signia'],
      undefined,
      undefined,
      false,
      false,
      'localToSelf'
    )
  ) {
    this.authrite = new Authrite(this.config.authriteConfig)
  }

  /**
   * Publicly reveal attributes to the Signia overlay.
   * 
   * @param {object} fieldsToReveal - The fields to reveal.
   * @param {string} certifierUrl - The URL of the certifier.
   * @param {string} certifierPublicKey - The public key of the certifier.
   * @param {string} certificateType - The type of certificate.
   * @param {boolean} [newCertificate=false] - Indicates if a new certificate should be created. Default is false.
   * @param {object} preVerifiedData - Verification data to send to the certifier if the attributes have been preVerified. Can be undefined.
   * @param {(message: string) => Promise<void>} [updateProgress] - A callback function to update progress. Default is an empty asynchronous function.
   * @returns {Promise<object>} A promise that resolves with the results of the submission to the overlay.
   */
  async publiclyRevealAttributes(fieldsToReveal: object, certifierUrl: string, certifierPublicKey: string, certificateType: string, newCertificate = false, preVerifiedData: object, updateProgress = async (message) => { }): Promise<object> {
    // Search for a matching certificate
    let matchingCertificates
    if (!newCertificate) {
      await updateProgress('Looking for matching certificate...')
      matchingCertificates = await SDK.getCertificates({
        certifiers: [certifierPublicKey],
        types: {
          [certificateType]: Object.keys(fieldsToReveal)
        }
      })
    }

    // If no certificate is found, the user needs to request one before revealing particular attributes
    let certificate: Certificate
    if (newCertificate === true || !matchingCertificates || matchingCertificates.length === 0) {
      // Create a new Authrite client for interacting with the SigniCert server
      const client = new AuthriteClient(certifierUrl)
      await updateProgress('Identifying certifier...')

      // Check if the server is who we think it is
      const identifyResponse = await client.createSignedRequest('/identify', {})
      if (identifyResponse.status !== 'success' || identifyResponse.certifierPublicKey !== certifierPublicKey || !identifyResponse.certificateTypes.some(([type]) => type === certificateType)) {
        throw new ERR_BAD_REQUEST('Unexpected Identify Certifier Response. Check certifierPublicKey and certificateType.')
      }

      // If pre-verification has been done through some other process (such as Persona KYC API iFrame in a UI),
      // Then we should send that data to the backend for validation before proceeding
      if (preVerifiedData) {
        // Is confirmCertificate necessary?
        await updateProgress('Checking verification status...')
        const verificationResponse = await client.createSignedRequest('/checkVerification', {
          preVerifiedData,
          certificateFields: fieldsToReveal
        })

        // Check user has completed verification
        if (verificationResponse.status !== 'verified') {
          throw new Error('Attributes have not been verified!')
        }

        // The fields returned from the certifier are the fields that have been certified.
        // Note: these may contain additional data if it is necessary such as when a profile photo is verified and a UHRP url is returned as a field.
        // Additional fields cannot be added as the kernal does an additional check before signing.
        // The field data returned from the certifier could potentially be wrong, but it is the certifier who's reputation is at stake.
        fieldsToReveal = verificationResponse.verifiedAttributes
      } else {
        await updateProgress('Submitting attributes for verification...')
        // Submit attributes to reveal for verification by the certifier
        const verificationResponse = await client.createSignedRequest('/verifyAttributes', {
          attributes: fieldsToReveal
        })

        // Check user has completed verification
        if (verificationResponse.status !== 'verified') {
          throw new Error('Attributes have not been verified!')
        }
      }

      // Create a new certificate
      certificate = await client.createCertificate({
        certificateType,
        fieldObject: fieldsToReveal,
        certifierUrl,
        certifierPublicKey
      })
    } else {
      // Use the latest certificate (for now)
      // TODO: Consider best practices for this and removal of certificates
      certificate = matchingCertificates[matchingCertificates.length - 1]
    }

    await updateProgress('Creating a verifiable certificate...')

    // Get an anyone verifiable certificate
    const verifiableCertificate = await SDK.proveCertificate({
      certificate: certificate,
      fieldsToReveal: Object.keys(fieldsToReveal),
      verifierPublicIdentityKey: new bsv.PrivateKey('0000000000000000000000000000000000000000000000000000000000000001').publicKey.toString('hex')
    })

    // TODO: Make sure the verifiableCertificate doesn't contain extra fields such as UserId and isDeleted
    // Maybe the certificate structure should be recreated as expected similar to how it does it in verifyCert in authriteUtils

    // Check if an existing Signia token is found ??
    const lookupResults: Output[] = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: {
          identityKey: certificate.subject,
          certifiers: [certifierPublicKey]
        }
      }
    )

    // Get the first results...
    // Note: in this context there should only be one previous if there is an update
    let previousTokenEnvelope
    if (lookupResults && lookupResults.length !== 0) {
      previousTokenEnvelope = lookupResults[0]
    }

    // No inputs, unless redeeming a previous UTXO
    let actionInputs = {}

    // Check if an existing token was found
    if (previousTokenEnvelope) {
      const unlockingScript = await pushdrop.redeem({
        prevTxId: previousTokenEnvelope.txid,
        outputIndex: previousTokenEnvelope.vout,
        lockingScript: previousTokenEnvelope.outputScript,
        outputAmount: this.config.tokenAmount,
        protocolID: this.config.protocolID,
        keyID: this.config.keyID,
        counterparty: 'anyone'
      })

      // Define the input UTXOs to redeem in this transaction
      actionInputs = {
        [previousTokenEnvelope.txid]: {
          ...previousTokenEnvelope,
          inputs: typeof previousTokenEnvelope.inputs === 'string'
            ? JSON.parse(previousTokenEnvelope.inputs)
            : previousTokenEnvelope.inputs,
          mapiResponses: typeof previousTokenEnvelope.mapiResponses === 'string'
            ? JSON.parse(previousTokenEnvelope.mapiResponses)
            : previousTokenEnvelope.mapiResponses,
          proof: typeof previousTokenEnvelope.proof === 'string'
            ? JSON.parse(previousTokenEnvelope.proof)
            : previousTokenEnvelope.proof,
          outputsToRedeem: [{
            index: previousTokenEnvelope.vout,
            unlockingScript
          }]
        }
      }
    }

    // Build the lockingScript with pushdrop.create() and the transaction with createAction()
    const bitcoinOutputScript = await pushdrop.create({
      fields: [
        Buffer.from(JSON.stringify(verifiableCertificate))
      ],
      protocolID: this.config.protocolID,
      keyID: this.config.keyID,
      counterparty: 'anyone',
      counterpartyCanVerifyMyOwnership: true
    })

    // Redeem any previous UTXOs, and create a new Signia token
    const tx = await SDK.createAction({
      description: 'Create new Signia Token',
      inputs: actionInputs,
      outputs: [{
        satoshis: this.config.tokenAmount,
        script: bitcoinOutputScript
      }]
    })

    await updateProgress('Processing submission...')

    // Register the transaction on the overlay using Authrite
    return await this.makeAuthenticatedRequest(
      'submit',
      { ...tx, topics: this.config.topics }
    )
  }

  /**
   * Publicly attest attributes of a peer.
   * 
   * @param {string} peer - The public key of the peer to certify.
   * @param {object} fieldsToAttest - The fields to attest about a peer.
   * @param {string} certificateType - The type of certification to make about this peer (based on the fields).
   * @param {(message: string) => Promise<void>} [updateProgress] - A callback function to update progress. Default is an empty asynchronous function.
   * @returns {Promise<void>} A promise that resolves when the attestation has been made.
   */
  async certifyPeer(peer: string, fieldsToAttest: Record<string, string>, certificateType: string, updateProgress = async (message) => { }): Promise<object> {
    const identityKey = await SDK.getPublicKey({ identityKey: true })
    const validationKey = nodeCrypto.randomBytes(32).toString('base64')
    const serialNumber = nodeCrypto.randomBytes(32).toString('base64')

    // Encrypt fields
    const fields = {}
    const keyring = {}
    for (const [fieldName, fieldValue] of Object.entries(fieldsToAttest)) {
      // Create a keyID
      const keyID = `${serialNumber} ${fieldName}`

      // Generate a new random field encryption key
      const fieldRevelationKey = nodeCrypto.randomBytes(32).toString('base64')

      // Conceal field
      const concealedField = await CWICrypto.encrypt(
        new TextEncoder().encode(fieldValue),
        await crypto.subtle.importKey(
          'raw',
          Uint8Array.from(Buffer.from(fieldRevelationKey, 'base64')),
          { name: 'AES-GCM' },
          false,
          ['encrypt']
        ),
        'Uint8Array'
      )

      // 1. Derive their private key:
      const derivedPrivateKeyringKey = getPaymentPrivateKey({
        senderPublicKey: peer,
        recipientPrivateKey: '0000000000000000000000000000000000000000000000000000000000000001',
        invoiceNumber: `2-authrite certificate field encryption-${serialNumber} ${fieldName}`,
        returnType: 'babbage-bsv'
      })
      // 2. Derive the sender’s public key:
      const derivedPublicKeyringKey = getPaymentAddress({
        senderPrivateKey: '0000000000000000000000000000000000000000000000000000000000000001',
        recipientPublicKey: peer,
        invoiceNumber: `2-authrite certificate field encryption-${serialNumber} ${fieldName}`,
        returnType: 'babbage-bsv'
      })
      // 3. Use the shared secret between the keys from step 1 and step 2 for decryption.
      const sharedSecret = (derivedPublicKeyringKey.point.mul(derivedPrivateKeyringKey).toBuffer().slice(1)).toString('hex')

      const encryptionKey = await global.crypto.subtle.importKey(
        'raw',
        Uint8Array.from(Buffer.from(sharedSecret, 'hex')),
        {
          name: 'AES-GCM'
        },
        true,
        ['encrypt']
      )
      const encryptedFieldRevelationKeyForAnyone = await CWICrypto.encrypt(new Uint8Array(Buffer.from(fieldRevelationKey, 'base64')), encryptionKey, 'Uint8Array')
      fields[fieldName] = Buffer.from(concealedField).toString('base64')
      keyring[fieldName] = Buffer.from(encryptedFieldRevelationKeyForAnyone).toString('base64')
    }

    if (peer.length !== 66) {
      peer = bsv.PublicKey.fromHex(peer).toCompressed().toString()
    }

    const certificate: any = {
      type: certificateType,
      subject: peer,
      validationKey,
      serialNumber,
      fields,
      certifier: identityKey,
      revocationOutpoint: `000000000000000000000000000000000000000000000000000000000000000000000000`
    }

    const dataToSign = Buffer.from(stringify(certificate))

    // Compute certificate signature
    const signature = await SDK.createSignature({
      data: dataToSign,
      protocolID: [2, `authrite certificate signature ${Buffer.from(certificateType, 'base64').toString('hex')}`],
      keyID: serialNumber,
      counterparty: new bsv.PrivateKey(Buffer.from(validationKey, 'base64').toString('hex')).publicKey.toString()
    })
    certificate.signature = Buffer.from(signature).toString('hex')
    certificate.keyring = keyring
    await updateProgress('Creating a verifiable certificate...')

    // Build the lockingScript with pushdrop.create() and the transaction with createAction()
    const bitcoinOutputScript = await pushdrop.create({
      fields: [
        Buffer.from(JSON.stringify(certificate))
      ],
      protocolID: this.config.protocolID,
      keyID: this.config.keyID,
      counterparty: 'anyone',
      counterpartyCanVerifyMyOwnership: true
    })

    // Redeem any previous UTXOs, and create a new Signia token
    const tx = await SDK.createAction({
      description: 'Create new Signia Token',
      outputs: [{
        satoshis: this.config.tokenAmount,
        script: bitcoinOutputScript,
        basket: 'signia'
      }]
    })

    await updateProgress('Processing submission...')

    // Register the transaction on the overlay using Authrite
    return await this.makeAuthenticatedRequest(
      'submit',
      { ...tx, topics: this.config.topics }
    )
  }

  /**
  * Lists all certifications made to peers.
  * @public
  * @returns {Promise<any[]>}
  */
  async listCertifiedPeers(): Promise<any[]> {
    // Get tokens from the signia peers basket
    const entriesFromBasket = await SDK.getTransactionOutputs({
      basket: 'signia',
      spendable: true,
      includeEnvelope: true
    })

    for (let i = 0; i < entriesFromBasket.length; i++) {
      try {
        const o = entriesFromBasket[i]


        const result = pushdrop.decode({
          script: o.outputScript,
          fieldFormat: 'buffer'
        })

        const certificate = JSON.parse(result.fields[0])


        // Ensure result.lockingPublicKey came from result.fields[0]
        // Either the certifier or the subject must control the Signia token.
        const expectedSubject = getPaymentAddress({
          senderPrivateKey: '0000000000000000000000000000000000000000000000000000000000000001',
          recipientPublicKey: certificate.subject,
          invoiceNumber: '1-signia-1',
          returnType: 'publicKey'
        })
        const expectedCertifier = getPaymentAddress({
          senderPrivateKey: '0000000000000000000000000000000000000000000000000000000000000001',
          recipientPublicKey: certificate.certifier,
          invoiceNumber: '1-signia-1',
          returnType: 'publicKey'
        })

        // Make sure keys match
        if (expectedSubject !== result.lockingPublicKey && expectedCertifier !== result.lockingPublicKey) throw 'bad'

        // Use ECDSA to verify signature
        const hasValidSignature = bsv.crypto.ECDSA.verify(
          bsv.crypto.Hash.sha256(Buffer.concat(result.fields)),
          bsv.crypto.Signature.fromString(result.signature),
          bsv.PublicKey.fromString(result.lockingPublicKey)
        )
        if (!hasValidSignature) throw 'bad2'

        // Ensure validity of the certificate signature
        if (!verifyCertificateSignature(certificate)) throw 'bad3'
      } catch (e) {
        console.error(i, e)
      }
    }

    return await this.parseResults(entriesFromBasket)
  }

  /**
   * Revokes a peer certification
   * @public
   * @param entry - Peer certification to revoke
   */
  async revokeCertifiedPeer(entry): Promise<void> {
    // Create an unlocking script that spends the ProtoMap token
    const unlockingScript = await pushdrop.redeem({
      prevTxId: entry.txid,
      outputIndex: entry.vout,
      lockingScript: entry.outputScript,
      outputAmount: entry.amount,
      protocolID: this.config.protocolID,
      keyID: this.config.keyID,
      counterparty: 'anyone'
    })

    // Create a new transaction with no outputs
    const tx = await SDK.createAction({
      description: `Remove peer certification`,
      inputs: {
        [entry.txid as string]: {
          ...entry.envelope,
          satoshis: entry.amount,
          outputsToRedeem: [{
            index: entry.vout,
            unlockingScript
          }]
        }
      }
    })

    // Notify Confederacy that the entry is removed from the registry
    const response = await new Authrite().request(
      `${this.config.confederacyHost}/submit`,
      {
        method: 'POST',
        body: {
          ...tx,
          topics: this.config.topics // TODO: Also notify certificate revocation overlay
        }
      }
    )
    return await response.json()
  }


  /**
   * Example higher level lookup function
   * @param {string} identityKey 
   * @returns {object} - with identity information
   */
  async getNameFromKey(identityKey: string, certifiers: string[]): Promise<object> {
    // Validate params
    if (!identityKey) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the identity key to query by!')
      throw e
    }

    const [certificate]: Certificate[] = await this.discoverByIdentityKey(identityKey, certifiers) as Certificate[]
    if (!certificate || !certificate.decryptedFields || !certificate.decryptedFields.firstName || !certificate.decryptedFields.lastName) {
      return {}
    }
    const fields = certificate.decryptedFields
    return {
      firstName: fields.firstName,
      lastName: fields.lastName
    }
  }

  /**
   * Query the lookup service for the given attribute (and optional certifiers) and parseResults
   * @public 
   * @param {object} attributes 
   * @param {string[]} certifiers
   * @returns {Promise<object[]>}
   */
  async discoverByAttributes(attributes: object, certifiers: string[]): Promise<object[]> {
    // Validate params
    if (!attributes || Object.keys(attributes).length === 0) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the attributes to query by!')
      throw e
    }
    if (!certifiers || certifiers.length === 0) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the certifiers you trust!')
      throw e
    }

    // Request data from the Signia lookup service
    const results = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { attributes, certifiers }
      }
    )
    // Parse out the relevant data
    const parsedResults = await this.parseResults(results)
    return parsedResults
  }

  /**
   * Query the lookup service for the given identity key (and optional certifiers) parseResults
   * @public
   * @param {string} identityKey 
   * @param {string[]} certifiers 
   * @returns {Promise<object[]>}
   */
  async discoverByIdentityKey(identityKey: string, certifiers: string[]): Promise<object[]> {
    // Validate params
    if (!identityKey) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the identity key to query by!')
      throw e
    }
    if (!certifiers || certifiers.length === 0) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the certifiers you trust!')
      throw e
    }

    // Lookup data based on identity key
    const results = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { identityKey, certifiers }
      }
    )
    // Parse out the relevant data
    const parsedResults = await this.parseResults(results)
    return parsedResults
  }

  /**
   * Query the lookup service for the given certifiers, returning all results for the certifiers parseResults
   * @public
   * @param {string[]} certifiers 
   * @returns {Promise<object[]>}
   */
  async discoverByCertifier(certifiers: string[]): Promise<object[]> {
    // Validate params
    if (!certifiers || certifiers.length === 0) {
      const e = new CwiError('ERR_MISSING_PARAMETER', 'Please provide the certifiers you trust!')
      throw e
    }

    const results: Output[] = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { certifiers }
      }
    )
    // Parse out the relevant data
    const parsedResults = await this.parseResults(results)
    return parsedResults
  }

  /**
  * Internal func: Parse the returned UTXOs Decrypt and verify the certificates and signatures Return the set of identity keys, certificates and decrypted certificate fields
  * @param {Output[]} outputs
  * @returns {Promise<object[]>}
  */
  private async parseResults(outputs: Output[]): Promise<object[]> {
    const parsedResults: object[] = []
    for (const output of outputs) {
      try {
        // Decode the Signia token fields from the Bitcoin outputScript
        const result = pushdrop.decode({
          script: output.outputScript,
          fieldFormat: 'buffer'
        })
        console.log(result)

        // Parse out the certificate and relevant data
        const certificate = JSON.parse((result as Certificate).fields[0].toString())
        console.log(certificate)
        const decryptedFields = await decryptCertificateFields(certificate, certificate.keyring, '0000000000000000000000000000000000000000000000000000000000000001')
        console.log(decryptedFields)
        parsedResults.push({ ...certificate, decryptedFields })
      } catch (error) {
        console.error(error)
        // do nothing
      }
    }
    return parsedResults
  }
  /**
   * Helper function for making Authrite HTTP requests
   * @param {string} route - name of lookup service action
   * @param {object} body - of request
   * @returns {object} - result of HTTP request
   */
  private async makeAuthenticatedRequest(route: string, body: object): Promise<Output[]> {
    // Make a post request over Authrite
    const result = await this.authrite.request(`${this.config.confederacyHost}/${route}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body
    })
    return await result.json()
  }
}

// Helper type decelerations
interface Certificate {
  type: string,
  subject: string,
  validationKey: string,
  serialNumber: string,
  fields: object,
  certifier: string,
  revocationOutpoint: string,
  signature: string,
  keyring: object,
  decryptedFields: { [key: string]: string }
}