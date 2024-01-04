/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-empty-function */
import SDK from '@babbage/sdk'
import pushdrop from 'pushdrop'
import bsv from 'babbage-bsv'
import { Authrite, AuthriteClient } from 'authrite-js'
import { decryptCertificateFields } from 'authrite-utils'
import { ConfederacyConfig } from './utils/ConfederacyConfig'
import { Output } from 'confederacy-base'
import { ERR_BAD_REQUEST } from 'cwi-base'
import stringify from 'json-stable-stringify'
import * as CWICrypto from 'cwi-crypto'
import nodeCrypto from 'crypto'

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
      if (identifyResponse.status !== 'success' || identifyResponse.certifierPublicKey !== certifierPublicKey) {
        throw new ERR_BAD_REQUEST('Unexpected Identify Certifier Response. Check certifierPublicKey.')
      }

      // TODO: Consider appropriate response
      if (JSON.stringify(Object.keys(fieldsToReveal)) !== JSON.stringify(identifyResponse.certificateTypes[0][1])) {
        throw new ERR_BAD_REQUEST('Fields to reveal must match the certifier fields for the given certificate type.')
      }

      // If the attributes have been preVerified through some other process (such as Persona KYC API iFrame in a UI),
      // Then we should send that data to the backend for confirmation before proceeding
      if (preVerifiedData) {
        // Is confirmCertificate necessary?
        await updateProgress('Checking verification status...')
        const verificationResponse = await client.createSignedRequest('/checkVerification', {
          preVerifiedData,
          certificateFields: fieldsToReveal
        })

        // Check user has completed KYC verification
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

        // TODO: Consider appropriate verification response messages
        if (verificationResponse.status === 'passed') {
          if (JSON.stringify(verificationResponse.verifiedAttributes) !== JSON.stringify(fieldsToReveal)) {
            throw new Error('The verified attributes do not match the fields to reveal.')
          }
        } else {
          throw new Error('Certifier failed to validate attributes!')
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

      // Encrypt key used to conceal/reveal field
      const encryptedFieldRevelationKeyForAnyone = await SDK.encrypt({
        protocolID: [2, 'authrite certificate field encryption'],
        keyID,
        counterparty: new bsv.PrivateKey('0000000000000000000000000000000000000000000000000000000000000001').publicKey.toString('hex'), // anyone (1 x G)
        plaintext: new Uint8Array(Buffer.from(fieldRevelationKey, 'base64'))
      })
      fields[fieldName] = Buffer.from(concealedField).toString('base64')
      keyring[fieldName] = Buffer.from(encryptedFieldRevelationKeyForAnyone).toString('base64')
    }

    if (peer.length !== 66) {
      peer = bsv.PublicKey.fromHex(peer).toCompressed().toString()
    }
    const revocationKeyID = nodeCrypto.randomBytes(32).toString('base64')

    const revocationScript = await pushdrop.create({
      fields: [serialNumber],
      protocolID: [0, 'certificate revocation'],
      keyID: revocationKeyID
    })

    // Create certificate to sign
    const certificate: any = {
      type: certificateType,
      subject: peer,
      validationKey,
      serialNumber,
      fields,
      certifier: identityKey
    }

    const revocationTX = await SDK.createAction({
      outputs: [{
        satoshis: 1000,
        script: revocationScript,
        basket: 'signia peer certificates',
        customInstructions: JSON.stringify({
          ...certificate,
          revocationKeyID
        })
      }],
      description: 'Issue a certificate to a peer'
    })

    certificate.revocationOutpoint = `${revocationTX.txid}00000000`

    const dataToSign = Buffer.from(stringify(certificate))

    // Compute certificate signature
    const signature = await SDK.createSignature({
      data: dataToSign,
      protocolID: [2, `authrite certificate signature ${certificateType}`],
      keyID: serialNumber,
      returnType: 'string'
    })
    certificate.signature = signature.toString('hex')
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
   * Example higher level lookup function
   * @param identityKey 
   * @returns {object} - with identity information
   */
  async getNameFromKey(identityKey: string, certifiers: string[]): Promise<object> {
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
   * @param attributes 
   * @param certifiers
   * @returns {object[]}
   */
  async discoverByAttributes(attributes: object, certifiers: string[]): Promise<object[]> {
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
   * @param identityKey 
   * @param certifiers 
   * @returns {object[]}
   */
  async discoverByIdentityKey(identityKey: string, certifiers: string[]): Promise<object[]> {
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
   * @param certifiers 
   * @returns {object[]}
   */
  async discoverByCertifier(certifiers: string[]): Promise<object[]> {
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
   * @returns {object}
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

        // Parse out the certificate and relevant data
        const certificate = JSON.parse((result as Certificate).fields[0].toString())
        const decryptedFields = await decryptCertificateFields(certificate, certificate.keyring, '0000000000000000000000000000000000000000000000000000000000000001')
        parsedResults.push({ ...certificate, decryptedFields })
      } catch (error) {
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
  signature: string, // ?
  keyring: object,
  decryptedFields: { [key: string]: string }
}