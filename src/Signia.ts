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

// TODO: Rethink where this should be defined
const defaultConfig = new ConfederacyConfig(
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

const SIGNICERT_TYPE = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
const SIGNICERT_PUBLIC_KEY = '036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528'
const SIGNICERT_URL = 'https://signicert.babbage.systems'

/**
 * A system for decentralized identity management
 * @public
 */
export class Signia {
  private authrite: AuthriteClient
  /**
   * Constructs a new Signia instance
   * @param {ConfederacyConfig} config 
   * @param {string} certifierUrl
   */
  constructor (
    public config: ConfederacyConfig = defaultConfig, // Note: Named params might be better
    public certifierUrl: string = SIGNICERT_URL,
    public certifierPublicKey: string = SIGNICERT_PUBLIC_KEY
  ) {
    this.authrite = new Authrite(this.config.authriteConfig)
  }
  
  /**
   * Publicly reveal identity attributes to the Signia overlay
   * @public
   * @param {Array<string>} fieldsToReveal 
   * @returns {object} - submission confirmation from the overlay
   */
  async publiclyRevealIdentityAttributes(fieldsToReveal:object, newCertificate?: boolean, verificationId = 'notVerified'): Promise<object> {
    // Search for a matching certificate
    const certificates = await SDK.getCertificates({
      certifiers: [this.certifierPublicKey],
      types: {
        [SIGNICERT_TYPE]: Object.keys(fieldsToReveal)
      }
    })

    // If no certificate is found, the user needs to request one before revealing particular attributes
    let certificate: Certificate
    if (!certificates || certificates.length === 0 || newCertificate === true) {
      // Create a new Authrite client for interacting with the SigniCert server
      const client = new AuthriteClient(this.certifierUrl)

      // Check if the server is who we think it is
      const identifyResponse = await client.createSignedRequest('/identify', {})
      if (identifyResponse.status !== 'success' || identifyResponse.certifierPublicKey !== this.certifierPublicKey) {
        throw new ERR_BAD_REQUEST('Unexpected Identify Certifier Response. Check certifierPublicKey.')
      }

      // Is confirmCertificate necessary?
      // Check if the user's identity has been verified
      const results = await client.createSignedRequest('/checkVerification', {
        verificationId,
        certificateFields: fieldsToReveal
      })

      // Check user has completed KYC verification
      if (results.status !== 'verified' || !results.uhrpURL) {
        throw new Error('User identity has not verified!')
      }

      // Update the fields to include the profile photo UHRP URL
      fieldsToReveal = {...fieldsToReveal, profilePhoto: results.uhrpURL}
      
      // Create a new certificate
      certificate = await client.createCertificate({
        certificateType: SIGNICERT_TYPE,
        fieldObject: fieldsToReveal,
        certifierUrl: this.certifierUrl,
        certifierPublicKey: this.certifierPublicKey
      })
    } else {
      // Use the latest certificate (for now)
      // TODO: Consider best practices for this and removal of certificates
      certificate = certificates[certificates.length - 1]
    }

    // Get an anyone verifiable certificate
    const verifiableCertificate = await SDK.proveCertificate({
      certificate: certificate,
      fieldsToReveal: Object.keys(fieldsToReveal),
      verifierPublicIdentityKey: new bsv.PrivateKey('0000000000000000000000000000000000000000000000000000000000000001').publicKey.toString('hex')
    })

    // Check if an existing Signia token is found ??
    const lookupResults: Output[] = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { 
          identityKey: certificate.subject,
          certifier: this.certifierPublicKey 
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

    // Build the output with pushdrop.create() and the transaction with createAction()
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
  async getNameFromKey(identityKey: string): Promise<object> {
    const [certificate]:Certificate[] = await this.discoverByIdentityKey(identityKey) as Certificate[]
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
   * Query the lookup service for the given attribute (and optional certifier) and parseResults
   * @public 
   * @param attributes 
   * @param certifier 
   * @returns {object[]}
   */
  async discoverByAttributes(attributes: object, certifier: string = this.certifierPublicKey): Promise<object[]> {
    // Request data from the Signia lookup service
    const results =  await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { attributes, certifier }
      }
    )
    // Parse out the relevant data
    const parsedResults = await this.parseResults(results)
    return parsedResults
  }

  /**
   * Query the lookup service for the given identity key (and optional certifier) parseResults
   * @public
   * @param identityKey 
   * @param certifier 
   * @returns {object[]}
   */
  async discoverByIdentityKey(identityKey: string, certifier: string = this.certifierPublicKey): Promise<object[]> {
    // Lookup identity data based on identity key
    const results = await this.makeAuthenticatedRequest(
      'lookup',
      { 
        provider: 'Signia',
        query: { identityKey, certifier }
      }
    )
    // Parse out the relevant data
    const parsedResults = await this.parseResults(results)
    return parsedResults
  }

  /**
   * Query the lookup service for the given certifier, returning all results for the certifier parseResults
   * @public
   * @param certifier 
   * @returns {object[]}
   */
  async discoverByCertifier(certifier: string = this.certifierPublicKey): Promise<object[]> {
    const results: Output[] = await this.makeAuthenticatedRequest(
      'lookup',
      {
        provider: 'Signia',
        query: { certifier }
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
    const parsedResults:object[] = []
    for (const output of outputs) {
      try {
        // Decode the Signia token fields from the Bitcoin outputScript
        const result = pushdrop.decode({
          script: output.outputScript,
          fieldFormat: 'buffer'
        })

        // Parse out the certificate and relevant data
        const certificate =  JSON.parse((result as Certificate).fields[0].toString())
        const decryptedFields = await decryptCertificateFields(certificate, certificate.keyring, '0000000000000000000000000000000000000000000000000000000000000001')
        parsedResults.push({...certificate, decryptedFields})
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
  decryptedFields: SigniaFields
}

interface SigniaFields {
  firstName: string,
  lastName: string,
  profilePhoto: string
}