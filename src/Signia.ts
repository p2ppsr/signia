/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-empty-function */
import SDK from '@babbage/sdk'
import pushdrop from 'pushdrop'
import { Authrite } from 'authrite-js'
import { ConfederacyConfig } from './utils/ConfederacyConfig'
import { ERR_SIGNIA_CERT_NOT_FOUND } from './ERR_SIGNIA'
import { Output } from '@cwi/confederacy'

// TODO: Rethink where this should be defined
const defaultConfig = new ConfederacyConfig(
  'https://confederacy.babbage.systems',
  [0, 'signia'],
  '1',
  1000,
  ['signia'],
  undefined,
  undefined,
  false,
  false,
  'localToSelf'
)

/**
 * A system for decentralized identity management
 * @public
 */
export class Signia {
  private authrite: Authrite
  /**
   * Constructs a new Signia instance
   * @param {ConfederacyConfig} config 
   */
  constructor (
    public config: ConfederacyConfig = defaultConfig,
  ) {
    this.authrite = new Authrite(this.config.authriteConfig)
  }
  
  /**
   * Publicly reveal identity attributes to the Signia overlay
   * @public
   * @param {Array<string>} fieldsToReveal 
   * @returns {object} - submission confirmation from the overlay
   */
  async publiclyRevealIdentityAttributes(certifier: string, type: string, fieldsToReveal:string[]): Promise<object> {

    // Search for a matching certificate
    const [certificate] = await SDK.getCertificates({
      certifiers: [certifier],
      types: {
        [type]: fieldsToReveal
      }
    })

    // Make sure a certificate was found
    if (!certificate) throw new ERR_SIGNIA_CERT_NOT_FOUND(`A matching certificate was not found for certifier ${certifier} and type ${type}!`)

    // Get an anyone verifiable certificate
    const verifiableCertificate = await SDK.proveCertificate({
      certificate,
      fieldsToReveal,
      verifierPublicIdentityKey: 'anyone'
    })

    // Check if an existing Signia token is found
    // TODO: Check return value
    const [previousTokenEnvelope]: Output[] = await this.makeAuthenticatedRequest(
      'lookup',
      { certifier }
    )

    // No inputs, unless redeeming a previous UTXO
    let actionInputs = {}

    // Check if an existing token was found
    // TODO: Import UTXO def for type checking
    if (previousTokenEnvelope) {
      const unlockingScript = await pushdrop.redeem({
        prevTxId: previousTokenEnvelope.txid,
        outputIndex: previousTokenEnvelope.vout,
        lockingScript: previousTokenEnvelope.outputScript,
        outputAmount: this.config.tokenAmount,
        protocolID: this.config.protocolID,
        keyID: this.config.keyID,
        counterparty: 'self'
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
      keyID: this.config.keyID
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
   * Query the lookup service for the given attribute (and optional certifier) and parseResults
   * @public 
   * @param attribute 
   * @param certifier 
   * @returns {object}
   */
  async discoverByAttribute(attribute: string, certifier?: string): Promise<object> {
    
    // Request data from the Signia lookup service
    return await this.makeAuthenticatedRequest(
      'lookup',
      { attribute, certifier }
    )
  }

  /**
   * Query the lookup service for the given identity key (and optional certifier) parseResults
   * @public
   * @param identityKey 
   * @param certifier 
   * @returns {object}
   */
  async discoverByIdentityKey(identityKey: string, certifier?: string): Promise<object> {
    // Lookup identity data based on identity key
    return await this.makeAuthenticatedRequest(
      'lookup',
      { identityKey, certifier }
    )
  }

  /**
   * Query the lookup service for the given certifier, returning all results for the certifier parseResults
   * @public
   * @param certifier 
   * @returns {object}
   */
  async discoverByCertifier(certifier: string): Promise<object> {
    return await this.makeAuthenticatedRequest(
      'lookup',
      { certifier }
    )
  }

  /**
   * Internal func: Parse the returned UTXOs Decrypt and verify the certificates and signatures Return the set of identity keys, certificates and decrypted certificate fields
   * @returns {object}
   */
  // private async parseResults(data: object): Promise<object> {
  //   // TODO: Implement any necessary parsing -----------------------------
  //   throw new Error('Parsing not implemented!')
  // }
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
    // const jsonResult = await result.json()
    // return await this.parseResults(jsonResult)
    return await result.json()
  }
}