/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-empty-function */
import SDK from '@babbage/sdk'
import pushdrop from 'pushdrop'
import { Authrite } from 'authrite-js'
import { ConfederacyConfig } from './models/OverlayConfig'

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
  constructor (
    public config: ConfederacyConfig = defaultConfig
  ) {}
  
  /**
   * Publicly reveal identity attributes to the Signia overlay
   * @public
   * @param fieldsToReveal 
   * @returns {object} - submission confirmation from the overlay
   */
  async publiclyRevealIdentityAttributes(fieldsToReveal:Array<string>): Promise<object>{

    // TODO: Consider error handling
    const certificates = await SDK.getCertificates()

    // Call proveCertificate for the anyone verifier
    const verifiableCertificate = await SDK.proveCertificate({
      certificate: certificates[0],
      fieldsToReveal,
      verifierPublicIdentityKey: 'anyone'
    })

    // Build the output with pushdrop.create() and the transaction with createAction()
    const bitcoinOutputScript = await pushdrop.create({
      fields: [
        // identityKey required as a field?
        Buffer.from(JSON.stringify(verifiableCertificate))
      ],
      protocolID: this.config.protocolID,
      keyID: this.config.keyID
    })

    // Do we care if there is an existing Signia token?
    const tx = await SDK.createAction({
      description: 'Create new Signia Token',
      outputs: [{
        satoshis: this.config.tokenAmount,
        script: bitcoinOutputScript
      }]
    })

    // Register the transaction on the overlay using Authrite
    const client = new Authrite(this.config.authriteConfig)
    const result = await client.request(`${this.config.confederacyHost}/submit`, {
      method: 'post',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ...tx,
        topics: this.config.topics
      })
    })

    // Return the confirmation from the overlay node
    return await result.json()
  }

  /**
   * Query the lookup service for the given attribute (and optional certifier) and parseResults
   * @public 
   * @param attribute 
   * @param certifier 
   * @returns {object}
   */
  async discoverByAttribute(attribute: string, certifier?: string): Promise<object> {
    // TODO
    return {}
  }

  /**
   * Query the lookup service for the given identity key (and optional certifier) parseResults
   * @public
   * @param identityKey 
   * @param certifier 
   * @returns {object}
   */
  async discoverByIdentityKey(identityKey: string, certifier?: string): Promise<object> {
    // TODO
    return {}
  }

  /**
   * Query the lookup service for the given certifier, returning all results for the certifier parseResults
   * @public
   * @param certifier 
   * @returns {object}
   */
  async discoverByCertifier(certifier: string): Promise<object> {
    // TODO
    return {}
  }

  /**
   * Internal func: Parse the returned UTXOs Decrypt and verify the certificates and signatures Return the set of identity keys, certificates and decrypted certificate fields
   * @returns {object}
   */
  private async parseResults(): Promise<object> {
    // TODO
    return {}
  }
}