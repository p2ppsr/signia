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
      ['kvstore'],
      undefined,
      undefined,
      false,
      false,
      'localToSelf'
  )

/**
 * A system for tracing vehicle history
 * @public
 */
export class Signia {
  constructor (
    public tokenValue: number = 1, 
    public config: ConfederacyConfig = defaultConfig
  ) {}
  
  async publiclyRevealIdentityAttributes(fieldsToReveal:Array<string>) {

    // try catch needed here?
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

    // Build the output with pushdrop.create() and the transaction with createAction()
    // Do we care if there is an existing Signia token?
    const tx = await SDK.createAction({
      description: 'Create new Signia Token',
      outputs: [{
        satoshis: this.tokenValue,
        script: bitcoinOutputScript
      }
      ]
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
    return await result.json()

    /**
     * Return the confirmation from the overlay node
     */
  }

  // Query the lookup service for the given attribute (and optional certifier) and parseResults
  async discoverByAttribute() {

  }
  // which will Query the lookup service for the given identity key (and optional certifier) parseResults
  async discoverByIdentityKey() {

  }

  // which will Query the lookup service for the given certifier, returning all results for the certifier parseResults
  async discoverByCertifier() {

  }
  // Internal func: Parse the returned UTXOs Decrypt and verify the certificates and signatures Return the set of identity keys, certificates and decrypted certificate fields
  private async parseResults() {
    
  }
}