import { CwiError } from 'cwi-base'

export class ERR_SIGNIA_CERT_NOT_FOUND extends CwiError { constructor(description?: string) { super('ERR_CERT_NOT_FOUND', description || 'A matching certificate was not found!') } }