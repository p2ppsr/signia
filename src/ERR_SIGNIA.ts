import { CwiError } from 'cwi-base'

export class ERR_SIGNIA_CERT_NOT_FOUND extends CwiError { constructor(description?: string) { super('ERR_CERT_NOT_FOUND', description || 'A matching certificate was not found!') } }
export class ERR_SIGNIA_MISSING_PARAM extends CwiError { constructor(description?: string) { super('ERR_SIGNIA_MISSING_PARAM', description || 'You must provide all required params.') } }