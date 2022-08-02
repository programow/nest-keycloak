import { SetMetadata, CustomDecorator } from '@nestjs/common'

export const META_CLIENT_SCOPE = 'keycloak-client-scope'

export const DefineClientScope = (scope: string): CustomDecorator<string> =>
  SetMetadata<string, string>(META_CLIENT_SCOPE, scope)
