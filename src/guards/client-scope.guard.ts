import {
  CanActivate,
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  Inject,
} from '@nestjs/common'
import { KeycloakService } from '../service'
import { Reflector } from '@nestjs/core'
import { META_PUBLIC } from '../decorators/public.decorator'
import { KeycloakUser } from '../@types/user'
import { extractRequest } from '../utils/extract-request'
import { META_CLIENT_SCOPE } from '../decorators/client-scope.decorator'
import jwtDecode from 'jwt-decode'

@Injectable()
export class ClientScopeGuard implements CanActivate {
  logger = new Logger(ClientScopeGuard.name)

  constructor(
    @Inject(KeycloakService)
    private keycloak: KeycloakService,
    @Inject(Reflector.name)
    private readonly reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const necessaryScope: string = this.reflector.get<string>(
      META_CLIENT_SCOPE,
      context.getHandler()
    )

    //TODO: consider using cache, in this case, set cache method in registerAsync(memory, redis, etc)

    const request = extractRequest(context)
    const jwt = this.extractJwt(request.headers)

    try {
      const result = await this.keycloak.connect.grantManager.validateAccessToken(jwt)

      if (typeof result === 'string') {
        const decodedToken = jwtDecode<any>(result)
        return decodedToken.scope.split(' ').includes(necessaryScope)
      }
    } catch (error) {
      this.logger.warn(`Error occurred validating token`, error)
    }

    throw new UnauthorizedException()
  }

  private extractJwt({ authorization }: Record<string, string>): string {
    if (!authorization) {
      throw new UnauthorizedException()
    }

    const [type, payload] = authorization.split(' ')

    if (type.toLowerCase() !== 'bearer') {
      throw new UnauthorizedException()
    }

    return payload
  }
}
