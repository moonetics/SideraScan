import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from "@nestjs/common";
import { env } from "../config/env";
import { AuthService } from "./auth.service";
import type { AuthenticatedRequest } from "./auth.types";

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest>();
    const token = request.cookies?.[env.SESSION_COOKIE_NAME];

    if (!token) {
      throw new UnauthorizedException();
    }

    request.user = await this.authService.getUserFromSession(token);
    return true;
  }
}

