import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards
} from "@nestjs/common";
import type { FastifyReply } from "fastify";
import { z } from "zod";
import { env } from "../config/env";
import { AuthService } from "./auth.service";
import type { AuthenticatedRequest } from "./auth.types";
import { SessionAuthGuard } from "./session-auth.guard";

const loginSchema = z.object({
  identifier: z.string().trim().min(1),
  password: z.string().min(1)
});

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("login")
  @HttpCode(200)
  async login(
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply
  ) {
    const parsed = loginSchema.safeParse(body);

    if (!parsed.success) {
      throw new BadRequestException("Invalid login payload");
    }

    const result = await this.authService.login(
      parsed.data.identifier,
      parsed.data.password
    );

    reply.setCookie(env.SESSION_COOKIE_NAME, result.token, {
      httpOnly: true,
      maxAge: env.SESSION_TTL_SECONDS,
      path: "/",
      sameSite: "lax",
      secure: env.NODE_ENV === "production"
    });

    return { user: result.user };
  }

  @Post("logout")
  @HttpCode(200)
  logout(@Res({ passthrough: true }) reply: FastifyReply) {
    reply.clearCookie(env.SESSION_COOKIE_NAME, {
      path: "/",
      sameSite: "lax",
      secure: env.NODE_ENV === "production"
    });

    return { status: "ok" };
  }

  @Get("me")
  @UseGuards(SessionAuthGuard)
  me(@Req() request: AuthenticatedRequest) {
    return { user: request.user };
  }
}
