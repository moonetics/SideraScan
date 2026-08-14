import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Req,
  UseGuards
} from "@nestjs/common";
import { GlobalRole, UserStatus } from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { UsersService } from "./users.service";

const createUserSchema = z.object({
  email: z.string().trim().email().max(255),
  username: z.string().trim().min(3).max(80),
  displayName: z.string().trim().min(1).max(120),
  password: z.string().min(12).max(128),
  globalRole: z.enum(GlobalRole).default(GlobalRole.USER),
  status: z.enum(UserStatus).default(UserStatus.ACTIVE)
});

const updateUserSchema = z
  .object({
    email: z.string().trim().email().max(255).optional(),
    username: z.string().trim().min(3).max(80).optional(),
    displayName: z.string().trim().min(1).max(120).optional(),
    password: z.string().min(12).max(128).optional(),
    globalRole: z.enum(GlobalRole).optional(),
    status: z.enum(UserStatus).optional()
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one user field is required"
  });

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller("users")
@UseGuards(SessionAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  createUser(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.usersService.createUser(
      getRequestUser(request),
      parseBody(createUserSchema, body),
      request.ip
    );
  }

  @Get()
  listUsers(@Req() request: AuthenticatedRequest) {
    return this.usersService.listUsers(getRequestUser(request));
  }

  @Patch(":id")
  updateUser(
    @Req() request: AuthenticatedRequest,
    @Param("id") userId: string,
    @Body() body: unknown
  ) {
    return this.usersService.updateUser(
      getRequestUser(request),
      userId,
      parseBody(updateUserSchema, body),
      request.ip
    );
  }

  @Post(":id/disable")
  disableUser(
    @Req() request: AuthenticatedRequest,
    @Param("id") userId: string
  ) {
    return this.usersService.disableUser(
      getRequestUser(request),
      userId,
      request.ip
    );
  }
}

