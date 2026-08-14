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
import { AccountRole, AccountStatus } from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { AccountsService } from "./accounts.service";

const createAccountSchema = z.object({
  name: z.string().trim().min(2).max(160),
  slug: z.string().trim().min(2).max(120).optional()
});

const updateAccountSchema = z
  .object({
    name: z.string().trim().min(2).max(160).optional(),
    slug: z.string().trim().min(2).max(120).optional(),
    status: z.enum(AccountStatus).optional()
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one account field is required"
  });

const assignUserSchema = z.object({
  userId: z.string().uuid(),
  role: z.enum(AccountRole)
});

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller("accounts")
@UseGuards(SessionAuthGuard)
export class AccountsController {
  constructor(private readonly accountsService: AccountsService) {}

  @Post()
  createAccount(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.accountsService.createAccount(
      getRequestUser(request),
      parseBody(createAccountSchema, body),
      request.ip
    );
  }

  @Get()
  listAccounts(@Req() request: AuthenticatedRequest) {
    return this.accountsService.listAccounts(getRequestUser(request));
  }

  @Get(":id")
  getAccount(
    @Req() request: AuthenticatedRequest,
    @Param("id") accountId: string
  ) {
    return this.accountsService.getAccount(getRequestUser(request), accountId);
  }

  @Patch(":id")
  updateAccount(
    @Req() request: AuthenticatedRequest,
    @Param("id") accountId: string,
    @Body() body: unknown
  ) {
    return this.accountsService.updateAccount(
      getRequestUser(request),
      accountId,
      parseBody(updateAccountSchema, body),
      request.ip
    );
  }

  @Post(":id/suspend")
  suspendAccount(
    @Req() request: AuthenticatedRequest,
    @Param("id") accountId: string
  ) {
    return this.accountsService.suspendAccount(
      getRequestUser(request),
      accountId,
      request.ip
    );
  }

  @Post(":id/users")
  assignUser(
    @Req() request: AuthenticatedRequest,
    @Param("id") accountId: string,
    @Body() body: unknown
  ) {
    return this.accountsService.assignUser(
      getRequestUser(request),
      accountId,
      parseBody(assignUserSchema, body),
      request.ip
    );
  }
}

