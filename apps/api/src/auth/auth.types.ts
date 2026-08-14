import type { GlobalRole, UserStatus } from "@prisma/client";
import type { FastifyRequest } from "fastify";

export type AuthUser = {
  id: string;
  email: string;
  username: string;
  displayName: string;
  globalRole: GlobalRole;
  status: UserStatus;
};

export type AuthenticatedRequest = FastifyRequest & {
  user?: AuthUser;
};

