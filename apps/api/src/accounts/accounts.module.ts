import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { PrismaService } from "../prisma/prisma.service";
import { AccountsController } from "./accounts.controller";
import { AccountsService } from "./accounts.service";

@Module({
  imports: [AuthModule],
  controllers: [AccountsController],
  providers: [AccountsService, AuditService, PrismaService]
})
export class AccountsModule {}
