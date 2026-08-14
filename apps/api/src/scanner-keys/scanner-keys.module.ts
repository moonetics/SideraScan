import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { PrismaService } from "../prisma/prisma.service";
import {
  AccountScannerKeysController,
  ScannerKeysController
} from "./scanner-keys.controller";
import { ScannerKeysService } from "./scanner-keys.service";

@Module({
  imports: [AuthModule],
  controllers: [ScannerKeysController, AccountScannerKeysController],
  providers: [ScannerKeysService, AuditService, PrismaService]
})
export class ScannerKeysModule {}

