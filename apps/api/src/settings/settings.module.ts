import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { MonitoringModule } from "../monitoring/monitoring.module";
import { PrismaService } from "../prisma/prisma.service";
import { SettingsController } from "./settings.controller";
import { SettingsService } from "./settings.service";

@Module({
  imports: [AuthModule, MonitoringModule],
  controllers: [SettingsController],
  providers: [SettingsService, PrismaService, AuditService]
})
export class SettingsModule {}
