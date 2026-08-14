import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { MonitoringService } from "../monitoring/monitoring.service";
import { PrismaService } from "../prisma/prisma.service";
import { ExecutorIntelligenceController } from "./executor-intelligence.controller";
import { ExecutorIntelligenceService } from "./executor-intelligence.service";

@Module({
  imports: [AuthModule],
  controllers: [ExecutorIntelligenceController],
  providers: [
    ExecutorIntelligenceService,
    PrismaService,
    AuditService,
    MonitoringService
  ],
  exports: [ExecutorIntelligenceService]
})
export class ExecutorIntelligenceModule {}
