import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { MonitoringModule } from "../monitoring/monitoring.module";
import { PrismaService } from "../prisma/prisma.service";
import { ScanReviewsModule } from "../scan-reviews/scan-reviews.module";
import { ScansController } from "./scans.controller";
import { ScansService } from "./scans.service";

@Module({
  imports: [AuthModule, ScanReviewsModule, MonitoringModule],
  controllers: [ScansController],
  providers: [ScansService, PrismaService, AuditService]
})
export class ScansModule {}
