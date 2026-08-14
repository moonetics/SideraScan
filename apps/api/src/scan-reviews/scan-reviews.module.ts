import { Module } from "@nestjs/common";
import { MonitoringModule } from "../monitoring/monitoring.module";
import { PrismaService } from "../prisma/prisma.service";
import { ScanReviewsController } from "./scan-reviews.controller";
import { ScanReviewsService } from "./scan-reviews.service";

@Module({
  imports: [MonitoringModule],
  controllers: [ScanReviewsController],
  providers: [ScanReviewsService, PrismaService],
  exports: [ScanReviewsService]
})
export class ScanReviewsModule {}
