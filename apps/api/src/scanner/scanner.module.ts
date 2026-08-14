import { Module } from "@nestjs/common";
import { DetectionsModule } from "../detections/detections.module";
import { MonitoringModule } from "../monitoring/monitoring.module";
import { PrismaService } from "../prisma/prisma.service";
import { ScanReviewsModule } from "../scan-reviews/scan-reviews.module";
import { ScannerController } from "./scanner.controller";
import { ScannerService } from "./scanner.service";

@Module({
  imports: [DetectionsModule, ScanReviewsModule, MonitoringModule],
  controllers: [ScannerController],
  providers: [ScannerService, PrismaService]
})
export class ScannerModule {}
