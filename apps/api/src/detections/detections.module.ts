import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { PrismaService } from "../prisma/prisma.service";
import { DetectionsController } from "./detections.controller";
import { DetectionsService } from "./detections.service";

@Module({
  imports: [AuthModule],
  controllers: [DetectionsController],
  providers: [DetectionsService, PrismaService, AuditService],
  exports: [DetectionsService]
})
export class DetectionsModule {}
