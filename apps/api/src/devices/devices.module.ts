import { Module } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AuthModule } from "../auth/auth.module";
import { PrismaService } from "../prisma/prisma.service";
import { DevicesController } from "./devices.controller";
import { DevicesService } from "./devices.service";

@Module({
  imports: [AuthModule],
  controllers: [DevicesController],
  providers: [DevicesService, PrismaService, AuditService]
})
export class DevicesModule {}
