import { Module } from "@nestjs/common";
import { LoggerModule } from "nestjs-pino";
import { AccountsModule } from "./accounts/accounts.module";
import { AuthModule } from "./auth/auth.module";
import { DevicesModule } from "./devices/devices.module";
import { DetectionsModule } from "./detections/detections.module";
import { ExecutorIntelligenceModule } from "./executor-intelligence/executor-intelligence.module";
import { HealthController } from "./health/health.controller";
import { MonitoringModule } from "./monitoring/monitoring.module";
import { PrismaService } from "./prisma/prisma.service";
import { ScanReviewsModule } from "./scan-reviews/scan-reviews.module";
import { ScannerKeysModule } from "./scanner-keys/scanner-keys.module";
import { ScannerModule } from "./scanner/scanner.module";
import { ScansModule } from "./scans/scans.module";
import { SettingsModule } from "./settings/settings.module";
import { UsersModule } from "./users/users.module";

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.NODE_ENV === "production" ? "info" : "debug",
        redact: {
          paths: ["req.headers.authorization", "req.headers.cookie"],
          remove: true
        }
      }
    }),
    AuthModule,
    AccountsModule,
    ScannerKeysModule,
    ScannerModule,
    ScansModule,
    DevicesModule,
    DetectionsModule,
    ExecutorIntelligenceModule,
    ScanReviewsModule,
    MonitoringModule,
    SettingsModule,
    UsersModule
  ],
  controllers: [HealthController],
  providers: [PrismaService]
})
export class AppModule {}
