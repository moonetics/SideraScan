import { Controller, Get } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";

type HealthResponse = {
  status: "ok";
  service: "api";
  database?: "ok" | "error";
};

@Controller()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get("health/live")
  live(): HealthResponse {
    return {
      status: "ok",
      service: "api"
    };
  }

  @Get("health/ready")
  async ready(): Promise<HealthResponse> {
    const database = await this.checkDatabase();

    return {
      status: "ok",
      service: "api",
      database
    };
  }

  @Get("health")
  async health(): Promise<HealthResponse> {
    const database = await this.checkDatabase();

    return {
      status: "ok",
      service: "api",
      database
    };
  }

  private async checkDatabase(): Promise<"ok" | "error"> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return "ok";
    } catch {
      return "error";
    }
  }
}
