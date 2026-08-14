import "dotenv/config";
import "reflect-metadata";
import fastifyCookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import { Logger } from "nestjs-pino";
import { NestFactory } from "@nestjs/core";
import {
  FastifyAdapter,
  NestFastifyApplication
} from "@nestjs/platform-fastify";
import { AppModule } from "./app.module";
import { env } from "./config/env";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ bodyLimit: env.API_BODY_LIMIT_BYTES }),
    { bufferLogs: true }
  );

  app.useLogger(app.get(Logger));
  await app.register(helmet);
  await app.register(fastifyCookie, {
    secret: env.AUTH_SECRET
  });
  app.enableCors({
    origin: env.WEB_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["content-type", "x-requested-with"]
  });

  await app.listen(env.API_PORT, "0.0.0.0");
}

void bootstrap();
