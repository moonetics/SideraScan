import { resolve } from "node:path";
import * as argon2 from "argon2";
import { config } from "dotenv";
import { GlobalRole, PrismaClient, UserStatus } from "@prisma/client";

config({ path: resolve(__dirname, "../../../.env") });
config({ path: resolve(__dirname, "../.env"), override: true });

const prisma = new PrismaClient();

function readEnv(name: string, fallback: string): string {
  return process.env[name]?.trim() || fallback;
}

async function main() {
  const email = readEnv(
    "SEED_SUPER_ADMIN_EMAIL",
    "admin@example.com"
  ).toLowerCase();
  const username = readEnv(
    "SEED_SUPER_ADMIN_USERNAME",
    "superadmin"
  ).toLowerCase();
  const password = readEnv("SEED_SUPER_ADMIN_PASSWORD", "ChangeMe12345!");
  const displayName = readEnv(
    "SEED_SUPER_ADMIN_DISPLAY_NAME",
    "Super Admin"
  );

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id
  });

  const existing = await prisma.user.findFirst({
    where: {
      OR: [{ email }, { username }]
    },
    select: { id: true }
  });

  if (existing) {
    await prisma.user.update({
      where: { id: existing.id },
      data: {
        email,
        username,
        passwordHash,
        displayName,
        globalRole: GlobalRole.SUPER_ADMIN,
        status: UserStatus.ACTIVE,
        deletedAt: null
      }
    });
  } else {
    await prisma.user.create({
      data: {
      email,
      username,
      passwordHash,
      displayName,
      globalRole: GlobalRole.SUPER_ADMIN,
      status: UserStatus.ACTIVE
      }
    });
  }

  console.log(`Seeded Super Admin: ${email}`);
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
