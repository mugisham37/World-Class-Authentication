import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...');

  // Clean up existing data
  await prisma.auditLog.deleteMany();
  await prisma.riskAssessment.deleteMany();
  await prisma.oauthAccount.deleteMany();
  await prisma.recoveryToken.deleteMany();
  await prisma.mfaChallenge.deleteMany();
  await prisma.mfaFactor.deleteMany();
  await prisma.session.deleteMany();
  await prisma.credential.deleteMany();
  await prisma.userProfile.deleteMany();
  await prisma.user.deleteMany();

  // Create admin user
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      username: 'admin',
      emailVerified: true,
      active: true,
      profile: {
        create: {
          firstName: 'Admin',
          lastName: 'User',
          timezone: 'UTC',
          locale: 'en-US',
        },
      },
      credentials: {
        create: {
          type: 'password',
          secret: await bcrypt.hash('Password123!', 12),
          algorithm: 'bcrypt',
        },
      },
    },
  });

  console.log('Created admin user:', adminUser.id);

  // Create test user
  const testUser = await prisma.user.create({
    data: {
      email: 'user@example.com',
      username: 'testuser',
      emailVerified: true,
      active: true,
      profile: {
        create: {
          firstName: 'Test',
          lastName: 'User',
          timezone: 'UTC',
          locale: 'en-US',
        },
      },
      credentials: {
        create: {
          type: 'password',
          secret: await bcrypt.hash('Password123!', 12),
          algorithm: 'bcrypt',
        },
      },
    },
  });

  console.log('Created test user:', testUser.id);

  // Create MFA factor for admin
  const mfaFactor = await prisma.mfaFactor.create({
    data: {
      userId: adminUser.id,
      type: 'totp',
      secret: 'JBSWY3DPEHPK3PXP', // This is a test secret, not for production
      verified: true,
      default: true,
    },
  });

  console.log('Created MFA factor:', mfaFactor.id);

  // Create audit logs
  await prisma.auditLog.createMany({
    data: [
      {
        userId: adminUser.id,
        action: 'USER_CREATED',
        category: 'USER',
        target: adminUser.id,
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Seed Script',
      },
      {
        userId: testUser.id,
        action: 'USER_CREATED',
        category: 'USER',
        target: testUser.id,
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Seed Script',
      },
    ],
  });

  console.log('Created audit logs');

  console.log('Database seeding completed');
}

main()
  .catch((e) => {
    console.error('Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
