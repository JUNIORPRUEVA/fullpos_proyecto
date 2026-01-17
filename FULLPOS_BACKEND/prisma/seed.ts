/* eslint-disable no-console */
import { addDays, subDays } from 'date-fns';
import { prisma } from '../src/config/prisma';
import env from '../src/config/env';
import { hashPassword } from '../src/utils/password';

async function main() {
  const password = await hashPassword('fullpos123');

  const company = await prisma.company.upsert({
    where: { name: 'FULLPOS DEMO' },
    update: {
      ownerAppAndroidUrl: env.OWNER_APP_ANDROID_URL,
      ownerAppIosUrl: env.OWNER_APP_IOS_URL,
      ownerAppVersion: env.OWNER_APP_VERSION ?? '1.0.0',
    },
    create: {
      name: 'FULLPOS DEMO',
      rnc: '000000000',
      ownerAppAndroidUrl: env.OWNER_APP_ANDROID_URL,
      ownerAppIosUrl: env.OWNER_APP_IOS_URL,
      ownerAppVersion: env.OWNER_APP_VERSION ?? '1.0.0',
    },
  });

  const ownerUser = await prisma.user.upsert({
    where: { username: 'owner' },
    update: {
      password,
      role: 'owner',
      companyId: company.id,
      email: 'owner@fullpos.com',
      displayName: 'Demo Owner',
    },
    create: {
      username: 'owner',
      email: 'owner@fullpos.com',
      password,
      role: 'owner',
      companyId: company.id,
      displayName: 'Demo Owner',
    },
  });

  const hasSales = await prisma.sale.count({ where: { companyId: company.id } });
  if (hasSales === 0) {
    const session1 = await prisma.cashSession.create({
      data: {
        companyId: company.id,
        openedById: ownerUser.id,
        closedById: ownerUser.id,
        userName: ownerUser.username,
        openedAt: subDays(new Date(), 7),
        closedAt: subDays(addDays(new Date(), 0), 7),
        initialAmount: 500,
        closingAmount: 1800,
        expectedCash: 1780,
        difference: 20,
        status: 'CLOSED',
        paymentSummary: { cash: 1200, card: 600 },
      },
    });

    const session2 = await prisma.cashSession.create({
      data: {
        companyId: company.id,
        openedById: ownerUser.id,
        closedById: ownerUser.id,
        userName: ownerUser.username,
        openedAt: subDays(new Date(), 2),
        closedAt: subDays(new Date(), 2),
        initialAmount: 400,
        closingAmount: 1450,
        expectedCash: 1460,
        difference: -10,
        status: 'CLOSED',
        paymentSummary: { cash: 900, transfer: 550 },
      },
    });

    await prisma.cashMovement.createMany({
      data: [
        {
          companyId: company.id,
          sessionId: session1.id,
          type: 'ingreso',
          amount: 300,
          note: 'Ingreso inicial',
        },
        {
          companyId: company.id,
          sessionId: session2.id,
          type: 'retiro',
          amount: 150,
          note: 'Retiro de caja',
        },
      ],
    });

    await prisma.sale.create({
      data: {
        companyId: company.id,
        localCode: 'POS-0001',
        kind: 'invoice',
        status: 'completed',
        subtotal: 1000,
        itbisAmount: 180,
        total: 1180,
        paymentMethod: 'cash',
        paidAmount: 1180,
        changeAmount: 0,
        fiscalEnabled: false,
        sessionId: session1.id,
        createdById: ownerUser.id,
        createdAt: subDays(new Date(), 7),
        items: {
          create: [
            {
              productNameSnapshot: 'Camisa',
              qty: 2,
              unitPrice: 200,
              totalLine: 400,
            },
            {
              productNameSnapshot: 'Pantal\u00f3n',
              qty: 1,
              unitPrice: 600,
              totalLine: 600,
            },
          ],
        },
      },
    });

    await prisma.sale.create({
      data: {
        companyId: company.id,
        localCode: 'POS-0002',
        kind: 'invoice',
        status: 'completed',
        subtotal: 850,
        itbisAmount: 153,
        total: 1003,
        paymentMethod: 'card',
        paidAmount: 1003,
        changeAmount: 0,
        sessionId: session1.id,
        createdById: ownerUser.id,
        createdAt: subDays(new Date(), 6),
        items: {
          create: [
            {
              productNameSnapshot: 'Zapatos',
              qty: 1,
              unitPrice: 550,
              totalLine: 550,
            },
            {
              productNameSnapshot: 'Correa',
              qty: 1,
              unitPrice: 300,
              totalLine: 300,
            },
          ],
        },
      },
    });

    await prisma.sale.create({
      data: {
        companyId: company.id,
        localCode: 'POS-0003',
        kind: 'invoice',
        status: 'completed',
        subtotal: 500,
        itbisAmount: 90,
        total: 590,
        paymentMethod: 'transfer',
        paidAmount: 590,
        changeAmount: 0,
        sessionId: session2.id,
        createdById: ownerUser.id,
        createdAt: subDays(new Date(), 2),
        items: {
          create: [
            {
              productNameSnapshot: 'Blusa',
              qty: 1,
              unitPrice: 250,
              totalLine: 250,
            },
            {
              productNameSnapshot: 'Falda',
              qty: 1,
              unitPrice: 250,
              totalLine: 250,
            },
          ],
        },
      },
    });

    await prisma.sale.create({
      data: {
        companyId: company.id,
        localCode: 'POS-0004',
        kind: 'invoice',
        status: 'completed',
        subtotal: 300,
        itbisAmount: 54,
        total: 354,
        paymentMethod: 'cash',
        paidAmount: 360,
        changeAmount: 6,
        sessionId: session2.id,
        createdById: ownerUser.id,
        createdAt: subDays(new Date(), 1),
        items: {
          create: [
            {
              productNameSnapshot: 'Accesorios',
              qty: 3,
              unitPrice: 100,
              totalLine: 300,
            },
          ],
        },
      },
    });
  }

  console.log('Seed completado');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
