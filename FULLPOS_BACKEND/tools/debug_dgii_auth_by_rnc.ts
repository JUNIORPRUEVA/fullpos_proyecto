/* eslint-disable no-console */
import { prisma } from '../src/config/prisma';
import { DgiiDirectoryService } from '../src/modules/electronic-invoicing/services/dgii-directory.service';
import { DgiiSignatureService } from '../src/modules/electronic-invoicing/services/dgii-signature.service';
import { DgiiAuthService } from '../src/modules/electronic-invoicing/services/dgii-auth.service';
import { ElectronicInvoicingAuditService } from '../src/modules/electronic-invoicing/services/electronic-invoicing-audit.service';
import { ElectronicInvoicingMapperService } from '../src/modules/electronic-invoicing/services/electronic-invoicing-mapper.service';
import { DgiiEnvironment } from '../src/modules/electronic-invoicing/types/dgii.types';

function readArg(name: string) {
  const exact = process.argv.find((item) => item.startsWith(`--${name}=`));
  if (!exact) return undefined;
  return exact.slice(name.length + 3).trim();
}

async function main() {
  const companyRnc = readArg('companyRnc');
  const companyCloudId = readArg('companyCloudId');
  const envRaw = readArg('environment');
  const environment = (envRaw as DgiiEnvironment | undefined) ?? undefined;

  if (!companyRnc && !companyCloudId) {
    throw new Error('Debe indicar --companyRnc=... o --companyCloudId=...');
  }

  const auth = new DgiiAuthService(
    prisma,
    new ElectronicInvoicingMapperService(prisma),
    new DgiiSignatureService(),
    new ElectronicInvoicingAuditService(prisma),
    new DgiiDirectoryService(),
  );

  try {
    const result = await auth.debugAuthenticateByLocators(
      {
        companyRnc,
        companyCloudId,
        environment,
        forceRefresh: true,
      },
      'debug-dgii-auth-script',
    );

    console.log(
      JSON.stringify(
        {
          ...result,
          tokenFound: result.tokenFound,
        },
        null,
        2,
      ),
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(
    JSON.stringify(
      {
        ok: false,
        message: error instanceof Error ? error.message : String(error),
      },
      null,
      2,
    ),
  );
  process.exit(1);
});
