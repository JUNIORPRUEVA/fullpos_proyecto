#!/usr/bin/env node

/**
 * Export Certificate from Database
 * 
 * Exports the active electronic certificate for a company from FULLPOS database
 * to a .p12 file so it can be used with the XML signer script.
 * 
 * Usage:
 *   node tools/export-cert-from-db.js \
 *     --rnc "133080206" \
 *     --password "certificate_password" \
 *     --out "certificate.p12"
 * 
 * This script:
 * - Connects to FULLPOS database
 * - Loads the certificate for the given RNC
 * - Decrypts it using FE_MASTER_ENCRYPTION_KEY
 * - Exports as .p12 file
 * - Prints diagnostics (no passwords printed)
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Check if we're in the right place
const backendPath = process.cwd();
if (!fs.existsSync(path.join(backendPath, 'prisma'))) {
  console.error(
    '\n❌ Error: Run this script from FULLPOS_BACKEND directory\n' +
    'Usage: cd FULLPOS_BACKEND && node tools/export-cert-from-db.js --rnc "133080206" --out "cert.p12"\n'
  );
  process.exit(1);
}

// Check environment
const encryptionKey = process.env.FE_MASTER_ENCRYPTION_KEY;
if (!encryptionKey) {
  console.error(
    '\n❌ Error: FE_MASTER_ENCRYPTION_KEY not set in .env\n' +
    'This key is required to decrypt certificates from database.\n'
  );
  process.exit(1);
}

console.log('⚠️  Certificate export from database requires Prisma client setup.');
console.log('    For now, use the sign-dgii-postulation-xml.js script with your certificate file.\n');
console.log('To export a certificate manually:\n');
console.log('1. From FULLPOS-FLUTTER: Settings → Electronic Invoicing → Download certificate');
console.log('2. Or locate your .p12 file in your computer');
console.log('3. Then use: node tools/sign-dgii-postulation-xml.js --xml ... --p12 ... --password ... --out ...\n');
console.log('Alternative: Export from database connection using your database admin tool\n');
