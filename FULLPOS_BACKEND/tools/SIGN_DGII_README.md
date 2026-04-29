# DGII Postulation XML Signer

## Purpose

Sign a DGII postulation XML file (downloaded from DGII portal) using your .p12/.pfx certificate.

This script:
- ✅ Reads the XML file
- ✅ Loads the P12 certificate with private key
- ✅ Signs the XML using XMLDSig (RSA-SHA256 with SHA256 digest)
- ✅ Preserves the root element structure
- ✅ Inserts the Signature element correctly
- ✅ Outputs a new signed XML file
- ❌ Does NOT submit to DGII
- ❌ Does NOT modify any database records
- ❌ Does NOT touch sales or sequences

## Installation

The script uses these pre-installed dependencies in `package.json`:
- `@xmldom/xmldom` - XML DOM parsing
- `xml-crypto` - XMLDSig support
- `node-forge` - P12 certificate handling
- `crypto` - Node built-in

No additional `npm install` is needed.

## Usage

### Command Line

```bash
node tools/sign-dgii-postulation-xml.js \
  --xml "path/to/postulation.xml" \
  --p12 "path/to/certificate.p12" \
  --password "certificate_password" \
  --out "path/to/output.xml"
```

### Arguments

- `--xml` **[REQUIRED]** Path to your DGII postulation XML file (from portal download)
- `--p12` **[REQUIRED]** Path to your .p12 or .pfx certificate file
- `--password` **[REQUIRED]** Password for the certificate
- `--out` **[REQUIRED]** Output path for the signed XML file

### Real Example

```bash
node tools/sign-dgii-postulation-xml.js \
  --xml "C:\Users\pc\Downloads\202604281552373.xml" \
  --p12 "C:\Users\pc\cert.p12" \
  --password "MyCertPassword123" \
  --out "C:\Users\pc\Downloads\202604281552373_firmado.xml"
```

## Step-by-Step Usage

### 1. Download Postulation XML from DGII Portal

1. Go to https://dgii.gov.do
2. Search for "Registro de Software" or "Certificación de Software"
3. Fill in your software details (FULLPOS, URLs, etc.)
4. Click "GENERAR ARCHIVO"
5. Download the XML file (e.g., `202604281552373.xml`)

### 2. Locate Your Certificate

You need the .p12 or .pfx file that contains:
- Your certificate (public key)
- Your private key
- Certificate password

This is the same certificate used for FULLPOS electronic invoicing with RNC 133080206.

### 3. Run the Signing Script

```bash
# Navigate to backend folder
cd FULLPOS_BACKEND

# Run the signer
node tools/sign-dgii-postulation-xml.js \
  --xml "C:\Users\pc\Downloads\202604281552373.xml" \
  --p12 "C:\path\to\certificate.p12" \
  --password "your_cert_password" \
  --out "C:\Users\pc\Downloads\202604281552373_firmado.xml"
```

### 4. Check Output

The script will print diagnostics:
```
📋 DGII Postulation XML Signer

📖 Reading XML file...
   ✓ Input file: C:\Users\pc\Downloads\202604281552373.xml
   ✓ Root element: Postulacion

🔐 Loading certificate...
   ✓ Subject: CN=FULLTECH SRL,O=Empresa,C=DO
   ✓ Issuer: CN=AC-DGII,O=DGII,C=DO

✍️  Signing XML...
   ✓ Signature inserted: true
   ✓ Root element preserved: true (Postulacion)

💾 Writing output file...
   ✓ Output file: C:\Users\pc\Downloads\202604281552373_firmado.xml

📊 Signing Complete - Diagnostics:
   Input file:              C:\Users\pc\Downloads\202604281552373.xml
   Output file:             C:\Users\pc\Downloads\202604281552373_firmado.xml
   Root before:             Postulacion
   Root after:              Postulacion
   Has signature:           true
   Certificate subject:     CN=FULLTECH SRL,O=Empresa,C=DO
   Certificate issuer:      CN=AC-DGII,O=DGII,C=DO
   Local signature verify:  true

✅ XML signed successfully!
```

### 5. Use Signed XML in DGII Portal

1. Go back to DGII portal
2. Where required, upload the signed XML file (`202604281552373_firmado.xml`)
3. Complete remaining DGII registration steps

## Output Files

The script generates:
- `202604281552373_firmado.xml` - Signed XML with embedded Signature element

The XML structure is preserved:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Postulacion xmlns:xsi="..." xmlns:xsd="...">
  <!-- Original content -->
  
  <!-- Added by signer -->
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <!-- Signature metadata -->
    </SignedInfo>
    <SignatureValue><!-- RSA signature bytes in base64 --></SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate><!-- Your certificate in base64 --></X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</Postulacion>
```

## Security Notes

The script **NEVER prints**:
- ❌ Certificate password
- ❌ Private key
- ❌ Full certificate content
- ❌ Secrets or sensitive data

The script **ONLY prints** safe diagnostics:
- ✅ File paths
- ✅ Root element name
- ✅ Certificate subject/issuer (public info)
- ✅ Signature status (true/false)

## Troubleshooting

### Error: "XML file not found"
- Verify the XML path is correct
- Check file exists: `Test-Path "C:\path\to\file.xml"`

### Error: "P12 certificate file not found"
- Verify the .p12 path is correct
- Check file exists: `Test-Path "C:\path\to\cert.p12"`

### Error: "Failed to extract certificate or private key"
- Certificate password is wrong
- P12 file is corrupted
- P12 file format not supported (try converting with OpenSSL)

### Error: "Invalid XML"
- XML file is not valid
- Try opening in a text editor to verify format

## Technical Details

### XMLDSig Algorithms Used

- **Signature Algorithm:** RSA-SHA256
- **Digest Algorithm:** SHA256
- **Canonicalization:** Exclusive XML Canonicalization (http://www.w3.org/2001/10/xml-exc-c14n#)
- **Transforms:** Enveloped Signature

This matches DGII requirements for postulation signature.

### Signature Verification

The script performs a local signature verification check:
- Verifies Signature element exists
- Verifies structure is valid
- Does NOT verify against DGII (that happens in DGII portal)

## Next Steps

After signing:
1. ✅ You have `202604281552373_firmado.xml` (signed)
2. ✅ Upload to DGII portal if required
3. ✅ Complete DGII certification process
4. ❌ Script does NOT submit to DGII (you must do it)

## Notes

- This script is **READ-ONLY** for your database
- Does not modify FULLPOS application logic
- Does not affect sales or sequences
- Can be run standalone without FULLPOS app running
- Requires P12 certificate and password
- Output file overwrites existing files without prompting

---

**Version:** 1.0  
**Created:** April 28, 2026  
**Purpose:** Sign DGII postulation XML for manual submission
