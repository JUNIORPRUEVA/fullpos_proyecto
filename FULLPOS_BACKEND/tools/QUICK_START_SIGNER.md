# 🔐 DGII Postulation XML Signer - Quick Start

## Files Created

1. **`tools/sign-dgii-postulation-xml.js`** - Main signer script
2. **`tools/SIGN_DGII_README.md`** - Full documentation
3. **`tools/export-cert-from-db.js`** - Certificate export helper (reference)

## Quick Usage

### Step-by-Step

1. **Download your postulation XML from DGII portal**
   ```
   Example: C:\Users\pc\Downloads\202604281552373.xml
   ```

2. **Get your certificate .p12 file**
   ```
   From FULLPOS: Download from Settings → Electronic Invoicing
   Or: Find your existing .p12 file
   Example: C:\Users\pc\cert.p12
   ```

3. **Sign the XML**
   ```
   cd FULLPOS_BACKEND
   
   node tools/sign-dgii-postulation-xml.js ^
     --xml "C:\Users\pc\Downloads\202604281552373.xml" ^
     --p12 "C:\Users\pc\cert.p12" ^
     --password "your_cert_password" ^
     --out "C:\Users\pc\Downloads\202604281552373_firmado.xml"
   ```

4. **Check output**
   - File created: `202604281552373_firmado.xml` ✅
   - Has Signature element ✅
   - Ready for DGII ✅

## What It Does

✅ Reads XML  
✅ Loads P12 certificate  
✅ Signs with XMLDSig (RSA-SHA256)  
✅ Preserves root element  
✅ Creates output file  
✅ Prints safe diagnostics  

❌ Does NOT submit to DGII  
❌ Does NOT modify database  
❌ Does NOT print passwords/keys  

## Output Example

```
📋 DGII Postulation XML Signer

📖 Reading XML file...
   ✓ Input file: C:\Users\pc\Downloads\202604281552373.xml
   ✓ Root element: Postulacion

🔐 Loading certificate...
   ✓ Subject: CN=FULLTECH SRL,O=...,C=DO
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
   Certificate subject:     CN=FULLTECH SRL,...
   Certificate issuer:      CN=AC-DGII,...
   Local signature verify:  true

✅ XML signed successfully!
```

## File Structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<Postulacion xmlns:xsi="..." xmlns:xsd="...">
  <!-- Your original content -->
  <PostulacionID>50672</PostulacionID>
  <!-- ... -->
  
  <!-- ⬇️ Signature added here by script ⬇️ -->
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="..." />
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <Reference URI="">
        <DigestValue><!-- hash --></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue><!-- your RSA signature --></SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate><!-- your cert --></X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</Postulacion>
```

## Next Steps

After signing:
1. ✅ You have signed XML: `202604281552373_firmado.xml`
2. ✅ Upload to DGII portal if required
3. ✅ Continue with DGII certification process

---

See `SIGN_DGII_README.md` for complete documentation.
