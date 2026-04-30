const fs = require('fs');
const path = require('path');
const { DOMParser } = require('@xmldom/xmldom');

const tipoEcf = process.argv[2] || '33';
const xsdDirectory = path.resolve(process.cwd(), 'resources', 'dgii', 'xsd');
const selectedXsd = path.join(xsdDirectory, `e-CF ${tipoEcf} v.1.0.xsd`);

function readExpectedRoot(xsdPath) {
  const text = fs.readFileSync(xsdPath, 'utf8');
  const schema = text.match(/<xs:schema\b([^>]*)>/i)?.[1] || '';
  const root = text.match(/<xs:element\s+name="([^"]+)"/i)?.[1] || null;
  const targetNamespace = schema.match(/targetNamespace="([^"]+)"/i)?.[1] || null;
  const elementFormDefault = schema.match(/elementFormDefault="([^"]+)"/i)?.[1] || null;
  const imports = [...text.matchAll(/<xs:import\b[^>]*schemaLocation="([^"]+)"/gi)].map((item) => item[1]);
  const includes = [...text.matchAll(/<xs:include\b[^>]*schemaLocation="([^"]+)"/gi)].map((item) => item[1]);
  return { root, targetNamespace, elementFormDefault, imports, includes };
}

function generatedRoot(xml) {
  const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
  return document.documentElement?.nodeName || null;
}

if (!fs.existsSync(selectedXsd)) {
  console.error(`XSD not found: ${selectedXsd}`);
  process.exit(1);
}

const { DgiiCertificationXmlBuilderService } = require('../dist/modules/electronic-invoicing/services/dgii-certification-xml-builder.service');
const builder = new DgiiCertificationXmlBuilderService();
const result = builder.buildEcfXmlFromCertificationCase({
  rawRowJson: {
    TipoeCF: tipoEcf,
    eNCF: `E${tipoEcf}0000000001`,
    FechaVencimientoSecuencia: '2026-12-31',
    TipoIngresos: '01',
    TipoPago: '1',
    RNCEmisor: '101010101',
    RazonSocialEmisor: 'FULLPOS TEST',
    DireccionEmisor: 'Calle 1',
    FechaEmision: '2026-04-30',
    MontoTotal: '100.00',
    IndicadorFacturacion: '4',
    IndicadorBienoServicio: '1',
  },
});
const expected = readExpectedRoot(selectedXsd);

console.log(JSON.stringify({
  tipoEcf,
  selectedXsd,
  expectedRootElement: expected.root,
  targetNamespace: expected.targetNamespace,
  elementFormDefault: expected.elementFormDefault,
  imports: expected.imports,
  includes: expected.includes,
  generatedRootElement: result.xml ? generatedRoot(result.xml) : null,
  generationErrors: result.errors,
  generationWarnings: result.warnings,
}, null, 2));
