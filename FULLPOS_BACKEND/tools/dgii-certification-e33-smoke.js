const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { DgiiCertificationXmlBuilderService } = require('../dist/modules/electronic-invoicing/services/dgii-certification-xml-builder.service');

const builder = new DgiiCertificationXmlBuilderService();
const result = builder.buildEcfXmlFromCertificationCase({
  rawRowJson: {
    TipoeCF: '33',
    eNCF: 'E330000000001',
    FechaVencimientoSecuencia: '31-12-2026',
    TipoPago: '1',
    RNCEmisor: '101010101',
    RazonSocialEmisor: 'FULLPOS TEST',
    DireccionEmisor: 'Calle 1',
    FechaEmision: '30-04-2026',
    MontoTotal: '100.00',
    NCFModificado: 'E320000000001',
    FechaNCFModificado: '29-04-2026',
    CodigoModificacion: '1',
  },
});

const out = path.resolve(process.cwd(), 'tmp-generated-e33.xml');
if (result.xml) fs.writeFileSync(out, result.xml, 'utf8');

const xsd = path.resolve(process.cwd(), 'resources', 'dgii', 'xsd', 'e-CF 33 v.1.0.xsd');
const xmllint = process.env.XMLLINT_PATH?.trim() || 'xmllint';
const validation = result.xml
  ? spawnSync(xmllint, ['--noout', '--schema', xsd, out], { encoding: 'utf8', windowsHide: true })
  : null;
const xmllintOutput = validation
  ? [validation.stdout, validation.stderr, validation.error?.message].filter(Boolean).join('\n').trim()
  : null;

const xml = result.xml || '';
const itemBody = xml.match(/<Item>([\s\S]*?)<\/Item>/)?.[1] || '';
const itemOrder = [...itemBody.matchAll(/<([A-Za-z0-9]+)>/g)].map((match) => match[1]);

console.log(JSON.stringify({
  generatedXml: result.xml ? out : null,
  xsd,
  generationErrors: result.errors,
  generationWarnings: result.warnings,
  checks: {
    noPlaceholderHashE: !xml.includes('#e'),
    rootIsECF: /^<\?xml[\s\S]*?<ECF>/.test(xml),
    nombreItemAfterIndicadorFacturacion: itemOrder.indexOf('IndicadorFacturacion') > -1 &&
      itemOrder.indexOf('NombreItem') > itemOrder.indexOf('IndicadorFacturacion'),
    fechaHoraFirmaDirectChildAfterReferencia: /<\/InformacionReferencia>\s*<FechaHoraFirma>/.test(xml),
  },
  itemOrder,
  xmllint: validation
    ? {
        command: xmllint,
        available: !validation.error,
        status: validation.status,
        output: xmllintOutput,
      }
    : null,
}, null, 2));
