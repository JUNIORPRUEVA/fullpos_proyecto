import test from 'node:test';
import assert from 'node:assert/strict';
import { DgiiXmlBuilderService } from '../services/dgii-xml-builder.service';

test('DgiiXmlBuilderService builds deterministic e-CF XML', () => {
  const service = new DgiiXmlBuilderService();
  const xml = service.build({
    ecf: 'E310000000001',
    documentTypeCode: '31',
    issueDate: new Date('2025-01-03T10:00:00.000Z'),
    currencyCode: 'DOP',
    issuer: {
      rnc: '101010101',
      name: 'Comercio Demo SRL',
      address: 'Av. Principal 1',
      email: 'facturas@demo.com',
      phone: '8095550101',
    },
    buyer: {
      rnc: '131313131',
      name: 'Cliente Fiscal SRL',
    },
    lines: [
      {
        lineNumber: 1,
        description: 'Producto A',
        quantity: 2,
        unitPrice: 100,
        lineExtensionAmount: 200,
        taxAmount: 36,
      },
    ],
    subtotalAmount: 200,
    taxAmount: 36,
    totalAmount: 236,
    signatureDate: new Date('2025-01-03T14:05:06.000Z'),
  });

  assert.match(xml, /<eNCF>E310000000001<\/eNCF>/);
  assert.match(xml, /<RNCEmisor>101010101<\/RNCEmisor>/);
  assert.match(xml, /<RazonSocialComprador>Cliente Fiscal SRL<\/RazonSocialComprador>/);
  assert.match(xml, /<ITBISTotal>36\.00<\/ITBISTotal>/);
  assert.match(xml, /<FechaHoraFirma>03-01-2025 10:05:06<\/FechaHoraFirma>/);
});

test('DgiiXmlBuilderService builds consumer invoice XML for type 32 without buyer RNC', () => {
  const service = new DgiiXmlBuilderService();
  const xml = service.build({
    ecf: 'E320000000001',
    documentTypeCode: '32',
    issueDate: new Date('2025-01-03T10:00:00.000Z'),
    currencyCode: 'DOP',
    issuer: {
      rnc: '101010101',
      name: 'Comercio Demo SRL',
      address: 'Av. Principal 1',
    },
    buyer: {
      rnc: null,
      name: 'Consumidor Final',
    },
    lines: [
      {
        lineNumber: 1,
        description: 'Producto B',
        quantity: 1,
        unitPrice: 50,
        lineExtensionAmount: 50,
        taxAmount: 9,
      },
    ],
    subtotalAmount: 50,
    taxAmount: 9,
    totalAmount: 59,
    signatureDate: new Date('2025-01-03T14:05:06.000Z'),
  });

  assert.match(xml, /<TipoeCF>32<\/TipoeCF>/);
  assert.match(xml, /<RazonSocialComprador>Consumidor Final<\/RazonSocialComprador>/);
  assert.doesNotMatch(xml, /<RNCComprador>/);
});

test('DgiiXmlBuilderService updates FechaHoraFirma without adding a Signature', () => {
  const service = new DgiiXmlBuilderService();
  const xml = '<?xml version="1.0" encoding="UTF-8"?><eCF><Encabezado/><DetallesItems/><FechaHoraFirma>01-01-2025 00:00:00</FechaHoraFirma></eCF>';

  const updated = service.ensureFechaHoraFirma(xml, new Date('2025-01-03T14:05:06.000Z'));

  assert.match(updated, /<FechaHoraFirma>03-01-2025 10:05:06<\/FechaHoraFirma>/);
  assert.doesNotMatch(updated, /<Signature/);
});