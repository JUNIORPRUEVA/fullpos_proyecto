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
  });

  assert.match(xml, /<eNCF>E310000000001<\/eNCF>/);
  assert.match(xml, /<RNCEmisor>101010101<\/RNCEmisor>/);
  assert.match(xml, /<RazonSocialComprador>Cliente Fiscal SRL<\/RazonSocialComprador>/);
  assert.match(xml, /<ITBISTotal>36\.00<\/ITBISTotal>/);
});