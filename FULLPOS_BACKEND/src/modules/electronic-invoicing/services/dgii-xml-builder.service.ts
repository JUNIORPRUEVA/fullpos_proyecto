import { ElectronicInvoiceBuildInput } from '../types/electronic-invoice.types';
import { formatMoney } from '../utils/validation.utils';
import { create } from 'xmlbuilder2';

function formatDate(value: Date) {
  return value.toISOString().slice(0, 10);
}

export class DgiiXmlBuilderService {
  build(input: ElectronicInvoiceBuildInput) {
    const root = create({ version: '1.0', encoding: 'UTF-8' }).ele('eCF');

    const encabezado = root.ele('Encabezado');
    const idDoc = encabezado.ele('IdDoc');
    idDoc.ele('eNCF').txt(input.ecf);
    idDoc.ele('TipoeCF').txt(input.documentTypeCode);
    idDoc.ele('FechaEmision').txt(formatDate(input.issueDate));
    idDoc.ele('Moneda').txt(input.currencyCode);

    if (input.reference) {
      const infoReferencia = encabezado.ele('InformacionReferencia');
      infoReferencia.ele('NCFModificado').txt(input.reference.modifiedEcf);
      if (input.reference.modifiedDocumentTypeCode) {
        infoReferencia.ele('TipoNCFModificado').txt(input.reference.modifiedDocumentTypeCode);
      }
      if (input.reference.modifiedIssueDate) {
        infoReferencia.ele('FechaNCFModificado').txt(formatDate(input.reference.modifiedIssueDate));
      }
      if (input.reference.reason) {
        infoReferencia.ele('RazonModificacion').txt(input.reference.reason);
      }
    }

    const emisor = encabezado.ele('Emisor');
    emisor.ele('RNCEmisor').txt(input.issuer.rnc ?? '');
    emisor.ele('RazonSocialEmisor').txt(input.issuer.name);
    if (input.issuer.address) emisor.ele('DireccionEmisor').txt(input.issuer.address);
    if (input.issuer.email) emisor.ele('CorreoEmisor').txt(input.issuer.email);
    if (input.issuer.phone) emisor.ele('TelefonoEmisor').txt(input.issuer.phone);

    const comprador = encabezado.ele('Comprador');
    if (input.buyer.rnc) comprador.ele('RNCComprador').txt(input.buyer.rnc);
    comprador.ele('RazonSocialComprador').txt(input.buyer.name);
    if (input.buyer.address) comprador.ele('DireccionComprador').txt(input.buyer.address);
    if (input.buyer.email) comprador.ele('CorreoComprador').txt(input.buyer.email);
    if (input.buyer.phone) comprador.ele('TelefonoComprador').txt(input.buyer.phone);

    const totales = encabezado.ele('Totales');
    totales.ele('MontoGravadoTotal').txt(formatMoney(input.subtotalAmount));
    totales.ele('ITBISTotal').txt(formatMoney(input.taxAmount));
    totales.ele('MontoTotal').txt(formatMoney(input.totalAmount));

    const detalles = root.ele('DetallesItems');
    for (const line of input.lines) {
      const item = detalles.ele('Item');
      item.ele('NumeroLinea').txt(String(line.lineNumber));
      if (line.productCode) item.ele('CodigoItem').txt(line.productCode);
      item.ele('NombreItem').txt(line.description);
      item.ele('CantidadItem').txt(line.quantity.toFixed(3));
      item.ele('PrecioUnitarioItem').txt(formatMoney(line.unitPrice));
      item.ele('MontoItem').txt(formatMoney(line.lineExtensionAmount));
      item.ele('ITBISItem').txt(formatMoney(line.taxAmount));
    }

    return root.end({ prettyPrint: false });
  }
}