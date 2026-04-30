import fs from 'fs';
import path from 'path';
import { DOMParser } from '@xmldom/xmldom';

export type DgiiCertificationXmlValidationResult = {
  wellFormed: boolean;
  xsdValidated: boolean;
  valid: boolean;
  canSign: boolean;
  errors: string[];
  warnings: string[];
  xsdDirectory: string;
  xsdFiles: string[];
};

function findParserErrors(node: any, out: string[] = []) {
  if (!node) return out;
  const name = String(node.nodeName ?? node.localName ?? '').toLowerCase();
  if (name.includes('parsererror')) {
    out.push(String(node.textContent ?? 'XML parsererror'));
  }
  for (let index = 0; index < (node.childNodes?.length ?? 0); index += 1) {
    findParserErrors(node.childNodes[index], out);
  }
  return out;
}

export class DgiiCertificationXmlValidationService {
  constructor(
    private readonly xsdDirectory = path.resolve(process.cwd(), 'resources', 'dgii', 'xsd'),
  ) {}

  validate(xml: string): DgiiCertificationXmlValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!xml.trim()) {
      errors.push('XML vacio');
    }

    let wellFormed = false;
    if (errors.length === 0) {
      try {
        const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
        const root = document.documentElement;
        const parserErrors = findParserErrors(document);
        if (!root || parserErrors.length > 0) {
          errors.push(...(parserErrors.length > 0 ? parserErrors : ['XML sin elemento raiz']));
        } else {
          wellFormed = true;
        }
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'XML no parseable');
      }
    }

    const xsdFiles = this.listXsdFiles();
    const xsdValidated = false;
    if (xsdFiles.length === 0) {
      warnings.push('DGII XSD files not found. Place official XSD files in resources/dgii/xsd.');
    } else {
      warnings.push('DGII XSD files found, but XSD validation engine is not configured in this runtime.');
    }

    return {
      wellFormed,
      xsdValidated,
      valid: wellFormed && errors.length === 0,
      canSign: wellFormed && errors.length === 0,
      errors,
      warnings,
      xsdDirectory: this.xsdDirectory,
      xsdFiles,
    };
  }

  private listXsdFiles() {
    try {
      if (!fs.existsSync(this.xsdDirectory)) {
        fs.mkdirSync(this.xsdDirectory, { recursive: true });
        return [];
      }
      return fs
        .readdirSync(this.xsdDirectory)
        .filter((fileName) => fileName.toLowerCase().endsWith('.xsd'))
        .sort();
    } catch {
      return [];
    }
  }
}
