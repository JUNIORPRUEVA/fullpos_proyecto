import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
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
  xsdFileUsed?: string | null;
  xsdValidationEngineAvailable: boolean;
  xsdError?: string | null;
  rawXmllintOutput?: string | null;
};

type XsdEngine = {
  available: boolean;
  command: string | null;
  name: string | null;
  versionOutput?: string;
  error?: string;
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

function hasXmlSignature(xml: string) {
  return /<([A-Za-z0-9_:-]+:)?Signature(\s|>)/.test(xml);
}

function makeXsdXmllintCompatible(xsd: string) {
  return xsd
    .replace(/name=" IndicadorServicioTodoIncluidoType"/g, 'name="IndicadorServicioTodoIncluidoType"')
    .replace(/\[\$0-9\]/g, '[0-9]')
    .replace(/\(\?:\.\[0-9\]\{2\}\)\?/g, '(\\.[0-9]{2})?')
    .replace(/\(\?:/g, '(');
}

function allowUnsignedPreSignXsd(xmlSchema: string) {
  return xmlSchema
    .replace(/<xs:any\b([^>]*)minOccurs="1"([^>]*)maxOccurs="1"([^>]*)\/>/g, '<xs:any$1minOccurs="0"$2maxOccurs="1"$3/>');
}

export class DgiiCertificationXmlValidationService {
  private xmllintWarningLogged = false;

  constructor(
    private readonly xsdDirectory = path.resolve(process.cwd(), 'resources', 'dgii', 'xsd'),
  ) {}

  diagnostics() {
    const xsdFiles = this.listXsdFiles();
    const engine = this.detectXsdEngine();
    return {
      xsdDirectory: this.xsdDirectory,
      xsdDirectoryExists: fs.existsSync(this.xsdDirectory),
      xsdFiles,
      xsdFilesFound: xsdFiles.length,
      xsdValidationEngineAvailable: engine.available,
      xsdValidationEngine: engine.name,
      xsdValidationEngineCommand: engine.command,
    };
  }

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
    const engine = this.detectXsdEngine();
    let xsdValidated = false;
    let xsdFileUsed: string | null = null;
    let xsdValid = false;
    let xsdError: string | null = null;
    if (xsdFiles.length === 0) {
      warnings.push('DGII XSD files not found. Place official XSD files in resources/dgii/xsd.');
    } else if (!engine.available) {
      this.logXmllintUnavailable(engine);
      warnings.push('xmllint not installed. XSD validation disabled.');
    } else if (wellFormed) {
      const selectedXsd = this.selectXsdFile(xml, xsdFiles);
      xsdFileUsed = selectedXsd;
      const preSignValidation = !hasXmlSignature(xml);
      const result = this.validateWithXmllint(xml, selectedXsd, engine.command!, {
        allowUnsignedSignatureSlot: preSignValidation,
      });
      xsdValidated = !result.schemaInvalid;
      xsdValid = result.valid;
      xsdError = result.schemaInvalid ? null : result.errorOutput;
      if (!result.schemaInvalid) errors.push(...result.errors);
      warnings.push(...result.warnings);
    } else {
      warnings.push('XSD validation skipped because XML is not well formed.');
    }

    return {
      wellFormed,
      xsdValidated,
      valid: xsdFiles.length > 0
        ? xsdValidated && xsdValid && errors.length === 0
        : wellFormed && errors.length === 0,
      canSign: wellFormed && errors.length === 0 && (xsdFiles.length === 0 || (xsdValidated && xsdValid)),
      errors,
      warnings,
      xsdDirectory: this.xsdDirectory,
      xsdFiles,
      xsdFileUsed,
      xsdValidationEngineAvailable: engine.available,
      xsdError,
      rawXmllintOutput: xsdError,
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

  private detectXsdEngine() {
    const candidates = [
      process.env.XMLLINT_PATH?.trim(),
      'xmllint',
      process.platform === 'win32' ? 'xmllint.exe' : undefined,
    ].filter((value): value is string => !!value);

    let lastError: string | undefined;
    for (const command of candidates) {
      const result = spawnSync(command, ['--version'], {
        encoding: 'utf8',
        windowsHide: true,
      });
      const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
      if (!result.error && result.status === 0) {
        return {
          available: true,
          command,
          name: 'xmllint',
          versionOutput: output,
        } satisfies XsdEngine;
      }
      lastError = result.error?.message || output || `xmllint exited with status ${result.status}`;
    }

    return {
      available: false,
      command: null,
      name: null,
      error: lastError,
    } satisfies XsdEngine;
  }

  private selectXsdFile(xml: string, xsdFiles: string[]) {
    const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
    const rootName = String(document.documentElement?.nodeName ?? '').replace(/^[^:]+:/, '').toLowerCase();
    const tipoEcf = Array.from(document.getElementsByTagName('*'))
      .find((node: any) => String(node.localName ?? node.nodeName).replace(/^[^:]+:/, '').toLowerCase() === 'tipoecf')
      ?.textContent?.trim();
    const normalizedFiles = xsdFiles.map((fileName) => ({
      fileName,
      normalized: fileName.toLowerCase(),
    }));
    const preferred = rootName === 'rfce'
      ? normalizedFiles.find((entry) =>
          entry.normalized.includes('rfce') && (!tipoEcf || entry.normalized.includes(tipoEcf.toLowerCase())),
        )?.fileName
      : tipoEcf
        ? normalizedFiles.find((entry) =>
            entry.normalized.includes('e-cf') && entry.normalized.includes(tipoEcf.toLowerCase()),
          )?.fileName
        : normalizedFiles.find((entry) => entry.normalized.includes(rootName))?.fileName;
    return path.join(this.xsdDirectory, preferred ?? xsdFiles[0]);
  }

  private validateWithXmllint(
    xml: string,
    xsdPath: string,
    xmllintCommand: string,
    options?: { allowUnsignedSignatureSlot?: boolean },
  ) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fullpos-dgii-xsd-'));
    const xmlPath = path.join(tmpDir, 'document.xml');
    try {
      fs.writeFileSync(xmlPath, xml, 'utf8');
      let schemaPath = xsdPath;
      const warnings: string[] = [];
      const xsd = fs.readFileSync(xsdPath, 'utf8');
      let adjustedXsd = makeXsdXmllintCompatible(xsd);
      const usedXmllintCompatibility = adjustedXsd !== xsd;
      if (options?.allowUnsignedSignatureSlot) {
        adjustedXsd = allowUnsignedPreSignXsd(adjustedXsd);
      }
      if (adjustedXsd !== xsd) {
        const adjustedXsdPath = path.join(tmpDir, 'xmllint-compatible.xsd');
        fs.writeFileSync(adjustedXsdPath, adjustedXsd, 'utf8');
        schemaPath = adjustedXsdPath;
        if (usedXmllintCompatibility) {
          warnings.push('XSD validation used a temporary xmllint-compatible schema copy. Official XSD files were not modified.');
        }
        if (options?.allowUnsignedSignatureSlot) {
          warnings.push('Pre-sign XSD validation allowed the pending Signature slot. Official XSD still applies after signing.');
        }
      }
      const result = spawnSync(xmllintCommand, ['--noout', '--schema', schemaPath, xmlPath], {
        encoding: 'utf8',
        windowsHide: true,
      });
      const stdout = result.stdout?.trim() ?? '';
      const stderr = result.stderr?.trim() ?? '';
      const output = [stdout, stderr].filter(Boolean).join('\n').trim();
      console.debug('[electronic-invoicing.certification.xsd] xmllint.validation', {
        xsdFileUsed: xsdPath,
        schemaPath,
        xmlPath,
        command: xmllintCommand,
        exitStatus: result.status,
        error: result.error?.message ?? null,
        stdout,
        stderr,
        rawOutput: output,
      });
      if (result.status === 0 && !result.error) {
        return { valid: true, schemaInvalid: false, errors: [], warnings: [...warnings, ...(output ? [output] : [])], errorOutput: null };
      }
      const errorOutput = stderr || output || result.error?.message || 'XSD validation failed';
      const schemaInvalid = /Schemas parser error|failed to compile|not a valid regular expression|does not resolve to a\(n\) type definition/i.test(errorOutput);
      if (schemaInvalid) {
        return {
          valid: false,
          schemaInvalid: true,
          errors: [],
          warnings: [
            ...warnings,
            `DGII XSD file failed to compile with xmllint. XML was not XSD-validated. Details: ${errorOutput}`,
          ],
          errorOutput,
        };
      }
      return {
        valid: false,
        schemaInvalid: false,
        errors: [errorOutput],
        warnings,
        errorOutput,
      };
    } finally {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup only.
      }
    }
  }

  private logXmllintUnavailable(engine: XsdEngine) {
    if (this.xmllintWarningLogged) return;
    this.xmllintWarningLogged = true;
    console.warn('xmllint not installed. XSD validation disabled.', {
      platform: process.platform,
      checkedCommand: process.env.XMLLINT_PATH?.trim() || 'xmllint',
      error: engine.error ?? null,
      xsdDirectory: this.xsdDirectory,
    });
  }
}
