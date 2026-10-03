'use client';
import 'reflect-metadata';
import * as xmldsigjs from 'xmldsigjs';
import { X509Certificate } from '@peculiar/x509';
import { useEffect, useMemo, useRef, useState } from 'react';
import { createClient } from '@supabase/supabase-js';
import { createWorker } from 'tesseract.js';
import jsQR from 'jsqr';
import { XMLParser } from 'fast-xml-parser';
import {
  BrowserQRCodeReader,
} from '@zxing/browser';
import {
  BlobReader,
  ZipReader,
  TextWriter,
} from '@zip.js/zip.js';
const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL;

const SUPABASE_ANON_KEY =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

const ALLOWED_FILE_TYPES = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'application/zip',
];

const MAX_FILE_SIZE = 10 * 1024 * 1024;

const solutionCards = [
  {
    title: 'How it addresses the problem',
    items: [
      'Detects altered or synthetic documents',
      'Cross-checks consistency across extracted fields',
      'Flags suspicious identity patterns',
      'Creates a tamper-evident audit trail',
    ],
  },
  {
    title: 'Innovation & uniqueness',
    items: [
      'AI risk score paired with explainable reason codes',
      'Document fingerprint stored as a hash, not raw PII',
      'Permissioned, multi-organization verification',
      'Re-verification without re-uploading a trusted proof',
    ],
  },
];

const trustSteps = [
  [
    '01',
    'Upload',
    'ID or document submitted through an encrypted intake channel.',
  ],
  [
    '02',
    'AI Screen',
    'OCR and computer vision extract fields and surface layout tells.',
  ],
  [
    '03',
    'Verify',
    'Rules and a risk model check consistency across every field.',
  ],
  [
    '04',
    'Anchor',
    'A hash of the verification event is timestamped to the ledger.',
  ],
  [
    '05',
    'Decide',
    'Approve, send to manual review, or reject — with a reason.',
  ],
];

const stackRows = [
  [
    'AI / ML',
    'OCR, image preprocessing, anomaly screening',
  ],
  [
    'Backend',
    'Next.js / Supabase REST APIs',
  ],
  [
    'Blockchain',
    'Permissioned-ledger architecture',
  ],
  [
    'Security',
    'SHA-256, digital fingerprints, access control',
  ],
  [
    'Data',
    'PostgreSQL + encrypted object storage',
  ],
];

const methodItems = [
  [
    '1',
    'Document intake',
    'Encrypted upload',
  ],
  [
    '2',
    'AI extraction',
    'OCR + image preprocessing',
  ],
  [
    '3',
    'Forgery screening',
    'Visual + metadata signals',
  ],
  [
    '4',
    'Identity consistency',
    'Cross-field checks',
  ],
  [
    '5',
    'Risk engine',
    'Score + reason codes',
  ],
  [
    '6',
    'Ledger anchor',
    'Hash + timestamp',
  ],
  [
    '7',
    'Decision',
    'Approve / review / reject',
  ],
];

const audiences = [
  [
    'GOV / INSTITUTIONS',
    'Government & institutions',
    'Secure document intake and audit trails.',
  ],
  [
    'BANKING',
    'Banking & fintech',
    'KYC support and suspicious-case triage.',
  ],
  [
    'EDUCATION',
    'Education & HR',
    'Credential verification at scale.',
  ],
  [
    'PROVIDERS',
    'Service providers',
    'Reusable trust proofs across platforms.',
  ],
];

const references = [
  [
    'W3C',
    'Verifiable Credentials Data Model v2.0 — machine-verifiable, cryptographically secure, privacy-aware digital credentials.',
  ],
  [
    'NIST',
    'AI Risk Management Framework — guidance for trustworthy, secure, privacy-aware and accountable AI systems.',
  ],
  [
    'Hyperledger',
    'Fabric documentation — a permissioned distributed ledger suited to known, governed participants.',
  ],
  [
    'SIH 2026',
    'Provided idea template — structure, slide limits and submission pointers this concept follows.',
  ],
];

function escapeText(value) {
  return String(value ?? '');
}

function firstMatch(text, patterns) {
  for (const pattern of patterns) {
    const match = String(text || '').match(pattern);
    if (match?.[1]) return match[1].trim();
  }
  return '';
}

const DOCUMENT_TYPE_LABELS = {
  aadhaar: 'Aadhaar card',
  passport: 'Passport',
  driving_license: 'Driving licence',
  visa: 'Visa',
  permit: 'Permit document',
  national_id: 'National identity card',
  voter_id: 'Voter ID card',
  pan_card: 'PAN card',
  ration_card: 'Ration card',
  mess_card: 'Mess card',
  student_id: 'Student ID card',
  employee_id: 'Employee ID card',
  access_card: 'Access or visitor card',
  library_card: 'Library card',
  membership_card: 'Membership card',
  health_card: 'Health card',
  other_card: 'Other titled card',
  unknown: 'Unknown document',
};

const AUTO_APPROVABLE_PHOTO_ID_TYPES = new Set([
  'aadhaar',
  'passport',
  'driving_license',
  'visa',
  'permit',
  'national_id',
  'voter_id',
  'pan_card',
]);

function getDocumentTypeLabel(docType, fallback = '') {
  if (docType === 'other_card' && fallback) return fallback;
  return DOCUMENT_TYPE_LABELS[docType] || fallback || 'Unknown document';
}

function toReadableTitle(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function classifyNamedCard(text) {
  const normalized = String(text || '').toUpperCase();
  const rules = [
    { docType: 'mess_card', label: 'Mess card', patterns: [/\bMESS\s+CARD\b/, /AUTHORI[ZS]ED\s+DINING\s+ACCESS/] },
    { docType: 'student_id', label: 'Student ID card', patterns: [/\bSTUDENT\s+(?:ID|IDENTITY)(?:\s+CARD)?\b/, /\bSTUDENT\s+CARD\b/] },
    { docType: 'employee_id', label: 'Employee ID card', patterns: [/\b(?:EMPLOYEE|STAFF)\s+(?:ID|IDENTITY)(?:\s+CARD)?\b/] },
    { docType: 'access_card', label: 'Access or visitor card', patterns: [/\bACCESS\s+CARD\b/, /\bVISITOR\s+(?:CARD|PASS)\b/, /\bENTRY\s+PASS\b/] },
    { docType: 'library_card', label: 'Library card', patterns: [/\bLIBRARY\s+(?:ID\s+)?CARD\b/] },
    { docType: 'membership_card', label: 'Membership card', patterns: [/\bMEMBER(?:SHIP)?\s+CARD\b/] },
    { docType: 'health_card', label: 'Health card', patterns: [/\b(?:HEALTH|MEDICAL|INSURANCE)\s+CARD\b/] },
    { docType: 'voter_id', label: 'Voter ID card', patterns: [/\bVOTER\s+ID\b/, /ELECTOR(?:'S)?\s+PHOTO\s+IDENTITY\s+CARD/, /ELECTION\s+COMMISSION\s+OF\s+INDIA/] },
    { docType: 'pan_card', label: 'PAN card', patterns: [/\bPAN\s+CARD\b/, /PERMANENT\s+ACCOUNT\s+NUMBER/, /INCOME\s+TAX\s+DEPARTMENT/] },
    { docType: 'ration_card', label: 'Ration card', patterns: [/\bRATION\s+CARD\b/] },
  ];

  const exact = rules.find((rule) =>
    rule.patterns.some((pattern) => pattern.test(normalized))
  );
  if (exact) return { ...exact, confidence: 'named' };

  const genericTitle = normalized.match(
    /\b((?:[A-Z0-9&'-]+\s+){0,3}(?:IDENTITY\s+)?(?:CARD|PASS))\b/
  )?.[1];

  if (genericTitle && !/^(?:THIS|THE|YOUR)\s+(?:CARD|PASS)$/.test(genericTitle)) {
    return {
      docType: 'other_card',
      label: toReadableTitle(genericTitle),
      patterns: [],
      confidence: 'title',
    };
  }

  return null;
}

function extractDocumentFields(text, docType) {
  const compact = String(text || '').replace(/\r/g, '').replace(/[ \t]+/g, ' ');
  const dates = compact.match(/\b(?:\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}|\d{1,2}\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\s+\d{2,4})\b/gi) || [];
  const fields = {
    name: firstMatch(compact, [/(?:SURNAME|LAST NAME)\s*[:\-]?\s*([A-Z][A-Z .'-]{2,40}?)(?=\s+(?:GIVEN|NATIONALITY|DOB|DATE|SEX|GENDER|ADDRESS|ROLL|COURSE|ID|$))/i, /(?:GIVEN NAMES?|NAME)\s*[:\-]?\s*([A-Z][A-Z .'-]{2,40}?)(?=\s+(?:ROLL|COURSE|DOB|DATE|SEX|GENDER|ADDRESS|ID|START|END|$))/i]),
    documentNumber: '',
    nationality: firstMatch(compact, [/NATIONALITY\s*[:\-]?\s*([A-Z]{2,30})/i]),
    dateOfBirth: firstMatch(compact, [/(?:DATE OF BIRTH|DOB|BIRTH)\s*[:\-]?\s*(\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}|\d{1,2}\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\s+\d{2,4})/i]) || dates[0] || '',
    dateOfExpiry: firstMatch(compact, [/(?:DATE OF EXPIRY|EXPIRY|EXPIRES?|VALID UNTIL)\s*[:\-]?\s*(\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}|\d{1,2}\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\s+\d{2,4})/i]) || dates[1] || '',
    gender: firstMatch(compact, [/(?:SEX|GENDER)\s*[:\-]?\s*(MALE|FEMALE|M|F|X)\b/i]),
    visaType: firstMatch(compact, [/VISA TYPE\s*[:\-]?\s*([A-Z0-9 -]{1,24})/i]),
    stayDuration: firstMatch(compact, [/(?:DURATION OF STAY|STAY DURATION)\s*[:\-]?\s*([A-Z0-9 -]{1,24})/i]),
    course: firstMatch(compact, [/COURSE\s*[:\-]?\s*([A-Z0-9 .&/-]{2,30}?)(?=\s+(?:START|END|VALID|ID|$))/i]),
  };
  if (docType === 'passport') fields.documentNumber = firstMatch(compact, [/(?:PASSPORT(?: NO| NUMBER)?|DOCUMENT NO)\s*[:\-]?\s*([A-Z][0-9]{7})/i, /\b([A-Z][0-9]{7})\b/]);
  else if (docType === 'visa') fields.documentNumber = firstMatch(compact, [/VISA(?: NO| NUMBER)?\s*[:\-]?\s*([A-Z0-9]{5,20})/i]);
  else if (docType === 'aadhaar') fields.documentNumber = firstMatch(compact, [/\b(\d{4}\s?\d{4}\s?\d{4})\b/]).replace(/\s/g, '');
  else if (docType === 'pan_card') fields.documentNumber = firstMatch(compact, [/\b([A-Z]{5}\d{4}[A-Z])\b/i]);
  else if (docType === 'voter_id') fields.documentNumber = firstMatch(compact, [/(?:EPIC|VOTER)(?: NO| NUMBER| ID)?\s*[:\-]?\s*([A-Z0-9/-]{5,24})/i]);
  else if (['mess_card', 'student_id'].includes(docType)) fields.documentNumber = firstMatch(compact, [/(?:ROLL|ENROL+MENT|REGISTRATION)(?: NO| NUMBER)?\s*[:\-]?\s*([A-Z0-9/-]{3,24})/i]);
  else if (docType === 'employee_id') fields.documentNumber = firstMatch(compact, [/(?:EMPLOYEE|STAFF)(?: ID| NO| NUMBER| CODE)?\s*[:\-]?\s*([A-Z0-9/-]{3,24})/i]);
  else fields.documentNumber = firstMatch(compact, [/(?:ID|LICEN[CS]E|PERMIT)(?: NO| NUMBER)?\s*[:\-]?\s*([A-Z0-9-]{5,24})/i]);
  return Object.fromEntries(Object.entries(fields).filter(([, value]) => Boolean(value)));
}

function buildModuleFindings({ docType, extractedFields, anomalyReasons, consistencyScore, ocrConfidence, imageSignals }) {
  const requiredByType = {
    passport: ['documentNumber', 'dateOfBirth', 'dateOfExpiry'],
    visa: ['documentNumber', 'dateOfExpiry'],
    aadhaar: ['documentNumber', 'dateOfBirth'],
    driving_license: ['documentNumber', 'dateOfBirth'],
    permit: ['documentNumber', 'dateOfExpiry'],
    national_id: ['documentNumber', 'dateOfBirth'],
    voter_id: ['documentNumber'],
    pan_card: ['documentNumber'],
    mess_card: ['name'],
    student_id: ['name'],
    employee_id: ['name'],
  };
  const missing = (requiredByType[docType] || []).filter((key) => !extractedFields[key]);
  return {
    validationChecks: [
      { label: 'Document type recognized', status: docType === 'unknown' ? 'review' : 'pass', detail: docType === 'unknown' ? 'No readable document title or supported pattern was identified.' : getDocumentTypeLabel(docType) },
      { label: 'Expected fields present', status: missing.length ? 'review' : 'pass', detail: missing.length ? `Not reliably extracted: ${missing.join(', ')}` : 'Expected fields were found, or this card type has no fixed field requirement.' },
      { label: 'Cross-field consistency', status: consistencyScore >= 75 ? 'pass' : 'review', detail: `${consistencyScore}/100 consistency score` },
    ],
    tamperChecks: [
      {
        label: 'Portrait image quality',
        status: anomalyReasons.includes('unusual_image_noise') ? 'review' : 'pass',
        detail: anomalyReasons.includes('unusual_image_noise')
          ? 'Unusual image noise may reduce portrait comparison reliability.'
          : 'No coarse image-noise concern was detected.',
      },
      {
        label: 'OCR and field consistency',
        status: anomalyReasons.some((item) => ['aadhaar_number_mismatch', 'identity_fields_incomplete', 'low_ocr_confidence'].includes(item)) ? 'review' : 'pass',
        detail: anomalyReasons.some((item) => ['aadhaar_number_mismatch', 'identity_fields_incomplete', 'low_ocr_confidence'].includes(item))
          ? 'Some text or expected fields need manual review.'
          : 'OCR text and the checked fields are internally consistent.',
      },
      {
        label: 'Resolution, contrast and layout',
        status: anomalyReasons.some((item) => ['very_low_edge_density', 'low_contrast_image', 'low_resolution_image'].includes(item)) ? 'review' : 'pass',
        detail: anomalyReasons.some((item) => ['very_low_edge_density', 'low_contrast_image', 'low_resolution_image'].includes(item))
          ? 'The image quality may be too weak for reliable automated screening.'
          : 'The coarse resolution, contrast and edge checks passed.',
      },
      {
        label: 'OCR usability',
        status: imageSignals && ocrConfidence >= 35 ? 'pass' : 'review',
        detail: imageSignals && ocrConfidence >= 35
          ? 'The image produced usable OCR and visual quality signals.'
          : 'OCR or image-quality signals were not strong enough.',
      },
    ],
  };
}

const UIDAI_CERTIFICATE_PATH = '/uidai_offline_publickey_2026.cer';
async function inspectOfflineKycZip(
  file,
  shareCode
) {
  try {
    if (
      !shareCode ||
      !shareCode.trim()
    ) {
      return {
        detected: false,
        status: 'invalid',
        reason:
          'Offline e-KYC Share Code is required for ZIP verification.',
        isIdentityDocument: false,
        docType: 'unknown',
        confidence: 0,
        ocrConfidence: 0,
        riskScore: 100,
        decision: 'review',
        authenticityStatus:
          'not_verified',
        reasonCodes: [
          'offline_kyc_share_code_missing',
        ],
        matchedKeywords: [],
        extractedText: '',
        anomalyReasons: [],
      };
    }

    const zipReader =
      new ZipReader(
        new BlobReader(file),
        {
          password:
            shareCode.trim(),
        }
      );

    const entries =
      await zipReader.getEntries();

    const xmlEntry =
      entries.find(
        (entry) =>
          entry.filename
            .toLowerCase()
            .endsWith('.xml')
      );

    if (!xmlEntry) {
      await zipReader.close();

      return {
        detected: false,
        status: 'invalid',
        reason:
          'No XML file found inside the Offline e-KYC ZIP.',
        isIdentityDocument: false,
        docType: 'unknown',
        confidence: 0,
        ocrConfidence: 0,
        riskScore: 100,
        decision: 'review',
        authenticityStatus:
          'not_verified',
        reasonCodes: [
          'offline_kyc_xml_missing',
        ],
        matchedKeywords: [],
        extractedText: '',
        anomalyReasons: [],
      };
    }

    const xmlText =
      await xmlEntry.getData(
        new TextWriter()
      );

    await zipReader.close();

    /*
     * Parse the XML while preserving its
     * original signature markup.
     */
    const parser =
      new XMLParser({
        ignoreAttributes: false,
        preserveOrder: false,
      });

    const xml =
      parser.parse(xmlText);

    /*
     * Validate the XML's XMLDSig signature
     * using the public certificate shipped
     * with the application.
     */
    let signatureVerified = false;

    try {
      const certificateResponse =
        await fetch(
          '/uidai_offline_publickey_2026.cer',
          {
            cache: 'no-store',
          }
        );

      if (
        !certificateResponse.ok
      ) {
        throw new Error(
          `Unable to load UIDAI public certificate (${certificateResponse.status}).`
        );
      }

      const certificateBuffer =
        await certificateResponse.arrayBuffer();

      const uidaiCertificate =
        new X509Certificate(
          certificateBuffer
        );

      const publicKey =
        await uidaiCertificate.publicKey;

      const xmlDocument =
        xmldsigjs.Parse(
          xmlText
        );

      const signatures =
        xmlDocument.getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#',
          'Signature'
        );

      if (
        !signatures ||
        signatures.length === 0
      ) {
        throw new Error(
          'No XML digital signature found.'
        );
      }

      const signedXml =
        new xmldsigjs.SignedXml(
          xmlDocument
        );

      signedXml.LoadXml(
        signatures[0]
      );

      signatureVerified =
        await signedXml.Verify(
          publicKey
        );
    } catch (
      signatureError
    ) {
      console.error(
        'UIDAI XML signature verification failed:',
        signatureError
      );

      signatureVerified =
        false;
    }

    const uidData =
      xml?.OfflinePaperlessKyc
        ?.UidData || {};

    const poi =
      uidData?.Poi || {};

    const poa =
      uidData?.Poa || {};

    const referenceId =
      String(
        xml?.OfflinePaperlessKyc
          ?.["@_referenceId"] ||
          ''
      );

    const reasonCodes = [
      'offline_kyc_xml_detected',
    ];

    if (signatureVerified) {
      reasonCodes.push(
        'uidai_signature_verified'
      );
    } else {
      reasonCodes.push(
        'uidai_signature_invalid'
      );
    }

    const authenticityStatus =
      signatureVerified
        ? 'verified'
        : 'invalid';

    return {
      detected: true,
      status: signatureVerified
        ? 'verified'
        : 'invalid',

      referenceId,

      isIdentityDocument: true,
      docType: 'aadhaar',
      confidence: 100,
      ocrConfidence: 100,

      riskScore: signatureVerified
        ? 0
        : 100,

      decision: signatureVerified
        ? 'approved'
        : 'rejected',

      authenticityStatus,

      reasonCodes,

      matchedKeywords: [
        'AADHAAR',
        'UIDAI',
      ],

      extractedText: [
        poi?.["@_name"] || '',
        poi?.["@_dob"] || '',
        poi?.["@_gender"] || '',
        poa?.["@_state"] || '',
        poa?.["@_dist"] || '',
      ]
        .filter(Boolean)
        .join(' '),

      anomalyReasons: signatureVerified
        ? []
        : [
            'uidai_signature_invalid',
          ],

      reason:
        signatureVerified
          ? 'UIDAI Offline e-KYC XML signature verified successfully.'
          : 'UIDAI Offline e-KYC XML signature could not be verified.',
    };
  } catch (error) {
    console.error(
      'Offline e-KYC ZIP verification failed:',
      error
    );

    return {
      detected: false,
      status: 'invalid',
      reason:
        error.message ||
        'Unable to verify the Offline e-KYC ZIP.',
      isIdentityDocument: false,
      docType: 'unknown',
      confidence: 0,
      ocrConfidence: 0,
      riskScore: 100,
      decision: 'review',
      authenticityStatus:
        'not_verified',
      reasonCodes: [
        'offline_kyc_verification_failed',
      ],
      matchedKeywords: [],
      extractedText: '',
      anomalyReasons: [
        'offline_kyc_verification_failed',
      ],
    };
  }
}
/* -------------------------------------------------------
   SHA-256 OF THE ACTUAL UPLOADED FILE
------------------------------------------------------- */

async function sha256File(file) {
  const buffer = await file.arrayBuffer();

  const digest = await crypto.subtle.digest(
    'SHA-256',
    buffer
  );

  return Array.from(
    new Uint8Array(digest)
  )
    .map((byte) =>
      byte.toString(16).padStart(2, '0')
    )
    .join('');
}

/* -------------------------------------------------------
   LOAD AN IMAGE FILE
------------------------------------------------------- */

function getImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url =
      URL.createObjectURL(file);

    const image = new Image();

    image.onload = () => {
      URL.revokeObjectURL(url);
      resolve(image);
    };

    image.onerror = () => {
      URL.revokeObjectURL(url);

      reject(
        new Error(
          'Unable to read the uploaded image.'
        )
      );
    };

    image.src = url;
  });
}

/* -------------------------------------------------------
   ROTATE IMAGE
------------------------------------------------------- */

function createRotatedImage(
  image,
  degrees
) {
  return new Promise(
    (resolve, reject) => {
      const canvas =
        document.createElement(
          'canvas'
        );

      const swap =
        degrees === 90 ||
        degrees === 270;

      const maxOcrDimension = 2200;
      const resizeScale = Math.min(
        1,
        maxOcrDimension /
          Math.max(
            image.width,
            image.height
          )
      );
      const sourceWidth = Math.max(
        1,
        Math.round(
          image.width * resizeScale
        )
      );
      const sourceHeight = Math.max(
        1,
        Math.round(
          image.height * resizeScale
        )
      );

      canvas.width = swap
        ? sourceHeight
        : sourceWidth;

      canvas.height = swap
        ? sourceWidth
        : sourceHeight;

      const ctx =
        canvas.getContext('2d');

      if (!ctx) {
        reject(
          new Error(
            'Canvas is not available.'
          )
        );

        return;
      }

      ctx.translate(
        canvas.width / 2,
        canvas.height / 2
      );

      ctx.rotate(
        (degrees * Math.PI) / 180
      );

      ctx.drawImage(
        image,
        -sourceWidth / 2,
        -sourceHeight / 2,
        sourceWidth,
        sourceHeight
      );

      canvas.toBlob(
        (blob) => {
          if (!blob) {
            reject(
              new Error(
                'Unable to prepare image for OCR.'
              )
            );

            return;
          }

          resolve(blob);
        },
        'image/jpeg',
        0.95
      );
    }
  );
}

/* -------------------------------------------------------
   BASIC IMAGE SIGNALS
------------------------------------------------------- */

function calculateImageSignals(
  image
) {
  const maxDimension = 1600;

  const scale = Math.min(
    1,
    maxDimension /
      Math.max(
        image.width,
        image.height
      )
  );

  const width = Math.max(
    1,
    Math.round(
      image.width * scale
    )
  );

  const height = Math.max(
    1,
    Math.round(
      image.height * scale
    )
  );

  const canvas =
    document.createElement(
      'canvas'
    );

  canvas.width = width;
  canvas.height = height;

  const ctx =
    canvas.getContext('2d');

  if (!ctx) {
    return {
      width: image.width,
      height: image.height,
      brightness: null,
      contrast: null,
      edgeDensity: null,
      noiseLevel: null,
    };
  }

  ctx.drawImage(
    image,
    0,
    0,
    width,
    height
  );

  const data =
    ctx.getImageData(
      0,
      0,
      width,
      height
    ).data;

  let total = 0;
  let squared = 0;

  let edgeCount = 0;
  let noiseTotal = 0;

  const count =
    data.length / 4;

  /*
   * Convert pixels to approximate grayscale
   * and calculate basic image statistics.
   */
  const gray = new Array(
    count
  );

  for (
    let i = 0,
    p = 0;
    i < data.length;
    i += 4,
    p++
  ) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];

    const value =
      0.299 * r +
      0.587 * g +
      0.114 * b;

    gray[p] = value;

    total += value;
    squared +=
      value * value;
  }

  const mean =
    total / count;

  const variance =
    Math.max(
      0,
      squared / count -
        mean * mean
    );

  /*
   * Estimate local pixel noise and
   * simple edge density.
   *
   * These are screening signals only.
   */
  for (
    let y = 1;
    y < height - 1;
    y++
  ) {
    for (
      let x = 1;
      x < width - 1;
      x++
    ) {
      const index =
        y * width + x;

      const current =
        gray[index];

      const left =
        gray[index - 1];

      const right =
        gray[index + 1];

      const top =
        gray[index - width];

      const bottom =
        gray[index + width];

      const horizontal =
        Math.abs(
          left - right
        );

      const vertical =
        Math.abs(
          top - bottom
        );

      const edge =
        horizontal +
        vertical;

      if (edge > 45) {
        edgeCount++;
      }

      noiseTotal +=
        Math.abs(
          current -
            (
              left +
              right +
              top +
              bottom
            ) /
              4
        );
    }
  }

  const innerPixelCount =
    Math.max(
      1,
      (width - 2) *
        (height - 2)
    );

  const edgeDensity =
    edgeCount /
    innerPixelCount;

  const noiseLevel =
    noiseTotal /
    innerPixelCount;

  return {
    width,
    height,
    brightness: mean,
    contrast:
      Math.sqrt(variance),
    edgeDensity,
    noiseLevel,
  };
}

/* -------------------------------------------------------
   OCR + DOCUMENT SCREENING
------------------------------------------------------- */
function detectQrCode(image) {
  return new Promise((resolve) => {
    try {
      const maxDimension = 1800;
      const maxScanDimension = 2200;
      const maxScanPixels = 3_000_000;

      const scale = Math.min(
        1,
        maxDimension /
          Math.max(
            image.width,
            image.height
          )
      );

      const width = Math.max(
        1,
        Math.round(
          image.width * scale
        )
      );

      const height = Math.max(
        1,
        Math.round(
          image.height * scale
        )
      );

      const sourceCanvas =
        document.createElement(
          'canvas'
        );

      sourceCanvas.width =
        width;

      sourceCanvas.height =
        height;

      const sourceCtx =
        sourceCanvas.getContext(
          '2d'
        );
        const zxingReader =
  new BrowserQRCodeReader();

      if (!sourceCtx) {
        resolve({
          detected: false,
          data: '',
        });

        return;
      }

      sourceCtx.drawImage(
        image,
        0,
        0,
        width,
        height
      );

      /*
       * Aadhaar PDFs can contain several
       * panels on one page. Scan the full
       * page plus overlapping regions.
       */
      const regions = [
        {
          name: 'full',
          x: 0,
          y: 0,
          w: width,
          h: height,
        },

        {
          name: 'top-left',
          x: 0,
          y: 0,
          w: Math.floor(
            width * 0.75
          ),
          h: Math.floor(
            height * 0.75
          ),
        },

        {
          name: 'top-right',
          x: Math.floor(
            width * 0.25
          ),
          y: 0,
          w: Math.floor(
            width * 0.75
          ),
          h: Math.floor(
            height * 0.75
          ),
        },

        {
          name: 'bottom-left',
          x: 0,
          y: Math.floor(
            height * 0.25
          ),
          w: Math.floor(
            width * 0.75
          ),
          h: Math.floor(
            height * 0.75
          ),
        },

        {
          name: 'bottom-right',
          x: Math.floor(
            width * 0.25
          ),
          y: Math.floor(
            height * 0.25
          ),
          w: Math.floor(
            width * 0.75
          ),
          h: Math.floor(
            height * 0.75
          ),
        },

        /*
         * Extra QR-focused areas.
         */
        {
          name: 'upper-middle',
          x: Math.floor(
            width * 0.35
          ),
          y: Math.floor(
            height * 0.20
          ),
          w: Math.floor(
            width * 0.45
          ),
          h: Math.floor(
            height * 0.45
          ),
        },

        {
          name: 'lower-right-focus',
          x: Math.floor(
            width * 0.55
          ),
          y: Math.floor(
            height * 0.55
          ),
          w: Math.floor(
            width * 0.40
          ),
          h: Math.floor(
            height * 0.40
          ),
        },
      ];

      const scaleFactors = [
        1,
        1.35,
      ];

      for (
        const region of regions
      ) {
        const cropCanvas =
          document.createElement(
            'canvas'
          );

        const cropWidth =
          Math.max(
            1,
            Math.floor(region.w)
          );

        const cropHeight =
          Math.max(
            1,
            Math.floor(region.h)
          );

        cropCanvas.width =
          cropWidth;

        cropCanvas.height =
          cropHeight;

        const cropCtx =
          cropCanvas.getContext(
            '2d'
          );

        if (!cropCtx) {
          continue;
        }

        cropCtx.drawImage(
          sourceCanvas,
          region.x,
          region.y,
          region.w,
          region.h,
          0,
          0,
          cropWidth,
          cropHeight
        );

        for (
          const factor of scaleFactors
        ) {
          const requestedWidth =
            cropWidth * factor;
          const requestedHeight =
            cropHeight * factor;
          const memoryScale = Math.min(
            1,
            maxScanDimension /
              Math.max(
                requestedWidth,
                requestedHeight
              ),
            Math.sqrt(
              maxScanPixels /
                Math.max(
                  1,
                  requestedWidth *
                    requestedHeight
                )
            )
          );
          const scanWidth = Math.max(
            1,
            Math.round(
              requestedWidth *
                memoryScale
            )
          );
          const scanHeight = Math.max(
            1,
            Math.round(
              requestedHeight *
                memoryScale
            )
          );

          /*
           * Try three image versions:
           * 1. normal
           * 2. grayscale
           * 3. black/white threshold
           */
          for (
            const mode of [
              'normal',
              'grayscale',
              'threshold',
            ]
          ) {
            const scanCanvas =
              document.createElement(
                'canvas'
              );

            scanCanvas.width =
              scanWidth;

            scanCanvas.height =
              scanHeight;

            const scanCtx =
              scanCanvas.getContext(
                '2d'
              );

            if (!scanCtx) {
              continue;
            }

            scanCtx.imageSmoothingEnabled =
              false;

            scanCtx.drawImage(
              cropCanvas,
              0,
              0,
              scanWidth,
              scanHeight
            );

            if (
              mode !==
              'normal'
            ) {
              const pixels =
                scanCtx.getImageData(
                  0,
                  0,
                  scanWidth,
                  scanHeight
                );

              const data =
                pixels.data;

              for (
                let i = 0;
                i < data.length;
                i += 4
              ) {
                const gray =
                  0.299 *
                    data[i] +
                  0.587 *
                    data[i + 1] +
                  0.114 *
                    data[i + 2];

                if (
                  mode ===
                  'grayscale'
                ) {
                  data[i] =
                    gray;
                  data[i + 1] =
                    gray;
                  data[i + 2] =
                    gray;
                } else {
                  const value =
                    gray < 150
                      ? 0
                      : 255;

                  data[i] =
                    value;
                  data[i + 1] =
                    value;
                  data[i + 2] =
                    value;
                }
              }

              scanCtx.putImageData(
                pixels,
                0,
                0
              );
            }

            const imageData =
              scanCtx.getImageData(
                0,
                0,
                scanWidth,
                scanHeight
              );

            const result =
              jsQR(
                imageData.data,
                imageData.width,
                imageData.height,
                {
                  inversionAttempts:
                    'attemptBoth',
                }
              );

            if (
  result &&
  result.data &&
  result.data.trim().length > 0
) {
  scanCanvas.width = 1;
  scanCanvas.height = 1;
  cropCanvas.width = 1;
  cropCanvas.height = 1;
  sourceCanvas.width = 1;
  sourceCanvas.height = 1;

  resolve({
    detected: true,
    data: result.data,
  });

  return;
}
try {
  const zxingResult =
    zxingReader.decodeFromCanvas(
      scanCanvas
    );

  const zxingPayload =
    zxingResult
      ?.getText?.()
      ?.trim();

  if (zxingPayload) {
    scanCanvas.width = 1;
    scanCanvas.height = 1;
    cropCanvas.width = 1;
    cropCanvas.height = 1;
    sourceCanvas.width = 1;
    sourceCanvas.height = 1;

    resolve({
      detected: true,
      data: zxingPayload,
    });

    return;
  }
} catch (zxingError) {
  // No QR found in this scan.
  // Continue with the next crop.
}
            scanCanvas.width = 1;
            scanCanvas.height = 1;
          }
        }

        cropCanvas.width = 1;
        cropCanvas.height = 1;
      }

      sourceCanvas.width = 1;
      sourceCanvas.height = 1;

      console.log(
        'QR not detected after all scans'
      );

      resolve({
        detected: false,
        data: '',
      });
    } catch (error) {
      console.error(
        'QR detection failed:',
        error
      );

      resolve({
        detected: false,
        data: '',
      });
    }
  });
}
/*
 * Aadhaar numbers use the Verhoeff check digit.  OCR can also pick up
 * enrolment numbers, VID fragments, or random 12-digit strings, so only
 * checksum-valid values are used for an Aadhaar-number conflict signal.
 */
function isValidAadhaarNumber(value) {
  const digits = String(value || '').replace(/\D/g, '');

  if (!/^\d{12}$/.test(digits) || /^(\d)\1{11}$/.test(digits)) {
    return false;
  }

  const multiplication = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  const permutation = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  return digits
    .split('')
    .reverse()
    .reduce(
      (check, digit, index) =>
        multiplication[check][
          permutation[index % 8][Number(digit)]
        ],
      0
    ) === 0;
}

function evaluateScreening({
  text,
  ocrConfidence,
  imageSignals,
  file,
}) {
  const normalized = String(text || '')
    .toUpperCase()
    .replace(/\s+/g, ' ')
    .trim();

  /*
   * ---------------------------------------------
   * 1. IDENTITY-DOCUMENT INDICATORS
   * ---------------------------------------------
   */

  const keywords = [
    'AADHAAR',
    'AADHAR',
    'UIDAI',
    'PASSPORT',
    'IDENTITY',
    'IDENTIFICATION',
    'NATIONAL ID',
    'DRIVING',
    'LICENCE',
    'LICENSE',
    'VISA',
    'PERMIT',
    'DATE OF BIRTH',
    'DOB',
    'GOVERNMENT OF INDIA',
    'UNIQUE IDENTIFICATION AUTHORITY',
    'ENROLMENT NO',
    'ENROLLMENT NO',
    'YOUR AADHAAR NO',
    'AADHAAR NO',
    'VID',
    'MALE',
    'FEMALE',
    'ADDRESS',
  ];

  const matchedKeywords =
    keywords.filter((word) =>
      normalized.includes(word)
    );

  const fileNameLooksAadhaar =
    /(?:aadhaar|aadhar|adhaar|adhar)/i.test(
      file?.name || ''
    );

  /*
   * Aadhaar-like number.
   */
  const hasAadhaarNumber =
    /\b\d{4}\s?\d{4}\s?\d{4}\b/.test(
      normalized
    );
const aadhaarNumbers =
  normalized.match(
    /\b\d{4}\s?\d{4}\s?\d{4}\b/g
  ) || [];

const normalizedAadhaarNumbers =
  aadhaarNumbers.map((value) =>
    value.replace(/\s/g, '')
  );

const validAadhaarNumbers =
  normalizedAadhaarNumbers.filter(
    isValidAadhaarNumber
  );

const uniqueAadhaarNumbers =
  Array.from(
    new Set(validAadhaarNumbers)
  );

const aadhaarNumberMismatch =
  uniqueAadhaarNumbers.length > 1 &&
  normalized.includes('AADHAAR') &&
  normalized.includes('UIDAI');
  /*
   * Passport-like number.
   */
  const hasPassportNumber =
    /\b[A-Z]\d{7}\b/.test(
      normalized
    );

  /*
   * Date of birth/date pattern.
   */
  const hasDate =
    /\b(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{1,2}\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\s+\d{2,4})\b/.test(
      normalized
    );

  const hasName =
    /\bNAME\b/.test(normalized);

  const hasAddress =
    /\bADDRESS\b/.test(normalized);

  const hasGovernmentMarker =
    normalized.includes(
      'GOVERNMENT OF INDIA'
    );

  const hasUIDAIMarker =
    normalized.includes(
      'UIDAI'
    ) ||
    normalized.includes(
      'UNIQUE IDENTIFICATION AUTHORITY'
    );

  const namedCardMatch = classifyNamedCard(normalized);

  /*
   * ---------------------------------------------
   * 2. DOCUMENT DETECTION SCORE
   * ---------------------------------------------
   */

  let detectionScore = 0;

  detectionScore += Math.min(
    matchedKeywords.length * 7,
    42
  );

  if (hasAadhaarNumber) {
    detectionScore += 32;
  }

  if (hasPassportNumber) {
    detectionScore += 30;
  }

  if (hasDate) {
    detectionScore += 8;
  }

  if (hasName) {
    detectionScore += 4;
  }

  if (hasAddress) {
    detectionScore += 4;
  }

  if (hasGovernmentMarker) {
    detectionScore += 10;
  }

  if (hasUIDAIMarker) {
    detectionScore += 12;
  }

  if (namedCardMatch) {
    detectionScore += namedCardMatch.confidence === 'named' ? 70 : 45;
  }

  /*
   * A filename is only a heuristic, never proof. It is useful for scanned
   * PDFs where OCR may miss the small Aadhaar heading on the first pass.
   */
  if (fileNameLooksAadhaar) {
    detectionScore += 20;
  }

  detectionScore = Math.min(
    detectionScore,
    100
  );

  /*
   * ---------------------------------------------
   * 3. DOCUMENT TYPE
   * ---------------------------------------------
   */

  const isAadhaar =
    (
      (
        normalized.includes(
          'AADHAAR'
        ) ||
        normalized.includes(
          'AADHAR'
        ) ||
        normalized.includes(
          'UIDAI'
        ) ||
        normalized.includes(
          'YOUR AADHAAR'
        )
      ) &&
      (
        hasAadhaarNumber ||
        hasDate ||
        hasGovernmentMarker ||
        hasUIDAIMarker
      )
    ) ||
    (
      hasAadhaarNumber &&
      matchedKeywords.length >= 1
    ) ||
    (
      hasUIDAIMarker &&
      hasDate
    ) ||
    (
      fileNameLooksAadhaar &&
      Boolean(imageSignals)
    );

  const isPassport =
    normalized.includes(
      'PASSPORT'
    ) &&
    (
      hasPassportNumber ||
      hasDate
    );

  const isDrivingLicense =
    (
      normalized.includes(
        'DRIVING'
      ) ||
      normalized.includes(
        'LICENCE'
      ) ||
      normalized.includes(
        'LICENSE'
      )
    ) &&
    (
      hasDate ||
      hasName
    );

  const isVisa = normalized.includes('VISA') && (hasDate || /\b[A-Z0-9]{6,16}\b/.test(normalized));
  const isPermit = normalized.includes('PERMIT') && (hasDate || hasName);

  let docType =
    'unknown';

  if (isAadhaar) {
    docType =
      'aadhaar';
  } else if (
    isPassport
  ) {
    docType =
      'passport';
  } else if (
    isDrivingLicense
  ) {
    docType =
      'driving_license';
  } else if (isVisa) {
    docType = 'visa';
  } else if (isPermit) {
    docType = 'permit';
  } else if (namedCardMatch) {
    docType = namedCardMatch.docType;
  } else if (
    detectionScore >= 45 &&
    (
      hasDate ||
      hasName
    )
  ) {
    docType =
      'national_id';
  }

  const isIdentityDocument =
    docType !==
    'unknown';

  const documentLabel = getDocumentTypeLabel(
    docType,
    namedCardMatch?.label
  );

  const requiresDate = [
    'aadhaar',
    'passport',
    'driving_license',
    'visa',
    'permit',
    'national_id',
    'voter_id',
  ].includes(docType);

  /*
   * ---------------------------------------------
   * 4. IMAGE / OCR ANOMALY SIGNALS
   * ---------------------------------------------
   *
   * These are screening signals.
   * They DO NOT prove forgery.
   * ---------------------------------------------
   */

  const anomalyReasons = [];
  if (
  imageSignals &&
  imageSignals.edgeDensity !== null &&
  imageSignals.edgeDensity < 0.01
) {
  anomalyReasons.push(
    'very_low_edge_density'
  );
}

if (
  imageSignals &&
  imageSignals.noiseLevel !== null &&
  imageSignals.noiseLevel > 35
) {
  anomalyReasons.push(
    'unusual_image_noise'
  );
}
 if (aadhaarNumberMismatch) {
  anomalyReasons.push(
    'aadhaar_number_mismatch'
  );
}
  /*
   * Very small image.
   */
  if (
    imageSignals &&
    (
      imageSignals.width < 500 ||
      imageSignals.height < 500
    )
  ) {
    anomalyReasons.push(
      'low_resolution_image'
    );
  }

  /*
   * Very low contrast.
   */
  if (
    imageSignals &&
    imageSignals.contrast !== null &&
    imageSignals.contrast < 16
  ) {
    anomalyReasons.push(
      'low_contrast_image'
    );
  }

  /*
   * OCR confidence.
   */
  if (
    isIdentityDocument &&
    ocrConfidence < 35
  ) {
    anomalyReasons.push(
      'low_ocr_confidence'
    );
  }

  /*
   * Expected identity fields.
   */
  if (
    requiresDate &&
    !hasDate
  ) {
    anomalyReasons.push(
      'date_not_detected'
    );
  }

  if (
    isIdentityDocument &&
    !hasName &&
    !hasAddress
  ) {
    anomalyReasons.push(
      'identity_fields_incomplete'
    );
  }

  /*
   * Very small uploaded file.
   */
  if (
    file &&
    file.size <
      15 * 1024
  ) {
    anomalyReasons.push(
      'very_small_file'
    );
  }

  /*
   * ---------------------------------------------
   * 5. CONSISTENCY SIGNALS
   * ---------------------------------------------
   */

  let consistencyScore = 100;

  if (
    requiresDate &&
    !hasDate
  ) {
    consistencyScore -= 15;
  }

  if (
    isIdentityDocument &&
    !hasName &&
    !hasAddress
  ) {
    consistencyScore -= 15;
  }

  if (
    isAadhaar &&
    !hasAadhaarNumber &&
    !hasUIDAIMarker
  ) {
    consistencyScore -= 10;
  }

  if (
    ocrConfidence < 35
  ) {
    consistencyScore -= 20;
  }

  consistencyScore =
    Math.max(
      0,
      Math.min(
        100,
        consistencyScore
      )
    );

  /*
   * ---------------------------------------------
   * 6. SCREENING RISK SCORE
   * ---------------------------------------------
   */

  let riskScore = 100;

  /*
   * No document detected:
   * high risk / reject.
   */
  if (
    !isIdentityDocument
  ) {
    riskScore =
      90;
  } else {
    /*
     * Start from a moderate score.
     */
    riskScore =
      45;

    /*
     * Strong document evidence lowers risk.
     */
    if (
      detectionScore >= 80
    ) {
      riskScore -= 15;
    } else if (
      detectionScore >= 60
    ) {
      riskScore -= 8;
    }

    /*
     * Strong OCR lowers risk.
     */
    if (
      ocrConfidence >= 75
    ) {
      riskScore -= 10;
    } else if (
      ocrConfidence >= 55
    ) {
      riskScore -= 5;
    }

    /*
     * Strong Aadhaar number pattern.
     */
    if (
      hasAadhaarNumber
    ) {
      riskScore -= 8;
    }

    /*
     * Government/UIDAI markers.
     */
    if (
      hasGovernmentMarker
    ) {
      riskScore -= 5;
    }

    if (
      hasUIDAIMarker
    ) {
      riskScore -= 5;
    }
    /*
     * Consistency.
     */
    if (
      consistencyScore >= 90
    ) {
      riskScore -= 5;
    } else if (
      consistencyScore < 60
    ) {
      riskScore += 10;
    }

    /*
     * Anomaly signals.
     */
    if (
      anomalyReasons.includes(
        'low_resolution_image'
      )
    ) {
      riskScore += 12;
    }

    if (
      anomalyReasons.includes(
        'low_contrast_image'
      )
    ) {
      riskScore += 8;
    }

    if (
      anomalyReasons.includes(
        'low_ocr_confidence'
      )
    ) {
      riskScore += 12;
    }

    if (
      anomalyReasons.includes(
        'date_not_detected'
      )
    ) {
      riskScore += 5;
    }

    if (
      anomalyReasons.includes(
        'identity_fields_incomplete'
      )
    ) {
      riskScore += 8;
    }

    if (
      anomalyReasons.includes(
        'very_small_file'
      )
    ) {
      riskScore += 10;
    }
  }
  if (
  anomalyReasons.includes(
    'aadhaar_number_mismatch'
  )
) {
  riskScore += 35;
}
  if (
  anomalyReasons.includes(
    'very_low_edge_density'
  )
) {
  riskScore += 12;
}

if (
  anomalyReasons.includes(
    'unusual_image_noise'
  )
) {
  riskScore += 10;
}

  riskScore =
    Math.max(
      0,
      Math.min(
        100,
        Math.round(
          riskScore
        )
      )
    );

  /*
   * ---------------------------------------------
   * 7. FINAL DECISION
   * ---------------------------------------------
   *
   * This is screening:
   *
   * APPROVED = low screening risk
   * REVIEW   = uncertain
   * REJECTED = not identified / high risk
   */

  let decision =
    'rejected';

  if (
  !isIdentityDocument
) {
  decision =
    'rejected';
} else if (
  riskScore >= 50
) {
  decision =
    'review';

} else {
  decision =
    'approved';
}
  /*
   * ---------------------------------------------
   * 8. EXPLAINABLE REASON CODES
   * ---------------------------------------------
   */

  const reasonCodes =
    [];

  if (
    isIdentityDocument
  ) {
    reasonCodes.push(
      'identity_document_detected'
    );
  } else {
    reasonCodes.push(
      'identity_document_not_detected'
    );
  }
const authenticityStatus =
  isIdentityDocument
    ? 'pending_face_match'
    : 'not_available';
  if (
    matchedKeywords.length >
    0
  ) {
    reasonCodes.push(
      'identity_keywords_detected'
    );
  }

  if (
    hasAadhaarNumber
  ) {
    reasonCodes.push(
      'aadhaar_number_pattern_detected'
    );
  }

  if (
    hasPassportNumber
  ) {
    reasonCodes.push(
      'passport_number_pattern_detected'
    );
  }

  if (hasDate) {
    reasonCodes.push(
      'date_pattern_detected'
    );
  }

  if (hasGovernmentMarker) {
    reasonCodes.push(
      'government_marker_detected'
    );
  }

  if (hasUIDAIMarker) {
    reasonCodes.push(
      'uidai_marker_detected'
    );
  }

  if (fileNameLooksAadhaar) {
    reasonCodes.push(
      'aadhaar_filename_hint'
    );
  }

  if (namedCardMatch) {
    reasonCodes.push(
      'printed_card_title_detected',
      `${docType}_detected`
    );
  }

  reasonCodes.push(
    `consistency_score_${consistencyScore}`
  );

  reasonCodes.push(
    `detection_score_${detectionScore}`
  );

  if (
    anomalyReasons.length >
    0
  ) {
    reasonCodes.push(
      ...anomalyReasons
    );
  }

  /*
   * Important transparency flag.
   */
  if (
    isIdentityDocument
  ) {
    reasonCodes.push(
      'initial_tamper_screen_completed'
    );

    if (authenticityStatus === 'pending_face_match') {
      reasonCodes.push('camera_face_match_required');
    }
  }

  const extractedFields = extractDocumentFields(text, docType);
  const moduleFindings = buildModuleFindings({ docType, extractedFields, anomalyReasons, consistencyScore, ocrConfidence, imageSignals });

  return {
  isIdentityDocument,
  authenticityStatus,

  docType,
  documentLabel,

    confidence:
      detectionScore,

    ocrConfidence,

    riskScore,

    decision,

    consistencyScore,

    reasonCodes:
      Array.from(
        new Set(
          reasonCodes
        )
      ),

    matchedKeywords,

    extractedText:
      normalized,

    anomalyReasons,
    extractedFields,
    ...moduleFindings,

    reason:
      !isIdentityDocument
        ? 'No sufficient identity-document indicators detected.'
        : decision ===
            'approved'
          ? 'Identity document detected with low initial screening risk.'
          : 'Identity document detected, but additional review is recommended.',
  };
}
async function analyzeImageDocument(
  file
) {
  const image =
    await getImageFromFile(
      file
    );

 const imageSignals =
  calculateImageSignals(image);

  const angles = [
  0,
  90,
  270,
  180,
];

const worker =
  await createWorker('eng');

  let bestResult =
    null;

  try {
    for (
      const angle of angles
    ) {
      const imageBlob =
        await createRotatedImage(
          image,
          angle
        );

      const result =
        await worker.recognize(
          imageBlob
        );

      const text =
        result?.data?.text ||
        '';

      const confidence =
        Number(
          result?.data
            ?.confidence || 0
        );

      const score =
        text.length +
        confidence * 2;

      console.log(
        `OCR ${angle}°`,
        {
          confidence,
          characters:
            text.length,
        }
      );

      if (
        !bestResult ||
        score >
          bestResult.score
      ) {
        bestResult = {
          angle,
          text,
          confidence,
          score,
        };
      }
    }
  } finally {
    await worker.terminate();
  }

  const screening =
  evaluateScreening({
    text:
      bestResult?.text ||
      '',
    ocrConfidence:
      bestResult?.confidence ||
      0,
    imageSignals,
    file,
  });

  return {
    ...screening,
    rotationUsed:
      bestResult?.angle || 0,
    imageWidth:
      imageSignals.width,
    imageHeight:
      imageSignals.height,
    faceSourceFile: file,
  };
}

/* -------------------------------------------------------
   PDF ANALYSIS
   PDF -> IMAGE -> OCR
------------------------------------------------------- */

async function analyzePdfDocument(
  file
) {
  const pdfjsLib =
  await import(
    'pdfjs-dist/legacy/build/pdf.mjs'
  );

const buffer =
  await file.arrayBuffer();

/*
 * PDF.js needs a worker source in the browser.
 * Use the worker version that matches the loaded
 * PDF.js library.
 */
pdfjsLib.GlobalWorkerOptions.workerSrc =
  `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.mjs`;

const pdf =
  await pdfjsLib
    .getDocument({
      data: buffer,
    })
    .promise;
  /*
   * Analyze up to 5 pages.
   *
   * This handles:
   * - one-page Aadhaar scans
   * - front/back documents
   * - multi-panel PDF scans
   */
  const pageCount =
    Math.min(
      pdf.numPages,
      5
    );

  const pageResults = [];

  for (
    let pageNumber = 1;
    pageNumber <= pageCount;
    pageNumber++
  ) {
    const page =
      await pdf.getPage(
        pageNumber
      );

    /*
     * Render sharply enough for QR/OCR while keeping the browser tab
     * below a predictable memory ceiling. A fixed scale of 5 can create
     * canvases larger than 50 MB per page before OCR even starts.
     */
    const baseViewport =
      page.getViewport({
        scale: 1,
      });
    const maxPdfDimension = 2600;
    const maxPdfPixels = 4_000_000;
    const renderScale = Math.max(
      0.5,
      Math.min(
        3,
        maxPdfDimension /
          Math.max(
            baseViewport.width,
            baseViewport.height
          ),
        Math.sqrt(
          maxPdfPixels /
            Math.max(
              1,
              baseViewport.width *
                baseViewport.height
            )
        )
      )
    );
    const viewport =
      page.getViewport({
        scale: renderScale,
      });

    const canvas =
      document.createElement(
        'canvas'
      );

    canvas.width =
      Math.ceil(
        viewport.width
      );

    canvas.height =
      Math.ceil(
        viewport.height
      );

    const context =
      canvas.getContext(
        '2d'
      );

    if (!context) {
      page.cleanup();
      continue;
    }

    await page.render({
      canvasContext:
        context,
      viewport,
    }).promise;

    const blob =
      await new Promise(
        (resolve, reject) => {
          canvas.toBlob(
            (value) => {
              if (value) {
                resolve(
                  value
                );
              } else {
                reject(
                  new Error(
                    `Could not render PDF page ${pageNumber}.`
                  )
                );
              }
            },
            /* PNG prevents JPEG artefacts from destroying small QR cells. */
            'image/png'
          );
        }
      );

    const imageFile =
      new File(
        [blob],
        `${file.name}-page-${pageNumber}.png`,
        {
          type: 'image/png',
        }
      );

    canvas.width = 1;
    canvas.height = 1;
    page.cleanup();

    const result =
  await analyzeImageDocument(
    imageFile
  );

pageResults.push({
  ...result,
pdfPage:
    pageNumber,
});
  }

  if (
    pageResults.length === 0
  ) {
    throw new Error(
      'No PDF pages could be rendered.'
    );
  }

  /*
   * Prefer an identity-document result.
   * If several pages qualify, use the highest confidence.
   */
  const identityPages =
    pageResults.filter(
      (result) =>
        result.isIdentityDocument
    );

  const candidates =
    identityPages.length > 0
      ? identityPages
      : pageResults;

  const bestResult =
    candidates.reduce(
      (best, current) => {
        if (!best) {
          return current;
        }

        if (
          current.confidence >
          best.confidence
        ) {
          return current;
        }

        return best;
      },
      null
    );

  return {
    ...bestResult,
    reasonCodes:
      Array.from(
        new Set([
          ...(bestResult
            .reasonCodes ||
            []),
          'pdf_page_rendered',
          `pdf_page_${bestResult.pdfPage}_analysed`,
        ])
      ),
    reason:
      bestResult.isIdentityDocument
        ? `Identity document detected on PDF page ${bestResult.pdfPage}.`
        : 'No sufficient identity-document indicators detected in the PDF.',
  };
}

/* -------------------------------------------------------
   MAIN DOCUMENT ANALYSER
------------------------------------------------------- */

async function analyzeDocument(
  file,
  shareCode
) {

  if (!file) {
    return {
      isIdentityDocument:
        false,
      docType:
        'unknown',
      confidence:
        0,
      ocrConfidence:
        0,
      riskScore:
        100,
      decision:
        'rejected',
      reasonCodes: [
        'no_document_selected',
      ],
      matchedKeywords: [],
      extractedText:
        '',
      anomalyReasons: [],
      rotationUsed:
        0,
      reason:
        'No document selected.',
    };
  }

  try {
    if (
  file.type === 'application/zip' ||
  file.name
    .toLowerCase()
    .endsWith('.zip')
) {
  return await inspectOfflineKycZip(
  file,
  shareCode
);
}
    if (
      file.type ===
        'application/pdf' ||
      file.name
        .toLowerCase()
        .endsWith('.pdf')
    ) {
      return await analyzePdfDocument(
        file
      );
    }

    if (
      file.type ===
        'image/jpeg' ||
      file.type ===
        'image/png'
    ) {
      return await analyzeImageDocument(
        file
      );
    }

    return {
      isIdentityDocument:
        false,
      docType:
        'unknown',
      confidence:
        0,
      ocrConfidence:
        0,
      riskScore:
        100,
      decision:
        'rejected',
      reasonCodes: [
        'unsupported_document_type',
      ],
      matchedKeywords: [],
      extractedText:
        '',
      anomalyReasons: [],
      rotationUsed:
        0,
      reason:
        'Unsupported document type.',
    };
  } catch (error) {
    console.error(
      'Document analysis failed:',
      error
    );

    return {
      isIdentityDocument:
        false,
      docType:
        'unknown',
      confidence:
        0,
      ocrConfidence:
        0,
      riskScore:
        100,
      decision:
        'review',
      reasonCodes: [
        'document_analysis_failed',
      ],
      matchedKeywords: [],
      extractedText:
        '',
      anomalyReasons: [],
      rotationUsed:
        0,
      reason:
        error.message ||
        'Unable to analyze document.',
    };
  }
}

let faceModelsPromise = null;

async function loadFaceModels() {
  if (!faceModelsPromise) {
    faceModelsPromise = import(
      '@vladmandic/face-api'
    ).then(async (module) => {
      const faceapi =
        module.default?.nets
          ? module.default
          : module;

      await Promise.all([
        faceapi.nets.ssdMobilenetv1.loadFromUri(
          '/face-models'
        ),
        faceapi.nets.faceLandmark68Net.loadFromUri(
          '/face-models'
        ),
        faceapi.nets.faceRecognitionNet.loadFromUri(
          '/face-models'
        ),
      ]);

      return faceapi;
    });
  }

  try {
    return await faceModelsPromise;
  } catch (error) {
    faceModelsPromise = null;
    throw error;
  }
}

async function detectFaceDescriptor(
  faceapi,
  file,
  source
) {
  const image =
    await getImageFromFile(file);

  const detections =
    await faceapi
      .detectAllFaces(
        image,
        new faceapi.SsdMobilenetv1Options({
          minConfidence:
            source === 'selfie'
              ? 0.4
              : 0.3,
          maxResults: 6,
        })
      )
      .withFaceLandmarks()
      .withFaceDescriptors();

  if (detections.length === 0) {
    throw new Error(
      source === 'selfie'
        ? 'No face was detected in the live selfie. Retake it in brighter light and look straight at the camera.'
        : 'No portrait was detected in the document image. Use a clearer photo with the printed portrait fully visible.'
    );
  }

  if (
    source === 'selfie' &&
    detections.length !== 1
  ) {
    throw new Error(
      'More than one face was detected in the selfie. Retake it with only one person in view.'
    );
  }

  const largest =
    [...detections].sort(
      (left, right) =>
        right.detection.box.width *
          right.detection.box.height -
        left.detection.box.width *
          left.detection.box.height
    )[0];

  return {
    descriptor: largest.descriptor,
    faceCount: detections.length,
    detectionConfidence:
      Math.round(
        largest.detection.score *
          100
      ),
  };
}

async function compareDocumentFaceToSelfie(
  documentFile,
  selfieFile
) {
  const faceapi =
    await loadFaceModels();

  const [documentFace, selfieFace] =
    await Promise.all([
      detectFaceDescriptor(
        faceapi,
        documentFile,
        'document'
      ),
      detectFaceDescriptor(
        faceapi,
        selfieFile,
        'selfie'
      ),
    ]);

  const distance =
    faceapi.euclideanDistance(
      documentFace.descriptor,
      selfieFace.descriptor
    );

  /*
   * Face-API descriptors are commonly compared around a 0.6 distance.
   * This prototype uses that general threshold so older or small printed
   * ID portraits are not rejected solely because of scan quality. The
   * displayed score is a heuristic, not a calibrated biometric probability.
   */
  const matched = distance <= 0.6;
  const similarityScore =
    Math.max(
      0,
      Math.min(
        100,
        Math.round(
          (1 - distance) * 100
        )
      )
    );

  return {
    matched,
    distance,
    similarityScore,
    documentFaceCount:
      documentFace.faceCount,
    selfieFaceCount:
      selfieFace.faceCount,
    documentFaceConfidence:
      documentFace.detectionConfidence,
    selfieFaceConfidence:
      selfieFace.detectionConfidence,
  };
}

function applyFaceMatchDecision(
  analysis,
  faceMatch
) {
  const reasonCodes =
    (analysis.reasonCodes || [])
      .filter(
        (reason) =>
          ![
            'live_face_match_required',
            'camera_face_match_required',
          ].includes(reason)
      );

  reasonCodes.push(
    'camera_selfie_captured',
    'document_face_detected',
    'selfie_face_detected'
  );

  const documentRecognized =
    analysis.docType !== 'unknown';
  const documentLabel =
    analysis.documentLabel ||
    getDocumentTypeLabel(analysis.docType);
  const describedDocument =
    documentRecognized
      ? `the ${documentLabel.toLowerCase()}`
      : 'the document';

  if (faceMatch.documentFaceCount !== 1) {
    reasonCodes.push(
      'multiple_document_faces_detected'
    );

    return {
      ...analysis,
      faceMatchStatus: 'ambiguous',
      faceSimilarity:
        faceMatch.similarityScore,
      faceDistance:
        Number(
          faceMatch.distance.toFixed(3)
        ),
      selfieCaptured: true,
      authenticityStatus:
        'review_required',
      authenticityEvidence:
        'More than one face was detected on the document. No single portrait was used for automatic approval.',
      decision: 'review',
      riskScore:
        Math.max(
          65,
          analysis.riskScore
        ),
      reasonCodes:
        Array.from(
          new Set(reasonCodes)
        ),
      reason:
        'Multiple document portraits were detected. Select a document with one clearly visible holder portrait or review it manually.',
    };
  }

  if (faceMatch.matched) {
    reasonCodes.push(
      'face_match_passed'
    );

    const validationPassed =
      (analysis.validationChecks || [])
        .every((check) => check.status === 'pass');
    const hasBlockingAnomaly =
      (analysis.anomalyReasons || []).length > 0;
    const supportsAutomaticApproval =
      AUTO_APPROVABLE_PHOTO_ID_TYPES.has(
        analysis.docType
      );
    const screeningPassed =
      documentRecognized &&
      supportsAutomaticApproval &&
      validationPassed &&
      !hasBlockingAnomaly &&
      analysis.decision === 'approved';

    if (!documentRecognized) {
      reasonCodes.push(
        'document_type_review_required'
      );
    } else if (!supportsAutomaticApproval) {
      reasonCodes.push(
        'issuer_verification_required'
      );
    } else if (!screeningPassed) {
      reasonCodes.push(
        'document_screening_review_required'
      );
    }

    return {
      ...analysis,
      faceMatchStatus: 'matched',
      faceSimilarity:
        faceMatch.similarityScore,
      faceDistance:
        Number(
          faceMatch.distance.toFixed(3)
        ),
      selfieCaptured: true,
      authenticityStatus:
        'face_match_passed',
      authenticityEvidence:
        `The portrait on ${describedDocument} matched the camera selfie in the on-device prototype check. This confirms face similarity only, not liveness or issuer authenticity.`,
      decision:
        screeningPassed
          ? 'approved'
          : 'review',
      riskScore:
        screeningPassed
          ? Math.min(
              20,
              analysis.riskScore
            )
          : analysis.riskScore,
      reasonCodes:
        Array.from(
          new Set(reasonCodes)
        ),
      reason:
        screeningPassed
          ? `Prototype face check passed for ${documentLabel}: the document portrait matched the camera selfie.`
          : !documentRecognized
            ? 'The document portrait matched the camera selfie, but the document type still needs review.'
            : !supportsAutomaticApproval
              ? `The portrait matched, but ${documentLabel} issuer validity is not independently verified by this prototype.`
              : 'The document portrait matched the live selfie, but one or more document screening checks still need review.',
    };
  }

  reasonCodes.push(
    'face_match_failed'
  );

  return {
    ...analysis,
    faceMatchStatus: 'not_matched',
    faceSimilarity:
      faceMatch.similarityScore,
    faceDistance:
      Number(
        faceMatch.distance.toFixed(3)
      ),
    selfieCaptured: true,
    authenticityStatus:
      'face_match_failed',
    authenticityEvidence:
      `The portrait on ${describedDocument} did not match the camera selfie closely enough.`,
    decision: 'rejected',
    riskScore: 100,
    reasonCodes:
      Array.from(
        new Set(reasonCodes)
      ),
    reason:
      'Prototype rejection: the camera selfie did not match the document portrait closely enough.',
  };
}

/* -------------------------------------------------------
   PAGE COMPONENT
------------------------------------------------------- */

export default function Home() {
  const [
    supabase,
    setSupabase,
  ] = useState(null);
  const [
    status,
    setStatus,
  ] = useState(
    'connecting'
  );

  const [
    statusMessage,
    setStatusMessage,
  ] = useState(
    'Connecting to Supabase…'
  );

  const [
    ledger,
    setLedger,
  ] = useState([]);

  const [
    running,
    setRunning,
  ] = useState(false);

  const [
    selectedFile,
    setSelectedFile,
  ] = useState(null);
  const [
  shareCode,
  setShareCode,
] = useState('');

  const [
    uploadError,
    setUploadError,
  ] = useState('');

  const [
    ledgerError,
    setLedgerError,
  ] = useState('');

  const [
    analysisResult,
    setAnalysisResult,
  ] = useState(null);

  const documentVideoRef = useRef(null);
  const documentCameraStreamRef = useRef(null);
  const documentCameraRequestRef = useRef(0);
  const [documentCameraOpen, setDocumentCameraOpen] = useState(false);
  const [documentCameraStarting, setDocumentCameraStarting] = useState(false);
  const [documentCapturing, setDocumentCapturing] = useState(false);
  const [documentCameraError, setDocumentCameraError] = useState('');
  const [documentPreview, setDocumentPreview] = useState('');

  const videoRef = useRef(null);
  const cameraStreamRef =
    useRef(null);
  const cameraRequestRef = useRef(0);

  const [
    cameraOpen,
    setCameraOpen,
  ] = useState(false);

  const [
    cameraError,
    setCameraError,
  ] = useState('');

  const [
    selfieFile,
    setSelfieFile,
  ] = useState(null);

  const [
    selfiePreview,
    setSelfiePreview,
  ] = useState('');

  const [
    faceModelStatus,
    setFaceModelStatus,
  ] = useState('idle');

  const configReady =
    useMemo(
      () =>
        Boolean(
          SUPABASE_URL &&
          SUPABASE_ANON_KEY
        ),
      []
    );

  useEffect(() => {
    if (
      documentCameraOpen &&
      documentVideoRef.current &&
      documentCameraStreamRef.current
    ) {
      documentVideoRef.current.srcObject = documentCameraStreamRef.current;
      documentVideoRef.current.play().catch(() => {
        setDocumentCameraError('The document camera opened, but the preview could not start.');
      });
    }
  }, [documentCameraOpen]);

  useEffect(() => {
    if (
      cameraOpen &&
      videoRef.current &&
      cameraStreamRef.current
    ) {
      videoRef.current.srcObject =
        cameraStreamRef.current;

      videoRef.current
        .play()
        .catch(() => {
          setCameraError(
            'The camera opened, but the preview could not start.'
          );
        });
    }
  }, [cameraOpen]);

  useEffect(
    () => () => {
      cameraRequestRef.current += 1;
      documentCameraRequestRef.current += 1;
      cameraStreamRef.current
        ?.getTracks()
        .forEach((track) =>
          track.stop()
        );
      documentCameraStreamRef.current
        ?.getTracks()
        .forEach((track) =>
          track.stop()
        );
    },
    []
  );

  useEffect(
    () => () => {
      if (documentPreview) {
        URL.revokeObjectURL(documentPreview);
      }
    },
    [documentPreview]
  );

  useEffect(
    () => () => {
      if (selfiePreview) {
        URL.revokeObjectURL(selfiePreview);
      }
    },
    [selfiePreview]
  );

  /* -----------------------------------------------------
     CONNECT TO SUPABASE
  ----------------------------------------------------- */

  useEffect(() => {
    let mounted = true;
    let client = null;

    async function connect() {
      if (!configReady) {
        setStatus(
          'error'
        );

        setStatusMessage(
          'Supabase environment variables are missing'
        );

        setLedgerError(
          'Add NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to your environment and restart the app.'
        );

        return;
      }

      try {
        client =
          createClient(
            SUPABASE_URL,
            SUPABASE_ANON_KEY
          );

        if (!mounted) {
          return;
        }

        setSupabase(
          client
        );

        const {
          data,
          error,
        } = await client
          .from(
            'ledger_feed'
          )
          .select('*')
          .order(
            'anchored_at',
            {
              ascending:
                false,
            }
          )
          .limit(20);

        if (error) {
          console.error(
            'Supabase ledger_feed error:',
            error
          );

          if (!mounted) {
            return;
          }

          setStatus(
            'error'
          );

          setStatusMessage(
            error.code ===
              'PGRST205'
              ? 'Supabase connected — ledger_feed is missing'
              : 'Supabase connected — database query failed'
          );

          setLedgerError(
            error.message
          );

          return;
        }

        if (!mounted) {
          return;
        }

        setLedger(
          data ?? []
        );

        setStatus(
          'connected'
        );

        setStatusMessage(
          'Connected to Supabase'
        );

        /*
         * Real-time ledger refresh.
         */
        const channel =
          client
            .channel(
              'ledger_anchors_feed'
            )
            .on(
              'postgres_changes',
              {
                event:
                  'INSERT',
                schema:
                  'public',
                table:
                  'ledger_anchors',
              },
              async () => {
                const result =
                  await client
                    .from(
                      'ledger_feed'
                    )
                    .select('*')
                    .order(
                      'anchored_at',
                      {
                        ascending:
                          false,
                      }
                    )
                    .limit(20);

                if (
                  !result.error &&
                  mounted
                ) {
                  setLedger(
                    result.data ??
                      []
                  );
                }
              }
            )
            .subscribe();

        return () => {
          client.removeChannel(
            channel
          );
        };
      } catch (error) {
        console.error(
          'Supabase initialization error:',
          error
        );

        if (!mounted) {
          return;
        }

        setStatus(
          'error'
        );

        setStatusMessage(
          'Supabase initialization failed'
        );

        setLedgerError(
          error.message ||
            'Unknown error'
        );
      }
    }

    const cleanupPromise =
      connect();

    return () => {
      mounted = false;

      Promise.resolve(
        cleanupPromise
      ).then(
        (cleanup) => {
          if (
            typeof cleanup ===
            'function'
          ) {
            cleanup();
          }
        }
      );
    };
  }, [configReady]);

  /* -----------------------------------------------------
     REVEAL ANIMATIONS
  ----------------------------------------------------- */

  useEffect(() => {
    const elements =
      document.querySelectorAll(
        '.reveal'
      );

    if (
      !(
        'IntersectionObserver' in
        window
      )
    ) {
      elements.forEach(
        (element) =>
          element.classList.add(
            'visible'
          )
      );

      return;
    }

    const observer =
      new IntersectionObserver(
        (entries) => {
          entries.forEach(
            (entry) => {
              if (
                entry.isIntersecting
              ) {
                entry.target.classList.add(
                  'visible'
                );

                observer.unobserve(
                  entry.target
                );
              }
            }
          );
        },
        {
          threshold:
            0.08,
        }
      );

    elements.forEach(
      (element) =>
        observer.observe(
          element
        )
    );

    return () =>
      observer.disconnect();
  }, []);

  /* -----------------------------------------------------
     LEDGER REFRESH
  ----------------------------------------------------- */

  async function refreshLedger(
    client = supabase
  ) {
    if (!client) {
      return;
    }

    const {
      data,
      error,
    } = await client
      .from(
        'ledger_feed'
      )
      .select('*')
      .order(
        'anchored_at',
        {
          ascending:
            false,
        }
      )
      .limit(20);

    if (error) {
      setLedgerError(
        error.message
      );

      return;
    }

    setLedgerError('');
    setLedger(
      data ?? []
    );
  }

  /* -----------------------------------------------------
     UPLOAD TO STORAGE
  ----------------------------------------------------- */

  function stopDocumentCamera() {
    documentCameraRequestRef.current += 1;
    documentCameraStreamRef.current
      ?.getTracks()
      .forEach((track) => track.stop());
    documentCameraStreamRef.current = null;
    if (documentVideoRef.current) {
      documentVideoRef.current.pause();
      documentVideoRef.current.srcObject = null;
    }
    setDocumentCameraOpen(false);
    setDocumentCameraStarting(false);
    setDocumentCapturing(false);
  }

  function clearDocumentPreview() {
    setDocumentPreview((current) => {
      if (current) URL.revokeObjectURL(current);
      return '';
    });
  }

  async function startDocumentCamera() {
    setDocumentCameraError('');
    setUploadError('');
    setLedgerError('');
    setAnalysisResult(null);

    if (!navigator.mediaDevices?.getUserMedia) {
      setDocumentCameraError(
        'This browser does not provide camera access. Use a recent Chrome, Edge or Safari browser over HTTPS.'
      );
      return;
    }

    let requestId = null;

    try {
      stopCamera();
      stopDocumentCamera();

      requestId = documentCameraRequestRef.current + 1;
      documentCameraRequestRef.current = requestId;
      setDocumentCameraStarting(true);

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
        },
      });

      if (requestId !== documentCameraRequestRef.current) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }

      documentCameraStreamRef.current = stream;
      setDocumentCameraOpen(true);
    } catch (error) {
      if (documentCameraRequestRef.current === requestId) {
      setDocumentCameraError(
        error?.name === 'NotAllowedError'
          ? 'Camera permission was denied. Allow camera access and try again.'
          : 'Unable to open the document camera. Check that another app is not using it.'
      );
      }
    } finally {
      if (documentCameraRequestRef.current === requestId) {
        setDocumentCameraStarting(false);
      }
    }
  }

  async function captureDocumentPhoto() {
    const video = documentVideoRef.current;

    if (!video || !video.videoWidth || !video.videoHeight) {
      setDocumentCameraError('The camera is still starting. Wait a moment and try again.');
      return;
    }

    const maxDimension = 2200;
    const scale = Math.min(
      1,
      maxDimension / Math.max(video.videoWidth, video.videoHeight)
    );
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
    canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
    const context = canvas.getContext('2d');

    if (!context) {
      setDocumentCameraError('Unable to capture the document frame.');
      return;
    }

    context.drawImage(video, 0, 0, canvas.width, canvas.height);

    try {
      setDocumentCapturing(true);
      const blob = await new Promise((resolve, reject) =>
        canvas.toBlob(
          (value) => value
            ? resolve(value)
            : reject(new Error('Unable to create the document image.')),
          'image/jpeg',
          0.95
        )
      );

      if (blob.size > MAX_FILE_SIZE) {
        throw new Error(
          'The captured image is larger than 10 MB. Move closer, improve lighting and retake it.'
        );
      }

      const file = new File(
        [blob],
        `document-camera-${Date.now()}.jpg`,
        { type: 'image/jpeg' }
      );
      const previewUrl = URL.createObjectURL(file);

      clearDocumentPreview();
      setDocumentPreview(previewUrl);
      setSelectedFile(file);
      setShareCode('');
      setDocumentCameraError('');
      setAnalysisResult(null);
      setUploadError('');
      setLedgerError('');
      clearSelfie();
      stopDocumentCamera();
    } catch (error) {
      setDocumentCameraError(error.message || 'Unable to capture the document image.');
    } finally {
      setDocumentCapturing(false);
      canvas.width = 1;
      canvas.height = 1;
    }
  }

  function stopCamera() {
    cameraRequestRef.current += 1;
    cameraStreamRef.current
      ?.getTracks()
      .forEach((track) =>
        track.stop()
      );

    cameraStreamRef.current =
      null;
    if (videoRef.current) {
      videoRef.current.pause();
      videoRef.current.srcObject = null;
    }
    setCameraOpen(false);
  }

  function clearSelfie() {
    stopCamera();
    setSelfieFile(null);
    setSelfiePreview(
      (current) => {
        if (current) {
          URL.revokeObjectURL(
            current
          );
        }

        return '';
      }
    );
    setCameraError('');
    setFaceModelStatus('idle');
  }

  async function startCamera() {
    setCameraError('');
    setAnalysisResult(null);

    if (
      !navigator.mediaDevices
        ?.getUserMedia
    ) {
      setCameraError(
        'This browser does not provide camera access. Use a recent Chrome or Edge browser over HTTPS.'
      );
      return;
    }

    try {
      stopDocumentCamera();
      stopCamera();

      const requestId = cameraRequestRef.current + 1;
      cameraRequestRef.current = requestId;

      const stream =
        await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: {
            facingMode: 'user',
            width: {
              ideal: 960,
            },
            height: {
              ideal: 960,
            },
          },
        });

      if (requestId !== cameraRequestRef.current) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }

      cameraStreamRef.current =
        stream;
      setCameraOpen(true);
    } catch (error) {
      setCameraError(
        error?.name ===
          'NotAllowedError'
          ? 'Camera permission was denied. Allow camera access and try again.'
          : 'Unable to open the camera. Check that another app is not using it.'
      );
    }
  }

  async function captureSelfie() {
    const video =
      videoRef.current;

    if (
      !video ||
      !video.videoWidth ||
      !video.videoHeight
    ) {
      setCameraError(
        'The camera is still starting. Wait a moment and try again.'
      );
      return;
    }

    const maxDimension = 900;
    const scale = Math.min(
      1,
      maxDimension /
        Math.max(
          video.videoWidth,
          video.videoHeight
        )
    );
    const canvas =
      document.createElement(
        'canvas'
      );

    canvas.width = Math.max(
      1,
      Math.round(
        video.videoWidth * scale
      )
    );
    canvas.height = Math.max(
      1,
      Math.round(
        video.videoHeight * scale
      )
    );

    const context =
      canvas.getContext('2d');

    if (!context) {
      setCameraError(
        'Unable to capture the camera frame.'
      );
      return;
    }

    context.drawImage(
      video,
      0,
      0,
      canvas.width,
      canvas.height
    );

    const blob =
      await new Promise(
        (resolve, reject) =>
          canvas.toBlob(
            (value) =>
              value
                ? resolve(value)
                : reject(
                    new Error(
                      'Unable to create the selfie image.'
                    )
                  ),
            'image/jpeg',
            0.92
          )
      );

    canvas.width = 1;
    canvas.height = 1;

    const file = new File(
      [blob],
      `live-selfie-${Date.now()}.jpg`,
      {
        type: 'image/jpeg',
      }
    );

    const previewUrl =
      URL.createObjectURL(file);

    setSelfiePreview(
      (current) => {
        if (current) {
          URL.revokeObjectURL(
            current
          );
        }

        return previewUrl;
      }
    );
    setSelfieFile(file);
    setCameraError('');
    stopCamera();
  }

  async function uploadSelectedDocument() {
    if (!supabase) {
      setUploadError(
        'Supabase is not connected yet.'
      );

      return false;
    }

    if (!selectedFile) {
      setUploadError(
        'Please select a PDF, JPG or PNG document first.'
      );

      return false;
    }

    setUploadError('');

    const safeName =
      selectedFile.name.replace(
        /[^a-zA-Z0-9._-]/g,
        '_'
      );

    const filePath =
      `uploads/${Date.now()}-${safeName}`;

    const {
      error,
    } =
      await supabase.storage
        .from(
          'document'
        )
        .upload(
          filePath,
          selectedFile,
          {
            cacheControl:
              '3600',
            upsert:
              false,
            contentType:
              selectedFile.type,
          }
        );

    if (error) {
      console.error(
        'Document upload failed:',
        error
      );

      setUploadError(
        `Upload failed: ${error.message}`
      );

      return false;
    }

    return true;
  }

  /* -----------------------------------------------------
     MAIN VERIFICATION
  ----------------------------------------------------- */

  async function runSpecimenCheck() {
    if (!selfieFile) {
      setUploadError(
        'Capture a live selfie before running the verification.'
      );

      return;
    }

    if (!selectedFile) {
      setUploadError(
        'Please select a document first.'
      );

      return;
    }

    setRunning(
      true
    );

    setLedgerError('');
    setUploadError('');
    setAnalysisResult(
      null
    );

    try {
  /*
   * 1. Analyse the actual document.
   */
  let analysis =
    await analyzeDocument(
      selectedFile,
      shareCode
    );

  if (analysis.faceSourceFile) {
    setFaceModelStatus(
      'loading'
    );

    try {
      const faceMatch =
        await compareDocumentFaceToSelfie(
          analysis.faceSourceFile,
          selfieFile
        );

      analysis =
        applyFaceMatchDecision(
          analysis,
          faceMatch
        );

      setFaceModelStatus(
        'completed'
      );
    } catch (faceError) {
      analysis = {
        ...analysis,
        selfieCaptured: true,
        faceMatchStatus:
          'unavailable',
        authenticityStatus:
          'review_required',
        authenticityEvidence:
          faceError.message ||
          'Face comparison could not be completed.',
        decision: 'review',
        riskScore: Math.max(
          65,
          analysis.riskScore
        ),
        reasonCodes:
          Array.from(
            new Set([
              ...(analysis.reasonCodes || []),
              'camera_selfie_captured',
              'face_match_unavailable',
            ])
          ),
        reason:
          faceError.message ||
          'Face comparison could not be completed.',
      };

      setFaceModelStatus(
        'error'
      );
    }
  } else {
    analysis = {
      ...analysis,
      selfieCaptured: true,
      faceMatchStatus:
        'unavailable',
      authenticityStatus:
        'review_required',
      authenticityEvidence:
        'The uploaded file did not provide a portrait image for comparison.',
      decision: 'review',
      riskScore: Math.max(
        65,
        analysis.riskScore
      ),
      reasonCodes:
        Array.from(
          new Set([
            ...(analysis.reasonCodes || []),
            'camera_selfie_captured',
            'document_portrait_unavailable',
          ])
        ),
      reason:
        'The uploaded file did not provide a portrait image for comparison.',
    };

    setFaceModelStatus('error');
  }

  /*
   * Show result immediately.
   */
  setAnalysisResult(
    analysis
  );

      /*
       * 2. Upload file.
       */
      if (!supabase) {
        setLedgerError('Screening completed locally. Connect Supabase to save the document hash and audit event.');
        return;
      }

      const uploaded = await uploadSelectedDocument();
      if (!uploaded) return;

      /*
       * 3. Hash the real file.
       */
      const docHash =
        await sha256File(
          selectedFile
        );

      /*
       * 4. Create document record.
       */
      const {
        data: document,
        error:
          documentError,
      } =
        await supabase
          .from(
            'documents'
          )
          .insert({
            doc_type:
              analysis.docType,
            status:
              analysis.decision,
          })
          .select()
          .single();

      if (documentError) {
        throw new Error(
          `documents insert failed: ${documentError.message}`
        );
      }

      /*
       * 5. Create verification event.
       */
      const {
        data: event,
        error:
          eventError,
      } =
        await supabase
          .from(
            'verification_events'
          )
          .insert({
            document_id:
              document.id,
            risk_score:
              analysis.riskScore,
            reason_codes:
              analysis.reasonCodes,
            decision:
              analysis.decision,
          })
          .select()
          .single();

      if (eventError) {
        throw new Error(
          `verification_events insert failed: ${eventError.message}`
        );
      }

      /*
       * 6. Anchor hash to ledger.
       */
      const blockRef =
        `block#${Math.floor(
          1000 +
            Math.random() *
              9000
        )}`;

      const {
        error:
          anchorError,
      } =
        await supabase
          .from(
            'ledger_anchors'
          )
          .insert({
            verification_event_id:
              event.id,
            doc_hash:
              docHash,
            block_ref:
              blockRef,
          });

      if (anchorError) {
        throw new Error(
          `ledger_anchors insert failed: ${anchorError.message}`
        );
      }

      /*
       * 7. Refresh the newest ledger records.
       */
      await refreshLedger();

      /*
       * Add hash and block to the visible result.
       */
      setAnalysisResult({
        ...analysis,
        docHash,
        blockRef,
      });
    } catch (error) {
      console.error(
        'Document verification failed:',
        error
      );

      setLedgerError(
        error.message ||
          'Document verification failed.'
      );
    } finally {
      setRunning(
        false
      );
    }
  }

  return (
    <>
      {/* ------------------------------------------------
          TOP BAR
      ------------------------------------------------ */}

      <div className="topbar">
        <div className="brand">
          <div className="brand-mark">
            V
          </div>

          <div>
            <div className="brand-name">
              VERUS
            </div>

            <div className="brand-sub">
              SIH 2026 · SOFTWARE · PS ID SIH26188
            </div>
          </div>
        </div>

        <nav>
          <a href="#solution">
            Solution
          </a>

          <a href="#trust-loop">
            Trust Loop
          </a>

          <a href="#technical">
            Technical
          </a>

          <a href="#feasibility">
            Feasibility
          </a>

          <a href="#impact">
            Impact
          </a>

          <a href="#references">
            References
          </a>

          <a href="#ledger">
            Live Ledger
          </a>
        </nav>
      </div>

      {/* ------------------------------------------------
          HERO
      ------------------------------------------------ */}

      <section className="hero">
        <div className="security-weave" />

        <div className="hero-grid">
          <div>
            <div className="eyebrow">
              AI-Based Fake Identity &
              Document Screening System
            </div>

            <div className="ps-badge">
              SMART INDIA HACKATHON ·
              PROBLEM STATEMENT ID:{' '}
              <strong>
                SIH26188
              </strong>
            </div>

            <h1>
              Verify more.
              <br />
              <em>
                Expose less.
              </em>
            </h1>

            <p className="lede">
              A privacy-aware
              verification engine
              that reads identity
              documents, screens
              them for anomalies
              and inconsistency,
              and anchors only
              cryptographic proofs
              to a permissioned
              ledger.
            </p>

            <div className="hero-tags">
              <span className="tag">
                AI / OCR / CV
              </span>

              <span className="tag">
                Anomaly Detection
              </span>

              <span className="tag">
                SHA-256 Hashing
              </span>

              <span className="tag">
                Permissioned Ledger
              </span>
            </div>

            <div className="hero-meta">
              <div>
                <div className="k">
                  Theme
                </div>

                <div className="v">
                  Blockchain &
                  Cybersecurity
                </div>
              </div>

              <div>
                <div className="k">
                  Category
                </div>

                <div className="v">
                  Software
                </div>
              </div>

              <div>
                <div className="k">
                  PS ID
                </div>

                <div className="v">
                  SIH26188
                </div>
              </div>
            </div>
          </div>

          <div className="scan-stage">
            <div className="id-card">
              <div className="scanline" />

              <div className="id-top">
                <div className="id-title">
                  Specimen · National ID
                </div>

                <div className="id-status">
                  SCREENING · REVIEW
                </div>
              </div>

              <div className="id-body">
                <div className="id-photo" />

                <div className="id-fields">
                  <div className="id-field f1">
                    <div className="fill" />
                  </div>

                  <div className="id-field f2">
                    <div className="fill" />
                  </div>

                  <div className="id-field f3">
                    <div className="fill" />
                  </div>

                  <div className="id-field f4">
                    <div className="fill" />
                  </div>
                </div>
              </div>

              <div className="mrz">
                <div>
                  P&lt;IND
                  VERUS&lt;&lt;SPECIMEN
                  &lt;&lt;&lt;&lt;&lt;&lt;&lt;
                </div>

                <div>
                  0000000000IND0001019M31012310
                  &lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;02
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="hero-chain">
          <div className="hash-strip">
            <div className="dot" />

            <span className="hv">
              fingerprint&nbsp;
            </span>

            a13f…09c2 anchored to ledger
          </div>

          <div className="chain-row">
            <div className="chain-block" />
            <div className="chain-link" />
            <div className="chain-block" />
            <div className="chain-link" />
            <div className="chain-block active" />

            <span className="chain-label">
              block #4471
            </span>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------
          SOLUTION
      ------------------------------------------------ */}

      <section id="solution">
        <div className="section-head reveal">
          <div className="eyebrow">
            01 — Idea
          </div>

          <h2>
            What actually gets built.
          </h2>

          <p>
            AI extracts and validates
            document fields, detects
            suspicious characteristics,
            and assigns an explainable
            risk score. Only the
            cryptographic proof and
            verification event —
            never the raw document —
            are written to the ledger.
          </p>
        </div>

        <div className="card-grid reveal">
          {solutionCards.map(
            (card) => (
              <div
                className="card"
                key={card.title}
              >
                <h3>
                  {card.title}
                </h3>

                <ul>
                  {card.items.map(
                    (item) => (
                      <li
                        key={item}
                      >
                        {item}
                      </li>
                    )
                  )}
                </ul>
              </div>
            )
          )}
        </div>
      </section>

      {/* ------------------------------------------------
          TRUST LOOP
      ------------------------------------------------ */}

      <section id="trust-loop">
        <div className="section-head reveal">
          <div className="eyebrow">
            02 — Trust Loop
          </div>

          <h2>
            Five steps, one closed loop.
          </h2>

          <p>
            Every document moves
            through the same loop,
            from intake through
            screening and decision.
          </p>
        </div>

        <div className="loop-wrap reveal">
          {trustSteps.map(
            ([
              num,
              title,
              description,
            ]) => (
              <div
                className="loop-step"
                key={num}
              >
                <div className="num">
                  {num}
                </div>

                <h3>
                  {title}
                </h3>

                <p>
                  {description}
                </p>
              </div>
            )
          )}
        </div>
      </section>

      {/* ------------------------------------------------
          TECHNICAL
      ------------------------------------------------ */}

      <section id="technical">
        <div className="section-head reveal">
          <div className="eyebrow">
            03 — Technical Approach
          </div>

          <h2>
            Built on components that
            already work.
          </h2>

          <p>
            Mature OCR/image processing,
            REST APIs, relational
            storage and a ledger-based
            audit layer form the
            prototype architecture.
          </p>
        </div>

        <div className="reveal">
          <div className="stack-list">
            {stackRows.map(
              ([
                label,
                value,
              ]) => (
                <div
                  className="stack-row"
                  key={label}
                >
                  <div className="label">
                    {label}
                  </div>

                  <div className="val">
                    {value}
                  </div>
                </div>
              )
            )}
          </div>

          <div className="method-strip">
            {methodItems.map(
              ([
                num,
                title,
                description,
              ]) => (
                <div
                  className="method-item"
                  key={num}
                >
                  <div className="step-n">
                    {num}
                  </div>

                  <h4>
                    {title}
                  </h4>

                  <p>
                    {description}
                  </p>
                </div>
              )
            )}
          </div>

          <p className="privacy-note">
            <strong>
              PRIVACY BY DESIGN —
            </strong>{' '}
            raw identity documents
            stay off-chain; the
            ledger stores proofs,
            hashes and audit events.
          </p>
        </div>
      </section>

      {/* ------------------------------------------------
          FEASIBILITY
      ------------------------------------------------ */}

      <section id="feasibility">
        <div className="section-head reveal">
          <div className="eyebrow">
            04 — Feasibility & Viability
          </div>

          <h2>
            What could go wrong, and
            the plan for it.
          </h2>
        </div>

        <div className="card-grid reveal">
          <div className="card">
            <h3>
              Technical feasibility
            </h3>

            <p>
              Built on mature OCR/CV
              tooling, REST APIs,
              relational storage and
              permissioned-ledger
              architecture.
            </p>
          </div>

          <div className="card">
            <h3>
              Operational viability
            </h3>

            <p>
              Screening, verification
              and ledger anchoring are
              modular, with manual review
              available for uncertain
              cases.
            </p>
          </div>

          <div className="card">
            <h3>
              Key challenges / risks
            </h3>

            <ul>
              <li>
                False positives /
                negatives
              </li>

              <li>
                New document layouts
              </li>

              <li>
                Privacy and access
                control
              </li>

              <li>
                Model drift /
                adversarial inputs
              </li>
            </ul>
          </div>

          <div className="card">
            <h3>
              Mitigation strategies
            </h3>

            <ul>
              <li>
                Confidence thresholds
              </li>

              <li>
                Manual review
              </li>

              <li>
                Encryption +
                least privilege
              </li>

              <li>
                Continuous validation
              </li>
            </ul>
          </div>
        </div>

        <div className="risk-panel reveal">
          <div className="rp-head">
            <span>
              INITIAL SCREENING —
              SPECIMEN DOCUMENT
            </span>

            <span>
              SCREENING SCORE
            </span>
          </div>

          <div className="risk-bar">
            <div className="risk-fill" />
          </div>

          <div className="risk-reasons">
            <span>
              OCR confidence
            </span>

            <span>
              Identity indicators
            </span>

            <span>
              Layout / image signals
            </span>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------
          IMPACT
      ------------------------------------------------ */}

      <section id="impact">
        <div className="section-head reveal">
          <div className="eyebrow">
            05 — Impact & Benefits
          </div>

          <h2>
            Who this is built for.
          </h2>
        </div>

        <div className="aud-grid reveal">
          {audiences.map(
            ([
              k,
              title,
              description,
            ]) => (
              <div
                className="aud-card"
                key={k}
              >
                <div className="k">
                  {k}
                </div>

                <h4>
                  {title}
                </h4>

                <p>
                  {description}
                </p>
              </div>
            )
          )}
        </div>

        <div className="impact-row reveal">
          <div className="impact-item">
            <div className="big">
              Faster
            </div>

            <div className="lbl">
              Automated first-pass
              screening
            </div>
          </div>

          <div className="impact-item">
            <div className="big">
              Lower
            </div>

            <div className="lbl">
              Fraud exposure via
              earlier anomaly flagging
            </div>
          </div>

          <div className="impact-item">
            <div className="big">
              Stronger
            </div>

            <div className="lbl">
              Auditability with
              tamper-evident history
            </div>
          </div>

          <div className="impact-item">
            <div className="big">
              Better
            </div>

            <div className="lbl">
              Privacy — proofs
              on-chain, PII off-chain
            </div>
          </div>
        </div>

        <div className="principle reveal">
          “Verify more, expose less.”
        </div>
      </section>

      {/* ------------------------------------------------
          REFERENCES
      ------------------------------------------------ */}

      <section id="references">
        <div className="section-head reveal">
          <div className="eyebrow">
            06 — Research & References
          </div>

          <h2>
            What this design is
            grounded in.
          </h2>
        </div>

        <div className="ref-list reveal">
          {references.map(
            ([
              name,
              description,
            ]) => (
              <div
                className="ref-row"
                key={name}
              >
                <div className="rk">
                  {name}
                </div>

                <div className="rv">
                  <p>
                    {description}
                  </p>
                </div>
              </div>
            )
          )}
        </div>

        <p className="ref-note">
          Standards are referenced
          as design points for the
          prototype architecture;
          final deployment requires
          organization-specific
          compliance and validation.
        </p>
      </section>

      {/* ------------------------------------------------
          LIVE LEDGER / VERIFICATION
      ------------------------------------------------ */}

      <section id="ledger">
        <div className="section-head reveal">
          <div className="eyebrow">
            Live
          </div>

          <h2>
            Verification & Ledger feed.
          </h2>

          <p>
            Upload a document or photograph a physical card to run
            the screening pipeline.
            The latest verification
            events appear below.
          </p>
        </div>

        <div className="reveal">
          {/* UPLOAD PANEL */}

          <div
            className="upload-panel"
            style={{
              marginBottom:
                '24px',
            }}
          >
            <div className="upload-title">
              Provide a document for verification
            </div>

            <p className="upload-description">
              Upload a digital file, or use the camera to photograph a
              physical document or card. Maximum file size: 10 MB.
            </p>

            <div className="document-capture-panel">
              <div className="document-capture-heading">
                Physical document or card
              </div>
              <p className="upload-description">
                Place the full document inside the frame with its title,
                printed portrait and text visible in even lighting. On phones,
                the rear camera is preferred.
              </p>
              <p className="capture-privacy-note">
                The live preview stays on this device. After capture, the
                photo follows the same screening and optional Supabase upload
                flow as a selected image file.
              </p>

              {documentCameraOpen && (
                <div className="document-camera-stage">
                  <video
                    ref={documentVideoRef}
                    autoPlay
                    muted
                    playsInline
                    className="document-camera-video"
                  />
                  <div className="document-camera-guide" aria-hidden="true" />
                </div>
              )}

              {documentPreview && !documentCameraOpen && (
                <img
                  src={documentPreview}
                  alt="Captured document"
                  className="document-preview"
                />
              )}

              <div className="document-camera-actions">
                {!documentCameraOpen && (
                  <button
                    type="button"
                    className="run-btn"
                    onClick={startDocumentCamera}
                    disabled={documentCameraStarting || running}
                  >
                    {documentCameraStarting
                      ? 'Opening camera…'
                      : documentPreview
                        ? 'Retake document photo'
                        : 'Photograph document'}
                  </button>
                )}

                {documentCameraStarting && (
                  <button
                    type="button"
                    className="run-btn"
                    onClick={stopDocumentCamera}
                  >
                    Cancel
                  </button>
                )}

                {documentCameraOpen && (
                  <>
                    <button
                      type="button"
                    className="run-btn"
                    onClick={captureDocumentPhoto}
                    disabled={documentCapturing || running}
                    >
                      {documentCapturing ? 'Capturing…' : 'Capture document'}
                    </button>
                    <button
                      type="button"
                      className="run-btn"
                      onClick={stopDocumentCamera}
                      disabled={documentCapturing}
                    >
                      Cancel camera
                    </button>
                  </>
                )}
              </div>

              {documentCameraError && (
                <div className="ledger-error">
                  <strong>Document camera:</strong>{' '}
                  {documentCameraError}
                </div>
              )}
            </div>

            <div className="recognition-note">
              <strong>Document recognition:</strong>{' '}
              Printed titles and OCR patterns can identify Aadhaar, passport,
              driving licence, visa, permits, national/voter/PAN/ration IDs,
              and common mess, student, employee, access, library, membership
              and health cards. Unfamiliar cards may be labelled from a
              readable title and kept for review.
            </div>

            <div className="document-source-divider">
              <span>or upload a digital document</span>
            </div>

<input
  type="password"
  placeholder="Offline e-KYC Share Code (ZIP only)"
  value={shareCode}
  onChange={(event) =>
    setShareCode(
      event.target.value
    )
  }
  style={{
    width: '100%',
    marginTop: '12px',
    padding: '12px',
    borderRadius: '8px',
    border:
      '1px solid rgba(255,255,255,0.15)',
    background:
      'rgba(255,255,255,0.04)',
    color: 'inherit',
    outline: 'none',
  }}
/>
            
              <input
  type="file"
  accept=".pdf,.jpg,.jpeg,.png,.zip,application/pdf,image/jpeg,image/png,application/zip"
  onChange={(event) => {
    const file =
      event.target.files?.[0];

    setUploadError('');
    setLedgerError('');
    setAnalysisResult(null);
    setSelectedFile(null);
    stopDocumentCamera();
    clearDocumentPreview();
    clearSelfie();

    if (!file) {
      return;
    }

    if (
      !ALLOWED_FILE_TYPES.includes(
        file.type
      ) &&
      !file.name
        .toLowerCase()
        .endsWith('.pdf') &&
      !file.name
        .toLowerCase()
        .endsWith('.zip')
    ) {
      setUploadError(
        'Unsupported file type. Please upload a PDF, JPG, PNG or ZIP file.'
      );

      event.target.value = '';

      return;
    }

    if (
      file.size >
      MAX_FILE_SIZE
    ) {
      setUploadError(
        'File is too large. Maximum allowed size is 10 MB.'
      );

      event.target.value = '';

      return;
    }

    setSelectedFile(file);
  }}
/>
            

            {selectedFile && (
              <div
                className="selected-file"
                style={{
                  marginTop:
                    '12px',
                }}
              >
                Selected:{' '}

                <strong>
                  {
                    selectedFile.name
                  }
                </strong>
              </div>
            )}

            {selectedFile && (
              <div
                style={{
                  marginTop: '18px',
                  padding: '16px',
                  border:
                    '1px solid rgba(64, 220, 210, 0.25)',
                  borderRadius: '10px',
                  background:
                    'rgba(64, 220, 210, 0.04)',
                }}
              >
                <div className="upload-title">
                  Camera selfie comparison
                </div>

                <p className="upload-description">
                  Capture one clear,
                  front-facing photo. It is
                  processed locally in this
                  browser and is not uploaded
                  to Supabase. This compares faces only; it does not perform
                  liveness or anti-spoof detection.
                </p>

                {cameraOpen && (
                  <video
                    ref={videoRef}
                    autoPlay
                    muted
                    playsInline
                    style={{
                      display: 'block',
                      width: '100%',
                      maxWidth: '440px',
                      aspectRatio: '4 / 3',
                      marginTop: '14px',
                      objectFit: 'cover',
                      borderRadius: '10px',
                      transform:
                        'scaleX(-1)',
                      background: '#071019',
                    }}
                  />
                )}

                {selfiePreview && (
                  <img
                    src={selfiePreview}
                    alt="Captured camera selfie"
                    style={{
                      display: 'block',
                      width: '100%',
                      maxWidth: '320px',
                      aspectRatio: '4 / 3',
                      marginTop: '14px',
                      objectFit: 'cover',
                      borderRadius: '10px',
                      border:
                        '1px solid rgba(255,255,255,0.14)',
                    }}
                  />
                )}

                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: '10px',
                    marginTop: '14px',
                  }}
                >
                  {!cameraOpen &&
                    !selfieFile && (
                      <button
                        type="button"
                        className="run-btn"
                        onClick={startCamera}
                      >
                        Open camera
                      </button>
                    )}

                  {cameraOpen && (
                    <>
                      <button
                        type="button"
                        className="run-btn"
                        onClick={captureSelfie}
                      >
                        Capture selfie
                      </button>

                      <button
                        type="button"
                        className="run-btn"
                        onClick={stopCamera}
                      >
                        Cancel camera
                      </button>
                    </>
                  )}

                  {selfieFile && (
                    <button
                      type="button"
                      className="run-btn"
                      onClick={clearSelfie}
                    >
                      Retake selfie
                    </button>
                  )}
                </div>

                {selfieFile && (
                  <p
                    style={{
                      marginTop: '10px',
                      color: '#62e3d9',
                      fontSize: '12px',
                    }}
                  >
                    Camera selfie ready for
                    local face comparison.
                  </p>
                )}

                {cameraError && (
                  <div className="ledger-error">
                    <strong>
                      Camera:
                    </strong>{' '}
                    {cameraError}
                  </div>
                )}
              </div>
            )}

            {uploadError && (
              <div className="ledger-error">
                <strong>
                  Upload:
                </strong>{' '}
                {uploadError}
              </div>
            )}

            {/* ANALYSIS RESULT */}

            {analysisResult && (
              <div
                style={{
                  marginTop:
                    '20px',
                  padding:
                    '16px',
                  border:
                    '1px solid rgba(255,255,255,0.12)',
                  borderRadius:
                    '10px',
                }}
              >
                <div
                  className={`document-identification ${
                    analysisResult.docType === 'unknown'
                      ? 'review'
                      : 'recognized'
                  }`}
                >
                  <strong>
                    {analysisResult.docType === 'unknown'
                      ? 'Document type needs review'
                      : `Detected document: ${analysisResult.documentLabel || getDocumentTypeLabel(analysisResult.docType)}.`}
                  </strong>
                  <span>
                    {analysisResult.docType === 'unknown'
                      ? 'The face comparison can still run, but OCR could not identify a reliable card title or supported document pattern.'
                      : 'This type is inferred from readable text and document patterns; it is not proof that the issuer or document is genuine.'}
                  </span>
                </div>

                <div
                  style={{
                    display:
                      'grid',
                    gridTemplateColumns:
                      'repeat(auto-fit, minmax(150px, 1fr))',
                    gap:
                      '14px',
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Document type
                    </div>

                    <strong
                      style={{
                        textTransform:
                          'uppercase',
                      }}
                    >
                      {escapeText(
                        analysisResult.documentLabel ||
                          getDocumentTypeLabel(analysisResult.docType)
                      )}
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Detection confidence
                    </div>

                    <strong>
                      {
                        analysisResult.confidence
                      }
                      %
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Prototype risk
                    </div>

                    <strong>
                      {
                        analysisResult.riskScore
                      }
                      /100
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Overall screening
                    </div>

                    <strong
                      style={{
                        textTransform:
                          'uppercase',
                      }}
                    >
                      {
                        analysisResult.decision
                      }
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      OCR confidence
                    </div>

                    <strong>
                      {Math.round(
                        analysisResult.ocrConfidence ??
                          0
                      )}
                      %
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize:
                          '10px',
                        opacity:
                          0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Rotation used
                    </div>

                    <strong>
                      {
                        analysisResult.rotationUsed ??
                        0
                      }
                      °
                    </strong>
                  </div>
                  <div>
                    <div
                      style={{
                        fontSize: '10px',
                        opacity: 0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Camera selfie
                    </div>

                    <strong>
                      {analysisResult.selfieCaptured
                        ? 'Captured'
                        : 'Not captured'}
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: '10px',
                        opacity: 0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Face match
                    </div>

                    <strong>
                      {analysisResult.faceMatchStatus ===
                      'matched'
                        ? 'Matched'
                        : analysisResult.faceMatchStatus ===
                            'not_matched'
                          ? 'Not matched'
                          : 'Needs review'}
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: '10px',
                        opacity: 0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Face distance
                    </div>

                    <strong>
                      {Number.isFinite(
                        analysisResult.faceDistance
                      )
                        ? `${analysisResult.faceDistance.toFixed(3)} (match ≤ 0.600)`
                        : 'Unavailable'}
                    </strong>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: '10px',
                        opacity: 0.65,
                        textTransform:
                          'uppercase',
                      }}
                    >
                      Face evidence
                    </div>

                    <strong>
                      {analysisResult.faceMatchStatus ===
                      'matched'
                        ? 'Portrait + selfie match'
                        : analysisResult.faceMatchStatus ===
                            'not_matched'
                          ? 'Face mismatch'
                          : 'Review required'}
                    </strong>
                  </div>
                  {analysisResult.pdfPage && (
                    <div>
                      <div
                        style={{
                          fontSize:
                            '10px',
                          opacity:
                            0.65,
                          textTransform:
                            'uppercase',
                        }}
                      >
                        PDF page
                      </div>

                      <strong>
                        {
                          analysisResult.pdfPage
                        }
                      </strong>
                    </div>
                  )}
                </div>

                {analysisResult.authenticityEvidence && (
                  <p
                    style={{
                      marginTop: '16px',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      background:
                        'rgba(64, 220, 210, 0.06)',
                      color: '#bff9f4',
                      fontSize: '12px',
                    }}
                  >
                    <strong>
                      Face comparison evidence:
                    </strong>{' '}
                    {analysisResult.authenticityEvidence}
                  </p>
                )}

                {Object.keys(analysisResult.extractedFields || {}).length > 0 && (
                  <div className="result-module">
                    <div className="result-module-title">OCR extracted fields</div>
                    <div className="field-grid">
                      {Object.entries(analysisResult.extractedFields).map(([key, value]) => (
                        <div className="field-card" key={key}>
                          <span>{key.replace(/([A-Z])/g, ' $1')}</span>
                          <strong>{escapeText(value)}</strong>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="module-grid">
                  <div className="result-module">
                    <div className="result-module-title">Document validation</div>
                    {(analysisResult.validationChecks || []).map((check) => (
                      <div className={`check-row ${check.status}`} key={check.label}>
                        <span>{check.status === 'pass' ? '✓' : '!'}</span>
                        <div><strong>{check.label}</strong><small>{check.detail}</small></div>
                      </div>
                    ))}
                  </div>
                  <div className="result-module">
                    <div className="result-module-title">Image & OCR quality heuristics</div>
                    {(analysisResult.tamperChecks || []).map((check) => (
                      <div className={`check-row ${check.status}`} key={check.label}>
                        <span>{check.status === 'pass' ? '✓' : '!'}</span>
                        <div><strong>{check.label}</strong><small>{check.detail}</small></div>
                      </div>
                    ))}
                  </div>
                </div>

                <div
                  style={{
                    marginTop:
                      '18px',
                  }}
                >
                  <div
                    style={{
                      fontSize:
                        '10px',
                      opacity:
                        0.65,
                      textTransform:
                        'uppercase',
                      marginBottom:
                        '8px',
                    }}
                  >
                    Screening reasons
                  </div>

                  {(analysisResult.reasonCodes ||
                    []
                  ).map(
                    (reason) => (
                      <span
                        key={
                          reason
                        }
                        style={{
                          display:
                            'inline-block',
                          marginRight:
                            '8px',
                          marginBottom:
                            '8px',
                          padding:
                            '5px 8px',
                          border:
                            '1px solid rgba(255,255,255,0.15)',
                          borderRadius:
                            '999px',
                          fontSize:
                            '10px',
                        }}
                      >
                        {
                          reason
                        }
                      </span>
                    )
                  )}
                </div>

                {analysisResult.reason && (
                  <p
                    style={{
                      marginTop:
                        '12px',
                      fontSize:
                        '13px',
                      opacity:
                        0.8,
                    }}
                  >
                    {
                      analysisResult.reason
                    }
                  </p>
                )}

                <p
                  style={{
                    marginTop:
                      '10px',
                    fontSize:
                      '12px',
                    opacity:
                      0.65,
                  }}
                >
                  Hackathon prototype only: OCR, visual heuristics and the
                  on-device face comparison do not query an issuing authority
                  and are not official document authentication. OCR-based type
                  labels may be wrong on unclear images. The selfie check has
                  no liveness or anti-spoof test. A captured selfie is kept in
                  browser memory and is not uploaded to Supabase.
                </p>
              </div>
            )}
          </div>

          {/* LEDGER HEADER */}

          <div className="ledger-head">
            <div
              className={`ledger-status ${
                status ===
                'connected'
                  ? 'live'
                  : 'off'
              }`}
            >
              <span className="dotstate" />

              <span>
                {
                  statusMessage
                }
              </span>
            </div>

            <button
              className="run-btn"
              disabled={
                running ||
                !selectedFile ||
                !selfieFile
              }
              onClick={
                runSpecimenCheck
              }
            >
              {running
                ? faceModelStatus ===
                  'loading'
                  ? 'Comparing faces…'
                  : 'Analyzing…'
                : 'Run specimen check'}
            </button>
          </div>

          {ledgerError && (
            <div className="ledger-error">
              <strong>
                Supabase:
              </strong>{' '}
              {ledgerError}
            </div>
          )}

          {/* ------------------------------------------------
              SCROLLABLE LEDGER
          ------------------------------------------------ */}

          {ledger.length > 0 ? (
            <div
              className="table-wrap"
              style={{
                maxHeight:
                  '440px',
                overflowY:
                  'auto',
                overflowX:
                  'auto',
                borderRadius:
                  '10px',
                position:
                  'relative',
              }}
            >
              <table
                className="ledger-table"
              >
                <thead
                  style={{
                    position:
                      'sticky',
                    top: 0,
                    zIndex: 5,
                  }}
                >
                  <tr>
                    <th>
                      Anchored
                    </th>

                    <th>
                      Doc type
                    </th>

                    <th>
                      Risk
                    </th>

                    <th>
                      Decision
                    </th>

                    <th>
                      Hash
                    </th>

                    <th>
                      Block
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {ledger.map(
                    (row) => {
                      const hash =
                        escapeText(
                          row.doc_hash
                        );

                      const decision =
                        escapeText(
                          row.decision
                        ).toLowerCase();

                      const date =
                        row.anchored_at
                          ? new Date(
                              row.anchored_at
                            ).toLocaleString()
                          : '—';

                      return (
                        <tr
                          key={
                            row.id
                          }
                        >
                          <td>
                            {
                              date
                            }
                          </td>

                          <td>
                            {escapeText(
                              row.doc_type
                            ) ||
                              '—'}
                          </td>

                          <td>
                            {
                              row.risk_score ??
                              '—'
                            }
                          </td>

                          <td>
                            <span
                              className={`decision-pill ${decision}`}
                            >
                              {
                                decision ||
                                '—'
                              }
                            </span>
                          </td>

                          <td className="hashv">
                            {hash
                              ? `${hash.slice(
                                  0,
                                  10
                                )}…${hash.slice(
                                  -6
                                )}`
                              : '—'}
                          </td>

                          <td className="hashv">
                            {
                              escapeText(
                                row.block_ref
                              ) ||
                              '—'
                            }
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="ledger-empty">
              {status ===
              'connected'
                ? 'No ledger entries yet. Run a specimen check.'
                : 'Waiting for Supabase…'}
            </div>
          )}
        </div>
      </section>

      {/* ------------------------------------------------
          FOOTER
      ------------------------------------------------ */}

      <footer>
        <div>
          VERUS — AI-Based Fake Identity
          &amp; Document Screening System
        </div>

        <div>
          SIH 2026 · Blockchain &amp;
          Cybersecurity · Software · PS
          ID SIH26188
        </div>
      </footer>
    </>
  );
}
