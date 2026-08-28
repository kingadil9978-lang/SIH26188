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

const UIDAI_CERTIFICATE_PATH = '/uidai_offline_publickey_2026.cer';

function decimalQrPayloadToBytes(value) {
  const payload = String(value || '').trim();
  if (!/^\d+$/.test(payload)) {
    throw new Error('The QR payload is not a UIDAI Secure QR numeric payload.');
  }
  let hex = BigInt(payload).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function inflateSecureQrPayload(bytes) {
  for (const format of ['deflate', 'deflate-raw']) {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(
        new DecompressionStream(format)
      );
      return new Uint8Array(await new Response(stream).arrayBuffer());
    } catch {
      // Try the other UIDAI payload compression variant.
    }
  }
  throw new Error('Unable to decompress the Secure QR payload.');
}

async function verifyAadhaarSecureQr(qrData) {
  if (!qrData) return { status: 'unavailable', verified: false };
  if (!/^\d+$/.test(String(qrData).trim())) {
    return {
      status: 'unsupported',
      verified: false,
      reason: 'QR detected, but it is not a UIDAI Secure QR payload.',
    };
  }

  try {
    const signedPayload = await inflateSecureQrPayload(
      decimalQrPayloadToBytes(qrData)
    );
    const signatureLength = 256;
    if (signedPayload.length <= signatureLength) {
      throw new Error('Secure QR payload is too short to contain a UIDAI signature.');
    }

    const response = await fetch(UIDAI_CERTIFICATE_PATH, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Unable to load UIDAI certificate (${response.status}).`);
    }
    const certificate = new X509Certificate(await response.arrayBuffer());
    const content = signedPayload.slice(0, -signatureLength);
    const signature = signedPayload.slice(-signatureLength);
    const verified = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      certificate.publicKey,
      signature,
      content
    );
    return {
      status: verified ? 'verified' : 'invalid',
      verified,
      reason: verified
        ? 'UIDAI Secure QR digital signature verified.'
        : 'The UIDAI Secure QR digital signature did not verify.',
    };
  } catch (error) {
    console.error('UIDAI Secure QR verification failed:', error);
    return {
      status: 'invalid',
      verified: false,
      reason: error?.message || 'Unable to verify the UIDAI Secure QR signature.',
    };
  }
}
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

      canvas.width = swap
        ? image.height
        : image.width;

      canvas.height = swap
        ? image.width
        : image.height;

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
        -image.width / 2,
        -image.height / 2
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
      const maxDimension = 3000;

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
        1.5,
        2,
        2.5,
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
          const scanWidth =
            Math.max(
              1,
              Math.round(
                cropWidth *
                  factor
              )
            );

          const scanHeight =
            Math.max(
              1,
              Math.round(
                cropHeight *
                  factor
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
  console.log(
    'QR detected:',
    result
  );

  console.log(
    'QR payload:',
    result.data
  );

  console.log(
    'QR payload length:',
    result.data.length
  );

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
    console.log(
      'ZXing QR detected:',
      zxingPayload
    );

    console.log(
      'ZXing QR payload length:',
      zxingPayload.length
    );

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
try {
  const zxingResult =
     zxingReader.decodeFromCanvas(
      scanCanvas
    );

  if (
    zxingResult &&
    zxingResult.getText &&
    zxingResult.getText().trim().length > 0
  ) {
    const payload =
      zxingResult.getText().trim();

    console.log(
      'ZXing QR detected:',
      payload
    );

    resolve({
      detected: true,
      data: payload,
    });

    return;
  }
} catch (zxingError) {
  // ZXing throws when no QR is found.
  // Continue trying the next crop.
}
          }
        }
      }

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
  qrResult,
  qrVerification,
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
    /\b\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/.test(
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
  const qrDetected = Boolean(
  qrResult?.detected
);

const qrDataLength =
  qrResult?.data?.length || 0;

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
    isIdentityDocument &&
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
    isIdentityDocument &&
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

if (qrDetected) {
  reasonCodes.push(
    'qr_code_detected'
  );
} else {
  reasonCodes.push(
    'qr_code_not_detected'
  );
}

if (
  qrDetected &&
  qrDataLength > 0
) {
  reasonCodes.push(
    'qr_payload_detected'
  );
}
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
  qrVerification?.status === 'verified'
    ? 'verified'
    : qrVerification?.status === 'invalid'
      ? 'invalid'
      : isIdentityDocument
        ? 'not_verified'
        : 'not_available';

if (qrVerification?.status === 'verified') {
  reasonCodes.push('uidai_qr_signature_verified');
  riskScore = 0;
  decision = 'approved';
} else if (qrVerification?.status === 'invalid') {
  reasonCodes.push('uidai_qr_signature_invalid');
  riskScore = 100;
  decision = 'rejected';
} else if (qrDetected) {
  reasonCodes.push('uidai_qr_signature_not_verified');
}
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

    if (authenticityStatus === 'not_verified') {
      reasonCodes.push('issuer_authenticity_not_verified');
    }
  }

  return {
  isIdentityDocument,
  authenticityStatus,

  qrDetected,
  qrDataLength,
  qrVerificationStatus: qrVerification?.status || 'unavailable',

  docType,

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

    reason:
      qrVerification?.reason || (!isIdentityDocument
        ? 'No sufficient identity-document indicators detected.'
        : decision ===
            'approved'
          ? 'Identity document detected with low initial screening risk.'
          : 'Identity document detected, but additional review is recommended.'),
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

const qrResult =
  await detectQrCode(image);
const qrVerification =
  await verifyAadhaarSecureQr(qrResult?.data);
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
    qrResult,
    qrVerification,
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
     * Higher scale gives OCR
     * more pixels to work with.
     */
    const viewport =
      page.getViewport({
        /* Preserve small QR modules before the decoder sees the page. */
        scale: 5,
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

/* -------------------------------------------------------
   PAGE COMPONENT
------------------------------------------------------- */

export default function Home() {
  const [
    supabase,
    setSupabase,
  ] = useState(null);
  const videoRef = useRef(null);
const canvasRef = useRef(null);
const cameraStreamRef = useRef(null);

const [cameraOpen, setCameraOpen] = useState(false);
const [cameraReady, setCameraReady] = useState(false);
const [cameraError, setCameraError] = useState('');

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

  const configReady =
    useMemo(
      () =>
        Boolean(
          SUPABASE_URL &&
          SUPABASE_ANON_KEY
        ),
      []
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
    if (!supabase) {
      setLedgerError(
        'Supabase is not connected yet.'
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
  const analysis =
    await analyzeDocument(
      selectedFile,
      shareCode
    );

  /*
   * Show result immediately.
   */
  setAnalysisResult(
    analysis
  );

      /*
       * 2. Upload file.
       */
      const uploaded =
        await uploadSelectedDocument();

      if (!uploaded) {
        return;
      }

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
            Upload a document to run
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
              Upload a document for
              verification
            </div>

            <p className="upload-description">
              Accepted formats:
              PDF, JPG and PNG.
              Maximum size: 10 MB.
            </p>
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
                        analysisResult.docType
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
                      Risk
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
                      Decision
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
      textTransform: 'uppercase',
    }}
  >
    QR status
  </div>

  <strong>
    {analysisResult.qrDetected
      ? 'Detected'
      : 'Not detected'}
  </strong>
</div>

<div>
  <div
    style={{
      fontSize: '10px',
      opacity: 0.65,
      textTransform: 'uppercase',
    }}
  >
    QR verification
  </div>

  <strong>
    {analysisResult.qrVerificationStatus === 'verified'
      ? 'UIDAI signature verified'
      : analysisResult.qrVerificationStatus === 'invalid'
        ? 'Invalid signature'
        : analysisResult.qrDetected
          ? 'Not verified'
          : 'Unavailable'}
  </strong>
</div>
<div>
  <div
    style={{
      fontSize: '10px',
      opacity: 0.65,
      textTransform: 'uppercase',
    }}
  >
    Authenticity evidence
  </div>

  <strong>
    {analysisResult.authenticityStatus === 'verified'
      ? 'UIDAI verified'
      : analysisResult.authenticityStatus === 'invalid'
        ? 'Invalid'
        : analysisResult.authenticityStatus === 'not_verified'
          ? 'Not verified'
          : 'Not available'}
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
                  OCR and visual checks are screening only. Aadhaar
                  authenticity is confirmed only when the UIDAI digital
                  signature reports verified.
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
                status !==
                  'connected' ||
                running ||
                !selectedFile
              }
              onClick={
                runSpecimenCheck
              }
            >
              {running
                ? 'Analyzing…'
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
