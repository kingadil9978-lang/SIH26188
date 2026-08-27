'use client';

import { useEffect, useMemo, useState } from 'react';
import { createClient } from '@supabase/supabase-js';
import Tesseract from 'tesseract.js';
import { createWorker } from 'tesseract.js';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

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
  ['01', 'Upload', 'ID or document submitted through an encrypted intake channel.'],
  ['02', 'AI Screen', 'OCR and computer vision extract fields and surface layout tells.'],
  ['03', 'Verify', 'Rules and a risk model check consistency across every field.'],
  ['04', 'Anchor', 'A hash of the verification event is timestamped to the ledger.'],
  ['05', 'Decide', 'Approve, send to manual review, or reject — with a reason.'],
];

const stackRows = [
  ['AI / ML', 'Python, OpenCV, OCR, anomaly-detection model'],
  ['Backend', 'FastAPI / Node.js, REST APIs'],
  ['Blockchain', 'Hyperledger Fabric, smart contracts'],
  ['Security', 'SHA-256, digital signatures, role-based access control'],
  ['Data', 'PostgreSQL, encrypted object storage'],
];

const methodItems = [
  ['1', 'Document intake', 'Encrypted upload'],
  ['2', 'AI extraction', 'OCR + layout analysis'],
  ['3', 'Forgery detection', 'Visual + metadata checks'],
  ['4', 'Identity consistency', 'Cross-field / source checks'],
  ['5', 'Risk engine', 'Score + reason codes'],
  ['6', 'Blockchain anchor', 'Hash + timestamp + issuer'],
  ['7', 'Decision', 'Approve / review / reject'],
];

const audiences = [
  ['GOV / INSTITUTIONS', 'Government & institutions', 'Secure document intake and audit trails.'],
  ['BANKING', 'Banking & fintech', 'KYC support and suspicious-case triage.'],
  ['EDUCATION', 'Education & HR', 'Credential verification at scale.'],
  ['PROVIDERS', 'Service providers', 'Reusable trust proofs across platforms.'],
];

const references = [
  ['W3C', 'Verifiable Credentials Data Model v2.0 — machine-verifiable, cryptographically secure, privacy-aware digital credentials.'],
  ['NIST', 'AI Risk Management Framework — guidance for trustworthy, secure, privacy-aware and accountable AI systems.'],
  ['Hyperledger', 'Fabric documentation — a permissioned distributed ledger suited to known, governed participants.'],
  ['SIH 2026', 'Provided idea template — structure, slide limits and submission pointers this concept follows.'],
];
const ALLOWED_FILE_TYPES = [
  'application/pdf',
  'image/jpeg',
  'image/png',
];

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const reasonPool = [
  'font_kerning_mismatch',
  'mrz_checksum_irregular',
  'issuer_signature_verified',
  'field_cross_check_ok',
];

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);

  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function escapeText(value) {
  return String(value ?? '');
}

export default function Home() {
  const [supabase, setSupabase] = useState(null);
  const [status, setStatus] = useState('connecting');
  const [statusMessage, setStatusMessage] = useState('Connecting to Supabase…');
  const [ledger, setLedger] = useState([]);
  const [running, setRunning] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
const [uploadError, setUploadError] = useState('');
  const [ledgerError, setLedgerError] = useState('');

  const configReady = useMemo(
    () => Boolean(SUPABASE_URL && SUPABASE_ANON_KEY),
    []
  );

  useEffect(() => {
    let mounted = true;
    let client = null;

    async function connect() {
      if (!configReady) {
        setStatus('error');
        setStatusMessage('Supabase environment variables are missing');

        setLedgerError(
          'Add NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to .env.local, then restart npm run dev.'
        );

        return;
      }

      try {
        client = createClient(
          SUPABASE_URL,
          SUPABASE_ANON_KEY
        );

        if (!mounted) return;

        setSupabase(client);

        const { data, error } = await client
          .from('ledger_feed')
          .select('*')
          .order('anchored_at', { ascending: false })
          .limit(8);

        if (error) {
          console.error(
            'Supabase ledger_feed error:',
            error
          );

          if (!mounted) return;

          setStatus('error');

          setStatusMessage(
            error.code === 'PGRST205'
              ? 'Supabase connected — ledger_feed is missing'
              : 'Supabase connected — database query failed'
          );

          setLedgerError(error.message);

          return;
        }

        if (!mounted) return;

        setLedger(data ?? []);

        setStatus('connected');
        setStatusMessage('Connected to Supabase');

        const channel = client
          .channel('ledger_anchors_feed')
          .on(
            'postgres_changes',
            {
              event: 'INSERT',
              schema: 'public',
              table: 'ledger_anchors',
            },
            async () => {
              const result = await client
                .from('ledger_feed')
                .select('*')
                .order('anchored_at', {
                  ascending: false,
                })
                .limit(8);

              if (!result.error && mounted) {
                setLedger(result.data ?? []);
              }
            }
          )
          .subscribe();

        return () => {
          client.removeChannel(channel);
        };
      } catch (error) {
        console.error(
          'Supabase initialization error:',
          error
        );

        if (!mounted) return;

        setStatus('error');

        setStatusMessage(
          'Supabase initialization failed'
        );

        setLedgerError(
          error.message || 'Unknown error'
        );
      }
    }

    const cleanupPromise = connect();

    return () => {
      mounted = false;

      Promise.resolve(cleanupPromise).then(
        (cleanup) => {
          if (typeof cleanup === 'function') {
            cleanup();
          }
        }
      );
    };
  }, [configReady]);

  useEffect(() => {
    const elements =
      document.querySelectorAll('.reveal');

    if (!('IntersectionObserver' in window)) {
      elements.forEach((element) =>
        element.classList.add('visible')
      );

      return;
    }

    const observer =
      new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add(
                'visible'
              );

              observer.unobserve(
                entry.target
              );
            }
          });
        },
        { threshold: 0.08 }
      );

    elements.forEach((element) =>
      observer.observe(element)
    );

    return () => observer.disconnect();
  }, []);

  async function refreshLedger(
    client = supabase
  ) {
    if (!client) return;

    const { data, error } = await client
      .from('ledger_feed')
      .select('*')
      .order('anchored_at', {
        ascending: false,
      })
      .limit(8);

    if (error) {
      setLedgerError(error.message);
      return;
    }

    setLedgerError('');
    setLedger(data ?? []);
  }
  async function analyzeDocument(file) {
  if (!file) {
    return {
      isIdentityDocument: false,
      docType: 'unknown',
      confidence: 0,
      reason: 'No document selected',
    };
  }

  if (file.type === 'application/pdf') {
    return {
      isIdentityDocument: false,
      docType: 'pdf_document',
      confidence: 0,
      reason: 'PDF analysis will be added later',
    };
  }

  try {
    const worker = await Tesseract.createWorker('eng');

    const result = await worker.recognize(file);

    const text = (result.data.text || '').toUpperCase();

    await worker.terminate();

    console.log('OCR text:', text);

    const keywords = [
      'IDENTITY',
      'IDENTIFICATION',
      'AADHAAR',
      'AADHAR',
      'PASSPORT',
      'DRIVING',
      'LICENSE',
      'LICENCE',
      'NATIONAL ID',
      'DATE OF BIRTH',
      'DOB',
      'UIDAI',
    ];

    const matches = keywords.filter((word) =>
      text.includes(word)
    );

    const hasAadhaarNumber =
      /\b\d{4}\s?\d{4}\s?\d{4}\b/.test(text);

    const hasDateOfBirth =
      /\b\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/.test(text);

    let confidence = 0;

    confidence += Math.min(matches.length * 15, 60);

    if (hasAadhaarNumber) {
      confidence += 25;
    }

    if (hasDateOfBirth) {
      confidence += 15;
    }

    confidence = Math.min(confidence, 100);

    const isIdentityDocument = confidence >= 35;

    let docType = 'unknown';

    if (isIdentityDocument) {
      if (
        text.includes('AADHAAR') ||
        text.includes('AADHAR') ||
        text.includes('UIDAI') ||
        hasAadhaarNumber
      ) {
        docType = 'aadhaar';
      } else if (text.includes('PASSPORT')) {
        docType = 'passport';
      } else if (
        text.includes('DRIVING') ||
        text.includes('LICENSE') ||
        text.includes('LICENCE')
      ) {
        docType = 'driving_license';
      } else {
        docType = 'national_id';
      }
    }

    return {
      isIdentityDocument,
      docType,
      confidence,
      reason: isIdentityDocument
        ? 'Identity document indicators detected'
        : 'No identity document detected',
    };
  } catch (error) {
    console.error('OCR failed:', error);

    return {
      isIdentityDocument: false,
      docType: 'unknown',
      confidence: 0,
      reason: 'Unable to analyze image',
    };
  }
}
async function uploadSelectedDocument() {
  if (!supabase) {
    setUploadError('Supabase is not connected yet.');
    return false;
  }

  if (!selectedFile) {
    setUploadError('Please select a PDF, JPG or PNG document first.');
    return false;
  }

  setUploadError('');

  const safeName = selectedFile.name
    .replace(/[^a-zA-Z0-9._-]/g, '_');

  const filePath = `uploads/${Date.now()}-${safeName}`;

  const { error } = await supabase.storage
    .from('document')
    .upload(filePath, selectedFile, {
      cacheControl: '3600',
      upsert: false,
      contentType: selectedFile.type,
    });

  if (error) {
    console.error('Document upload failed:', error);
    setUploadError(`Upload failed: ${error.message}`);
    return false;
  }

  return true;
}
  async function runSpecimenCheck() {
    if (!supabase) {
      setLedgerError(
        'Supabase is not connected yet.'
      );

      return;
    }

    setRunning(true);
    setLedgerError('');
    const uploaded = await uploadSelectedDocument();

if (!uploaded) {
  setRunning(false);
  return;
}

    try {
  // -----------------------------------------
  // 1. OCR: read the uploaded image
  // -----------------------------------------
  let extractedText = '';

  if (
    selectedFile &&
    (selectedFile.type === 'image/jpeg' ||
      selectedFile.type === 'image/png')
  ) {
    const worker = await createWorker('eng');

    try {
      const result = await worker.recognize(selectedFile);
      extractedText = result.data.text || '';
    } finally {
      await worker.terminate();
    }
  }

  // -----------------------------------------
  // 2. Normalize OCR text
  // -----------------------------------------
  const text = extractedText
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();

  console.log('OCR extracted text:', text);

  // -----------------------------------------
  // 3. Check whether this looks like an ID
  // -----------------------------------------
  const idKeywords = [
    'aadhaar',
    'uidai',
    'identity',
    'identity card',
    'national id',
    'government of india',
    'date of birth',
    'dob',
    'address',
    'name',
  ];

  const matchedKeywords = idKeywords.filter(
    (keyword) => text.includes(keyword)
  );

  // Detect a 12-digit Aadhaar-like number
  const hasIdNumber =
    /\b\d{4}\s?\d{4}\s?\d{4}\b/.test(text);

  const looksLikeNationalId =
    hasIdNumber || matchedKeywords.length >= 3;

  // -----------------------------------------
  // 4. Reject documents that don't look like ID
  // -----------------------------------------
  let riskScore;
  let decision;
  let reasonCodes;

  if (!looksLikeNationalId) {
    riskScore = 90;
    decision = 'rejected';

    reasonCodes = [
      'document_type_mismatch',
      'national_id_not_detected',
      'insufficient_identity_text',
    ];
  } else {
    // Looks like a national ID
    riskScore = hasIdNumber ? 10 : 25;

    decision =
      riskScore > 45
        ? 'rejected'
        : riskScore > 20
          ? 'review'
          : 'approved';

    reasonCodes =
      riskScore <= 20
        ? ['national_id_detected']
        : [
            'national_id_detected',
            'manual_review_recommended',
          ];
  }

  // -----------------------------------------
  // 5. Generate document hash
  // -----------------------------------------
  const docHash = await sha256Hex(
    `specimen-${Date.now()}-${Math.random()}`
  );

  // -----------------------------------------
  // 6. Save document
  // -----------------------------------------
  const {
    data: document,
    error: documentError,
  } = await supabase
    .from('documents')
    .insert({
      doc_type: looksLikeNationalId
        ? 'national_id'
        : 'unknown',
      status: decision,
    })
    .select()
    .single();

  if (documentError) {
    throw new Error(
      `documents insert failed: ${documentError.message}`
    );
  }

  // -----------------------------------------
  // 7. Save verification event
  // -----------------------------------------
  const {
    data: event,
    error: eventError,
  } = await supabase
    .from('verification_events')
    .insert({
      document_id: document.id,
      risk_score: riskScore,
      reason_codes: reasonCodes,
      decision,
    })
    .select()
    .single();

  if (eventError) {
    throw new Error(
      `verification_events insert failed: ${eventError.message}`
    );
  }

  // -----------------------------------------
  // 8. Create ledger anchor
  // -----------------------------------------
  const blockRef =
    `block#${Math.floor(
      1000 + Math.random() * 9000
    )}`;

  const {
    error: anchorError,
  } = await supabase
    .from('ledger_anchors')
    .insert({
      verification_event_id: event.id,
      doc_hash: docHash,
      block_ref: blockRef,
    });

  if (anchorError) {
    throw new Error(
      `ledger_anchors insert failed: ${anchorError.message}`
    );
  }

  // -----------------------------------------
  // 9. Refresh the ledger
  // -----------------------------------------
  await refreshLedger();
  
    } catch (error) {
      console.error(
        'Specimen check failed:',
        error
      );

      setLedgerError(
        error.message ||
        'Specimen check failed.'
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
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

      <section className="hero">

        <div className="security-weave" />

        <div className="hero-grid">

          <div>

            <div className="eyebrow">
              AI-Based Fake Identity &amp;
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
              A privacy-aware verification
              engine that reads identity
              documents, scores them for
              tampering and inconsistency,
              and anchors only the
              cryptographic proof — never
              the document itself — to a
              permissioned ledger.
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
                  Blockchain &amp;
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
                  FLAGGED · REVIEW
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
                  VERUS&lt;&lt;SPECIMEN&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;
                </div>

                <div>
                  0000000000IND0001019M31012310&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;02
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
            tampering, and assigns an
            explainable risk score. Only
            the cryptographic proof and
            the verification event —
            never the raw document — is
            written to a permissioned
            blockchain.
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
                      <li key={item}>
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
            whether it&apos;s a first
            submission or a
            re-verification against an
            already-anchored proof.
          </p>

        </div>

        <div className="loop-wrap reveal">

          {trustSteps.map(
            ([num, title, description]) => (

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
            No exotic infrastructure —
            mature AI/CV tooling, a REST
            backend, and a permissioned
            chain scoped to the parties
            who actually need to trust
            each other.
          </p>

        </div>

        <div className="reveal">

          <div className="stack-list">

            {stackRows.map(
              ([label, value]) => (

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
              ([num, title, description]) => (

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
            raw identity documents stay
            off-chain; the ledger stores
            only verification proofs,
            hashes, and audit events.
          </p>

        </div>

      </section>

      <section id="feasibility">

        <div className="section-head reveal">

          <div className="eyebrow">
            04 — Feasibility &amp;
            Viability
          </div>

          <h2>
            What could go wrong, and the
            plan for it.
          </h2>

        </div>

        <div className="card-grid reveal">

          <div className="card">

            <h3>
              Technical feasibility
            </h3>

            <p>
              Built on mature components
              — OCR/CV, REST APIs,
              relational storage, and a
              permissioned blockchain.
              The prototype runs in a
              cloud or campus-lab
              environment without
              specialised infrastructure.
            </p>

          </div>

          <div className="card">

            <h3>
              Operational viability
            </h3>

            <p>
              Modular services allow
              phased deployment —
              screening, then
              verification, then ledger
              anchoring — with human
              review always available for
              uncertain cases.
            </p>

          </div>

          <div className="card">

            <h3>
              Key challenges / risks
            </h3>

            <ul>

              <li>
                False positives / negatives
              </li>

              <li>
                New or unseen document
                templates
              </li>

              <li>
                Data privacy and access
                control
              </li>

              <li>
                Model drift and adversarial
                inputs
              </li>

            </ul>

          </div>

          <div className="card">

            <h3>
              Mitigation strategies
            </h3>

            <ul>

              <li>
                Confidence thresholds with
                manual review
              </li>

              <li>
                Versioned template / rule
                registry
              </li>

              <li>
                Encryption and
                least-privilege access
              </li>

              <li>
                Continuous validation and
                model monitoring
              </li>

            </ul>

          </div>

        </div>

        <div className="risk-panel reveal">

          <div className="rp-head">

            <span>
              SAMPLE RISK SCORE —
              SPECIMEN DOCUMENT
            </span>

            <span>
              23 / 100
            </span>

          </div>

          <div className="risk-bar">
            <div className="risk-fill" />
          </div>

          <div className="risk-reasons">

            <span>
              font kerning mismatch
            </span>

            <span>
              MRZ checksum irregular
            </span>

            <span>
              issuer signature verified
            </span>

          </div>

        </div>

      </section>

      <section id="impact">

        <div className="section-head reveal">

          <div className="eyebrow">
            05 — Impact &amp; Benefits
          </div>

          <h2>
            Who this is built for.
          </h2>

        </div>

        <div className="aud-grid reveal">

          {audiences.map(
            ([k, title, description]) => (

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

      <section id="references">

        <div className="section-head reveal">

          <div className="eyebrow">
            06 — Research &amp;
            References
          </div>

          <h2>
            What this design is
            grounded in.
          </h2>

        </div>

        <div className="ref-list reveal">

          {references.map(
            ([name, description]) => (

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
          Standards are referenced as
          design points for the prototype
          architecture; final deployment
          requires organisation-specific
          compliance and validation.
        </p>

      </section>

      <section id="ledger">

        <div className="section-head reveal">

          <div className="eyebrow">
            Live
          </div>

          <h2>
            Ledger feed.
          </h2>

          <p>
            Reads live from Supabase —
            every row is a hash and a
            risk score, never the document
            itself.
          </p>

        </div>

        <div className="reveal">
<div className="upload-panel">
  <div className="upload-title">
    Upload a document for verification
  </div>

  <p className="upload-description">
    Accepted formats: PDF, JPG and PNG. Maximum size: 10 MB.
  </p>

  <input
    type="file"
    accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png"
    onChange={(event) => {
      const file = event.target.files?.[0];

      setUploadError('');
      setSelectedFile(null);

      if (!file) return;

      if (!ALLOWED_FILE_TYPES.includes(file.type)) {
        setUploadError(
          'Unsupported file type. Please upload a PDF, JPG or PNG file.'
        );
        event.target.value = '';
        return;
      }

      if (file.size > MAX_FILE_SIZE) {
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
    <div className="selected-file">
      Selected: <strong>{selectedFile.name}</strong>
    </div>
  )}

  {uploadError && (
    <div className="ledger-error">
      <strong>Upload:</strong> {uploadError}
    </div>
  )}
</div>
          <div className="ledger-head">

            <div
              className={`ledger-status ${
                status === 'connected'
                  ? 'live'
                  : 'off'
              }`}
            >

              <span className="dotstate" />

              <span>
                {statusMessage}
              </span>

            </div>

            <button
              className="run-btn"
              disabled={
                status !== 'connected' ||
                running
              }
              onClick={
                runSpecimenCheck
              }
            >
              {running
                ? 'Running…'
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

          {ledger.length > 0 ? (
            <div className="table-wrap">

              <table className="ledger-table">

                <thead>

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
                          key={row.id}
                        >

                          <td>
                            {date}
                          </td>

                          <td>
                            {escapeText(
                              row.doc_type
                            ) || '—'}
                          </td>

                          <td>
                            {row.risk_score ??
                              '—'}
                          </td>

                          <td>

                            <span
                              className={`decision-pill ${decision}`}
                            >
                              {decision ||
                                '—'}
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

                            {escapeText(
                              row.block_ref
                            ) || '—'}

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

              {status === 'connected'
                ? 'No ledger entries yet. Run a specimen check.'
                : 'Waiting for Supabase…'}

            </div>

          )}

        </div>

      </section>

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