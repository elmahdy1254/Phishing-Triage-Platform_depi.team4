/**
 * Phishing Triage – Mock Data
 * ============================
 * Realistic sample payloads used when USE_MOCK is enabled.
 * Every object follows the JSON contract defined in the spec.
 */

// ---------------------------------------------------------------------------
// 1. HIGH-RISK analysis  (score 87 – malicious)
// ---------------------------------------------------------------------------
const highRisk = {
  id: 'a1b2c3',
  filename: 'invoice_payment.eml',
  analyzed_at: '2026-11-19T10:32:00Z',

  risk: {
    score: 87,
    verdict: 'malicious',
    breakdown: [
      { factor: 'DMARC fail', points: 25 },
      { factor: 'SPF fail', points: 20 },
      { factor: 'Malicious URL detected', points: 20 },
      { factor: 'Dangerous attachment (.exe)', points: 15 },
      { factor: 'Return-Path domain mismatch', points: 7 }
    ]
  },

  envelope: {
    from: 'billing@fake-paypal.com',
    reply_to: 'support@paypalsecure-update.com',
    to: 'john.doe@acmecorp.com',
    subject: 'Urgent: Your invoice #INV-29847 is ready for payment',
    date: '2026-11-19T09:14:22Z',
    message_id: '<5f8a3b2c.1a2b3c@fake-paypal.com>',
    body_text:
      'Dear Customer,\n\nPlease review and pay your outstanding invoice immediately to avoid service disruption.\n\nClick here to view your invoice: https://fake-paypal.com/invoice/29847\n\nIf you have already made this payment, please disregard this message.\n\nRegards,\nPayPal Billing Team'
  },

  authentication: {
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    spoofing_indicators: [
      'Return-Path domain mismatch',
      'Display name impersonation (PayPal)',
      'Envelope-From differs from header From'
    ]
  },

  routing: [
    {
      hop: 1,
      from: 'mail-out.fake-paypal.com',
      by: 'mx1.shady-relay.net',
      ip: '185.234.72.19',
      timestamp: '2026-11-19T09:14:25Z',
      country: 'RU'
    },
    {
      hop: 2,
      from: 'mx1.shady-relay.net',
      by: 'gateway.bulletproof-host.biz',
      ip: '91.215.44.108',
      timestamp: '2026-11-19T09:14:30Z',
      country: 'UA'
    },
    {
      hop: 3,
      from: 'gateway.bulletproof-host.biz',
      by: 'edge-filter.acmecorp.com',
      ip: '198.51.100.22',
      timestamp: '2026-11-19T09:14:45Z',
      country: 'US'
    },
    {
      hop: 4,
      from: 'edge-filter.acmecorp.com',
      by: 'mail.acmecorp.com',
      ip: '10.0.1.5',
      timestamp: '2026-11-19T09:14:47Z',
      country: 'US'
    }
  ],

  urls: [
    {
      url: 'https://fake-paypal.com/invoice/29847',
      domain: 'fake-paypal.com',
      verdict: 'malicious',
      detections: 48,
      total_engines: 90,
      source: 'VirusTotal'
    },
    {
      url: 'https://paypalsecure-update.com/verify',
      domain: 'paypalsecure-update.com',
      verdict: 'malicious',
      detections: 32,
      total_engines: 90,
      source: 'VirusTotal'
    }
  ],

  attachments: [
    {
      filename: 'Invoice_29847.exe',
      extension: '.exe',
      size_bytes: 245_760,
      md5: 'e99a18c428cb38d5f260853678922e03',
      sha256:
        'a3f5b7d12c9e84f6a1b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4',
      dangerous_extension: true,
      verdict: 'malicious',
      detections: 61,
      total_engines: 72
    }
  ]
};

// ---------------------------------------------------------------------------
// 2. MEDIUM-RISK analysis  (score 45 – suspicious)
// ---------------------------------------------------------------------------
const mediumRisk = {
  id: 'd4e5f6',
  filename: 'meeting_invite.msg',
  analyzed_at: '2026-11-18T15:47:12Z',

  risk: {
    score: 45,
    verdict: 'suspicious',
    breakdown: [
      { factor: 'SPF softfail', points: 15 },
      { factor: 'DMARC none', points: 10 },
      { factor: 'Suspicious URL detected', points: 12 },
      { factor: 'Unusual sending time', points: 8 }
    ]
  },

  envelope: {
    from: 'sarah.jones@partnercorp.io',
    reply_to: 'sarah.jones@partnercorp.io',
    to: 'team@acmecorp.com',
    subject: 'Re: Q4 Strategy Meeting – Updated Agenda',
    date: '2026-11-18T14:22:08Z',
    message_id: '<8b2d4e6f.meeting@partnercorp.io>',
    body_text:
      'Hi Team,\n\nPlease find the updated agenda for our Q4 strategy meeting attached.\n\nI have also shared the presentation deck via the link below:\nhttps://partnercorp-files.com/shared/q4-deck\n\nLooking forward to the discussion.\n\nBest,\nSarah Jones\nVP Strategy, PartnerCorp'
  },

  authentication: {
    spf: 'softfail',
    dkim: 'pass',
    dmarc: 'none',
    spoofing_indicators: []
  },

  routing: [
    {
      hop: 1,
      from: 'smtp-out.partnercorp.io',
      by: 'relay1.partnercorp.io',
      ip: '104.26.11.78',
      timestamp: '2026-11-18T14:22:10Z',
      country: 'US'
    },
    {
      hop: 2,
      from: 'relay1.partnercorp.io',
      by: 'mx-proxy.google.com',
      ip: '142.250.80.27',
      timestamp: '2026-11-18T14:22:18Z',
      country: 'US'
    },
    {
      hop: 3,
      from: 'mx-proxy.google.com',
      by: 'edge-filter.acmecorp.com',
      ip: '198.51.100.22',
      timestamp: '2026-11-18T14:22:25Z',
      country: 'US'
    },
    {
      hop: 4,
      from: 'edge-filter.acmecorp.com',
      by: 'mail.acmecorp.com',
      ip: '10.0.1.5',
      timestamp: '2026-11-18T14:22:27Z',
      country: 'US'
    },
    {
      hop: 5,
      from: 'mail.acmecorp.com',
      by: 'store.acmecorp.com',
      ip: '10.0.1.12',
      timestamp: '2026-11-18T14:22:28Z',
      country: 'US'
    }
  ],

  urls: [
    {
      url: 'https://partnercorp-files.com/shared/q4-deck',
      domain: 'partnercorp-files.com',
      verdict: 'suspicious',
      detections: 3,
      total_engines: 90,
      source: 'VirusTotal'
    }
  ],

  attachments: [
    {
      filename: 'Q4_Agenda_v2.docx',
      extension: '.docx',
      size_bytes: 84_291,
      md5: '7c6a180b36896a6ba87e4cf0c47f0f74',
      sha256:
        'b4d8e2f1a3c5d7e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3',
      dangerous_extension: false,
      verdict: 'clean',
      detections: 0,
      total_engines: 72
    }
  ]
};

// ---------------------------------------------------------------------------
// 3. CLEAN analysis  (score 8 – clean)
// ---------------------------------------------------------------------------
const cleanEmail = {
  id: 'g7h8i9',
  filename: 'newsletter.eml',
  analyzed_at: '2026-11-17T08:15:30Z',

  risk: {
    score: 8,
    verdict: 'clean',
    breakdown: [
      { factor: 'Low volume sender', points: 5 },
      { factor: 'First-time sender to org', points: 3 }
    ]
  },

  envelope: {
    from: 'noreply@techdigest.com',
    reply_to: 'noreply@techdigest.com',
    to: 'john.doe@acmecorp.com',
    subject: 'TechDigest Weekly – Top Stories in Cybersecurity',
    date: '2026-11-17T07:00:00Z',
    message_id: '<weekly-2026-47@techdigest.com>',
    body_text:
      'TechDigest Weekly\n==================\n\nTop stories this week:\n\n1. Zero-day vulnerability patched in major browser\n2. New NIST guidelines for post-quantum cryptography\n3. Cloud-native SIEM adoption surges 40%\n\nRead the full newsletter: https://techdigest.com/weekly/2026-47\n\nManage your subscription: https://techdigest.com/unsubscribe\n\n© 2026 TechDigest Inc.'
  },

  authentication: {
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    spoofing_indicators: []
  },

  routing: [
    {
      hop: 1,
      from: 'mailer.techdigest.com',
      by: 'mta-out1.techdigest.com',
      ip: '151.101.1.195',
      timestamp: '2026-11-17T07:00:02Z',
      country: 'US'
    },
    {
      hop: 2,
      from: 'mta-out1.techdigest.com',
      by: 'mx.google.com',
      ip: '142.250.115.27',
      timestamp: '2026-11-17T07:00:08Z',
      country: 'US'
    },
    {
      hop: 3,
      from: 'mx.google.com',
      by: 'edge-filter.acmecorp.com',
      ip: '198.51.100.22',
      timestamp: '2026-11-17T07:00:15Z',
      country: 'US'
    }
  ],

  urls: [
    {
      url: 'https://techdigest.com/weekly/2026-47',
      domain: 'techdigest.com',
      verdict: 'clean',
      detections: 0,
      total_engines: 90,
      source: 'VirusTotal'
    },
    {
      url: 'https://techdigest.com/unsubscribe',
      domain: 'techdigest.com',
      verdict: 'clean',
      detections: 0,
      total_engines: 90,
      source: 'VirusTotal'
    }
  ],

  attachments: [
    {
      filename: 'techdigest-2026-47.pdf',
      extension: '.pdf',
      size_bytes: 1_245_184,
      md5: 'd4735e3a265e16eee03f59718b9b5d03',
      sha256:
        'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
      dangerous_extension: false,
      verdict: 'clean',
      detections: 0,
      total_engines: 72
    }
  ]
};

// ---------------------------------------------------------------------------
// All analyses (used by list / search endpoints)
// ---------------------------------------------------------------------------
export const MOCK_ANALYSES = [highRisk, mediumRisk, cleanEmail];

// ---------------------------------------------------------------------------
// Dashboard / stats payload
// ---------------------------------------------------------------------------
export const MOCK_STATS = {
  total_analyses: 1_247,
  malicious_count: 312,
  suspicious_count: 489,
  clean_count: 423,
  unknown_count: 23,

  avg_risk_score: 42.6,
  top_targeted_domains: [
    { domain: 'acmecorp.com', count: 487 },
    { domain: 'finance.acmecorp.com', count: 213 },
    { domain: 'hr.acmecorp.com', count: 178 }
  ],

  verdict_distribution: {
    labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
    data: [312, 489, 423, 23],
    colors: ['#D9715F', '#D9A94F', '#8FB38A', '#8AA7B8']
  },

  analyses_over_time: {
    labels: [
      '2026-11-13',
      '2026-11-14',
      '2026-11-15',
      '2026-11-16',
      '2026-11-17',
      '2026-11-18',
      '2026-11-19'
    ],
    datasets: [
      {
        label: 'Malicious',
        data: [12, 18, 9, 15, 22, 14, 11],
        color: '#D9715F'
      },
      {
        label: 'Suspicious',
        data: [23, 31, 19, 27, 35, 20, 25],
        color: '#D9A94F'
      },
      {
        label: 'Clean',
        data: [30, 28, 33, 25, 29, 31, 27],
        color: '#8FB38A'
      }
    ]
  }
};

// ---------------------------------------------------------------------------
// Health check payload
// ---------------------------------------------------------------------------
export const MOCK_HEALTH = {
  status: 'ok',
  version: '1.4.0',
  uptime_seconds: 864_000,
  services: {
    database: 'healthy',
    virus_total: 'healthy',
    email_parser: 'healthy'
  }
};

// ---------------------------------------------------------------------------
// Helper: look up a single analysis by ID
// ---------------------------------------------------------------------------
/**
 * Return the mock analysis matching `id`, or `undefined`.
 * @param {string} id
 */
export function getMockAnalysisById(id) {
  return MOCK_ANALYSES.find((a) => a.id === id);
}

/**
 * Filter and paginate the analyses list.
 * @param {{ page?: number, limit?: number, verdict?: string, q?: string }} params
 * @returns {{ items: object[], total: number }}
 */
export function getMockAnalysesList(params = {}) {
  let items = [...MOCK_ANALYSES];

  // Filter by verdict
  if (params.verdict) {
    items = items.filter((a) => a.risk.verdict === params.verdict);
  }

  // Simple text search across filename & subject
  if (params.q) {
    const q = params.q.toLowerCase();
    items = items.filter(
      (a) =>
        a.filename.toLowerCase().includes(q) ||
        a.envelope.subject.toLowerCase().includes(q) ||
        a.envelope.from.toLowerCase().includes(q)
    );
  }

  const total = items.length;
  const page = Math.max(1, parseInt(params.page, 10) || 1);
  const limit = Math.max(1, parseInt(params.limit, 10) || 10);
  const start = (page - 1) * limit;

  return {
    items: items.slice(start, start + limit),
    total
  };
}
