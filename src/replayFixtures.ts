export interface ReplayTraceSession {
  name: string
  appId: string
  requests: readonly string[]
  mustStayAvailable: readonly string[]
  expectedObservedInLight: readonly string[]
  expectedBlockedInLight: readonly string[]
  expectedOptionalMatches: readonly string[]
}

export const ANONYMIZED_PILOT_DNS_TRACES: readonly ReplayTraceSession[] = [
  {
    name: 'checkout_flow',
    appId: 'com.choicefirst.checkout',
    requests: [
      'api.choicefirst.example',
      'login.example.com',
      'checkout.example.com',
      'ads.measurement.example',
      'fingerprint.optional.example',
    ],
    mustStayAvailable: ['login.example.com', 'checkout.example.com'],
    expectedObservedInLight: ['login.example.com', 'checkout.example.com'],
    expectedBlockedInLight: ['ads.measurement.example'],
    expectedOptionalMatches: ['fingerprint.optional.example'],
  },
  {
    name: 'streaming_playback',
    appId: 'com.choicefirst.media',
    requests: [
      'video.choicefirst.example',
      'stream-cdn.example.com',
      'analytics.beacon.example',
      'video-reco.optional.example',
    ],
    mustStayAvailable: ['stream-cdn.example.com'],
    expectedObservedInLight: ['stream-cdn.example.com'],
    expectedBlockedInLight: ['analytics.beacon.example'],
    expectedOptionalMatches: ['video-reco.optional.example'],
  },
  {
    name: 'pilot_app_startup',
    appId: 'com.choicefirst.pilot',
    requests: [
      'bootstrap.choicefirst.example',
      'bootstrap-api.example.com',
      'captcha.example.com',
      'startup-telemetry.example.com',
      'metrics-core.example.com',
      'crash-upload.optional.example',
    ],
    mustStayAvailable: ['bootstrap-api.example.com', 'captcha.example.com', 'startup-telemetry.example.com'],
    expectedObservedInLight: ['bootstrap-api.example.com', 'captcha.example.com', 'startup-telemetry.example.com'],
    expectedBlockedInLight: ['metrics-core.example.com'],
    expectedOptionalMatches: ['crash-upload.optional.example'],
  },
] as const