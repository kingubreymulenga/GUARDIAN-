# M.A.R.V.I.S. implementation and deployment notes

## Included in this build

- Separate customer and administrator M.A.R.V.I.S. interfaces and role-scoped AI endpoints.
- Administrator holographic command interface and voice-first greeting. Browser speech synthesis and voice selection depend on device/browser support and user interaction policies.
- Customer-initiated human support requests for voice, two-way video, and explicitly consented one-way camera sharing.
- Admin-only support queue; a human administrator must accept before the customer is told the session is active.
- Authenticated WebSocket signaling, participant checks, persisted call lifecycle records, and activity audit entries.
- No call recording. Camera/microphone access is requested only after a customer or administrator explicitly chooses to join a relevant session.
- External top-ups, external withdrawals, external Airtel transfers, airtime delivery, and virtual card issuance fail closed until real providers are integrated. Internal Guardian-to-Guardian transfers and Guardian QR payments remain internal ledger movements, not Airtel or bank transfers.

## Render environment

Keep secrets only in Render environment variables:

- `SECRET_KEY` — strong random session-signing secret.
- `ADMIN_USERNAME` and `ADMIN_PASSWORD` — administrator credentials.
- `COOKIE_SECURE=true` — required when serving over HTTPS.
- `GEMINI_API_KEY` — server-side Gemini API key; never expose it in browser code or commit it.
- `GEMINI_MODEL=gemini-3.8-flash` — model identifier; can be changed without editing source.

Back up the database before deployment. The new `support_calls` table is created by the existing SQLAlchemy `Base.metadata.create_all()` startup initialization; no existing table is dropped.

## Important production limitations before public rollout

1. The current WebRTC implementation advertises a public STUN server only. This is not enough for reliable calls across every mobile carrier, NAT, or restrictive network. Deploy a TURN service and implement short-lived TURN credentials from a protected backend endpoint before relying on calls in production.
2. Signaling rooms currently live in application memory. Run a single application worker/instance for this version. Multi-worker or multi-instance deployment needs shared signaling/pub-sub state and coordinated call ownership.
3. Test real voice, video, camera-sharing, reconnection, and permission-denial behavior on the actual Render HTTPS domain and target iOS Safari/Android browsers. A successful signaling test does not prove media will traverse every network.
4. Face enrollment, liveness detection, and biometric matching are not implemented. Camera preview and support camera sharing are not face verification.
5. Virtual card issuance is disabled. No bank-issued Visa/Mastercard card is currently available. No new feature should be represented as an external financial rail unless a real provider is connected and verified.
6. Before handling real customer funds at scale, independently review transaction locking/idempotency, CSRF protection, rate limiting, audit retention, database durability/backups, and payment-provider reconciliation.

## Verification performed for this build

- Python syntax compilation for the modified backend modules.
- JavaScript syntax validation for both dashboard scripts after resolving the Jinja template variable for the check.
- FastAPI import and route registration check in a local validation process.
- TestClient verification of customer call request, administrator queue, administrator acceptance, authenticated WebSocket participant joining, signaling relay, and administrator call termination.

These checks do not replace an end-to-end browser/media test on the deployed service.
