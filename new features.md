# THE-GUARDIAN – Five feature additions

## Implemented backend endpoints

### Savings goals
- `GET /api/v1/user/savings-goals`
- `POST /api/v1/user/savings-goals`
- `POST /api/v1/user/savings-goals/{goal_id}/contribute`

Contributions debit the user's Guardian wallet and create wallet-ledger entries. Goals are completed automatically when the target is reached.

### QR payments
- `GET /api/v1/user/qr-code`
- `POST /api/v1/user/qr-pay`

QR payment transfers funds between two active Guardian accounts and records matching debit/credit ledger entries. This is an internal Guardian wallet payment, not an Airtel or bank QR network payment.

### Virtual Guardian Card
- `GET /api/v1/user/virtual-card`
- `POST /api/v1/user/virtual-card/freeze`
- `POST /api/v1/user/virtual-card/unfreeze`

Card issuance is disabled until a real issuing processor is integrated.

### Spending analytics
- `GET /api/v1/user/spending-analytics?period=week|month|year`

Summarizes allowed outgoing transactions from the user's transaction history.

### Security centre
- `GET /api/v1/user/security-alerts`
- `POST /api/v1/user/security-alerts/{alert_id}/read`
- `GET /api/v1/admin/security-alerts`
- `GET /api/v1/admin/feature-overview`

The customer UI shows security alerts and the admin UI shows feature counts and security alerts. Security alerts are persisted and scoped to the authenticated customer; card-related alerts are not generated while card issuance is disabled.

## Installation

Replace the corresponding files in your project with the versions in this archive. Keep your existing `.env` and database file. The new SQLAlchemy tables are created by the existing `Base.metadata.create_all()` startup initialization; existing tables are not dropped.

Install dependencies from the project's existing `requirements.txt`, then restart the FastAPI application. Back up the database before deploying any schema changes.

## Important limitations

- QR payments work only between active THE-GUARDIAN accounts.
- Card issuance and card controls are disabled until a real issuing processor is integrated.
- External wallet top-up, withdrawal, Airtel transfer to non-Guardian numbers, and airtime purchase now fail closed until verified providers are connected. Transfers and QR payments between active Guardian accounts are internal ledger movements only.
- Production deployment should add database transaction locking/idempotency, CSRF protection, rate limiting, audit review, and a real card/payment provider before handling real funds.


## M.A.R.V.I.S. human voice/video support (new implementation)
- Customer can explicitly request a voice-only or two-way video call. Browser permission is requested only after the customer chooses a call mode.
- Admin sees the authenticated incoming request, and must explicitly accept before the customer is told a human has joined.
- Call lifecycle is stored in `support_calls` and relevant actions are written to the existing activity audit log.
- WebRTC carries media peer-to-peer; the authenticated WebSocket endpoint only relays offer/answer/ICE signaling and enforces the customer/admin participants for the call. Calls are not recorded.
- This initial implementation uses a public STUN server for connectivity discovery. Production deployment must configure a TURN service for reliable calls across restrictive mobile networks/NATs and use a shared signaling/pub-sub backend if running multiple application workers/instances. Verify WebRTC connectivity on the target Render deployment and supported mobile browsers before enabling it for customers.
- The customer can explicitly request one-way camera sharing with an administrator. Biometric enrollment, liveness detection, and face matching are not implemented. A camera preview or shared camera stream is not face authentication.
