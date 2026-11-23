
https://real-time-fraud-detection-system-1-am1l.onrender.com/login


## M.A.R.V.I.S. customer assistant

The customer dashboard includes M.A.R.V.I.S. text chat, optional browser speech input/output, and an explicitly user-started camera preview. The camera preview is **not** biometric face verification. Secure face enrollment/matching is not included.

Configure these server-side Render environment variables:

- `GEMINI_API_KEY`: Google AI Studio API key (keep it secret; never put it in frontend code).
- `GEMINI_MODEL`: optional model ID; defaults to `gemini-3.8-flash`.

M.A.R.V.I.S. is a customer-only assistant. It receives read-only context for the signed-in customer's wallet totals and recent transactions. It cannot initiate wallet actions or access administrator functions. Conversation history is stored locally in the customer's browser and a short recent window is sent with each chat request. Customers can clear local history from the assistant panel.
