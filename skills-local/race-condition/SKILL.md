# Race Condition Testing

## Scope and preconditions

Applies to any state-changing operation where timing matters: balance transfers,
coupon redemption, vote/like counting, limit-N-per-user features, invitation
accepts, account creation, and any TOCTOU (Time of Check, Time of Use) pattern.
Also applies to OTP brute force via race and parallel session creation.

It does **not** cover: general rate limiting bypass without state manipulation
(use `auth`), or business logic flaws that do not depend on timing (use
`logic-flaws`).

## Rules of engagement

- MUST have written authorization. Race condition tests send high volumes of
  concurrent requests that can impact performance.
- MUST start with small batches (10-20 requests) and scale up only if needed.
- NEVER test race conditions on financial operations in production. Use
  staging/test environments for balance manipulation tests.
- MUST clean up after testing (reverse duplicate operations if possible).

## Workflow

- [ ] 1. Identify race condition targets
- [ ] 2. Establish baseline behavior
- [ ] 3. Test with concurrent requests
- [ ] 4. Apply HTTP/2 single-packet technique
- [ ] 5. Test defense bypass
- [ ] 6. Verify the race outcome
- [ ] 7. Record the finding

## Step 1: Identify race condition targets

### Goal
Find operations where concurrent execution could violate business rules.

### High-value race targets

| Category | Target | What breaks |
|---|---|---|
| Financial | Money transfer | Double spend — `if (balance >= amount)` checked before deducted |
| Discount | Coupon/promo code | Used N times instead of once |
| Voting | Like/upvote/favorite | Counter incremented multiple times |
| Limits | "1 per user" features | Free trial, invitation, download |
| Invitation | Accept invite link | Multiple users join from single-use link |
| Account | Email verification | Multiple accounts verified with one token |
| Session | Login with same OTP | Multiple sessions from single OTP |
| Deletion | Account delete + action | Action executes after account "deleted" |
| Gift cards | Balance redemption | Balance deducted once, credit applied twice |

### Code-level indicators
Look for check-then-act patterns without locks:
- `if (count < limit) { count++; }` — not atomic
- `SELECT balance ... UPDATE balance` — not in a transaction
- `if (!used) { markUsed(); applyDiscount(); }` — TOCTOU gap

## Step 2: Establish baseline

### Goal
Know exactly what happens with a single, normal request.

### Actions
1. Use `send_request` to perform the target operation once.
2. Record the response: status code, body, any counters or balances.
3. Perform the same operation again — does the application properly reject
   the duplicate? (e.g., "Coupon already used", "Already voted")
4. Note the exact rejection message and timing.

## Step 3: Test with concurrent requests

### Goal
Send identical requests simultaneously to exploit the timing window.

### Actions
Prepare 10-20 identical requests with `run_intruder_attack` in concurrent mode.
All requests must arrive at the server within the same millisecond window.

### What to look for
- More than one 200/success response for a limit-1 operation
- Counter incremented by more than 1 (e.g., 12 likes from 10 requests)
- Balance deducted once but credit applied twice
- Multiple sessions created from a single OTP

### Scaling
Start with 10 concurrent requests. If 0 race, try 20, then 50. If the window
is very tight, you need the HTTP/2 technique (Step 4).

## Step 4: HTTP/2 single-packet attack

### Goal
Eliminate network jitter by sending all requests in a single TCP packet.

### Technique (James Kettle, DEF CON 31, 2023)
With HTTP/1.1, even "simultaneous" requests arrive as sequential TCP packets.
The server processes them one at a time with network-delay spacing (often
1-10ms between packets). This gap allows locks and dedup to work.

HTTP/2 multiplexes multiple streams in a single TCP packet. When all requests
fit in one packet (~1500 bytes), they arrive at the server simultaneously —
within microseconds. The application's check-then-act gap is now exploitable.

### How to apply in Void
Use `run_intruder_attack` with HTTP/2 and concurrent mode:
- Set the target to HTTP/2 (most modern servers support it)
- Send all requests as separate streams in the same connection
- The proxy batches them into minimal TCP segments

### Flatt Security scaling (2024)
For targets that need more than ~30 concurrent requests:
1. Open N separate HTTP/2 connections
2. Send the first request on each connection simultaneously (first-sequence-sync)
3. Pipeline remaining requests on each connection

This scales from ~30 to 10,000 concurrent requests within a single rate-limit
window. Useful for brute-forcing PINs within per-window rate limits.

## Step 5: Defense bypass

### Goal
Circumvent protections designed to prevent race conditions.

### Defense bypass table

| Defense | Bypass technique |
|---|---|
| **Idempotency key** | Use the SAME key for all requests — if the key prevents duplicates, use a fresh key per request instead |
| **DB unique constraint** | Time the requests to hit between INSERT and COMMIT — the constraint checks at commit time |
| **Queue serialization** | If the app uses multiple queues (by user, by resource, by region), race across queue boundaries |
| **Distributed lock** | If the lock has a lease expiry, send requests that arrive just as the lease expires |
| **Request dedup** | Vary a non-functional parameter (cache buster, timestamp) so requests look different |
| **Rate limit (per window)** | Send all requests at the very start of a new window before the counter initializes |
| **Double-submit token** | If the token is checked client-side, all concurrent requests share the same valid token |

## Step 6: Verify the race outcome

### Goal
Confirm that the race condition produced an actual business impact.

### Actions
1. After the concurrent burst, check the state:
   - Balance: was it deducted only once but credited multiple times?
   - Counter: does it show N+M instead of N+1?
   - Object: were multiple objects created from a limit-1 operation?
2. Use `send_request` to query the current state (balance, count, status).
3. Use `compare_responses` to diff the pre-race and post-race states.

### Key evidence
- The number of successful responses exceeding the expected limit
- Database state showing the violation (screenshot, API response)
- Timeline showing all requests landing within the same millisecond window

## Step 7: Record the finding

Use `add_pentest_finding` with:
- The target operation and its expected limit
- The number of concurrent requests sent
- The number of successful outcomes (exceeding the limit)
- The business impact (financial loss, unauthorized access)
- The HTTP/2 single-packet technique if used
- Pre-race and post-race state comparison

## Known false positives

- Multiple 200 responses that all perform the same idempotent operation — the
  operation may succeed multiple times but produce the same result (e.g., setting
  a flag that is already set).
- Counter appearing inflated due to caching — clear the cache and recheck.
- Race that works in test but not production due to different database isolation
  levels or infrastructure (load balancer serialization).
- Server responding 200 to all requests but only processing the first — check
  the actual state, not just response codes.

## Reminder

Race conditions are about the gap between checking and acting. The HTTP/2
single-packet attack eliminates network jitter, making previously unexploitable
windows exploitable. The three highest-value race targets: **financial operations**
(double spend), **coupon/promo redemption** (unlimited discounts), and **OTP
verification** (bypass rate limits via parallel attempts). Always verify the
outcome in the database state, not just response codes.
