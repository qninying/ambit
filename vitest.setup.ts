// ADR-016: the rate limiters in server.ts are constructed once, at module
// load, with their thresholds read from RATE_LIMIT_* env vars right then —
// unlike getSessionConfig()'s deliberately-fresh-per-request read, a
// stateful limiter can't re-read its own thresholds per request without
// losing its counts. That means the only place these env vars can be set
// for a test run is before the module graph loads at all, which is exactly
// what a Vitest setupFile runs before. Generous enough that real test
// traffic (e.g. server.test.ts's 20 separate login() calls) never trips it,
// while server.ts's own production defaults (120/60s general, 5/60s login)
// stay exactly as tight as ADR-016 designed them to be — this file changes
// nothing about what ships, only what the test run itself experiences.
process.env.RATE_LIMIT_GENERAL_MAX_REQUESTS ??= "100000";
process.env.RATE_LIMIT_LOGIN_MAX_REQUESTS ??= "100000";
