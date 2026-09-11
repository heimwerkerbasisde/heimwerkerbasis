# AVARRA Backend

Production Node/Vercel backend for the private German AVARRA text RPG.

## Runtime routes

- `GET /api/health`
- tRPC game routes under `/api/trpc/*`, including ritual, game master, portrait, and scene image procedures.

Secrets are configured only in the Vercel Production environment:

- `GROQ_API_KEY`
- `POLLINATIONS_API_KEY`

No secrets belong in this repository.
