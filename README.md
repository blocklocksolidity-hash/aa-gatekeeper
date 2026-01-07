# aa-gatekeeper

> Open-source under MIT. Built for real-world ERC-4337 UX, not research demos.

# AA Gatekeeper (B2) — Phase-1 Deterministic UserOp Classifier + Local Bundler-ish Runner

AA Gatekeeper is a lightweight HTTP service that sits in front of ERC-4337 flow and provides:

- **Human-friendly UX**: `/` landing page + `/health` status page (browser-ready)
- **Machine-friendly API**: JSON-RPC `POST /`
- **Deterministic “signal bundle” classification**: `aa_classifyUserOperation`
- **Phase-1 enforcement**: rejects only **deterministic high-severity** failures before calling `EntryPoint.handleOps`

This repo is intentionally Phase-1: minimal surface area, deterministic checks, and demo-first UX so teams can evaluate quickly.

---

## Why this exists

**Bundlers and wallets fail in ways that are predictable.** Gatekeeper pre-classifies a UserOperation and returns a bundle of actionable signals (with fixes), enabling:

- Better UX (tell the user what’s wrong before submitting)
- Less griefing and wasted gas
- Better ops (request IDs, structured logs, predictable behavior)

---

## Quick demo (browser)

1. Start the service
2. Open:
   - http://127.0.0.1:4337/  (landing page)
   - http://127.0.0.1:4337/health (status page)

---

## Features (Phase-1)

### Endpoints
- `GET /` — Human landing page (demo)
- `GET /health` — Health page (HTML in browser, JSON for machines)
- `POST /` — JSON-RPC endpoint

### JSON-RPC methods
- `eth_supportedEntryPoints`
- `aa_about`
- `aa_classifyUserOperation`
- `eth_sendUserOperation`
- `eth_getUserOperationByHash`
- `eth_getUserOperationReceipt`
- `pimlico_getUserOperationStatus`

---

## Install

Requirements:
- Node.js 18+ (recommended 20+)
- Anvil (or another JSON-RPC Ethereum node)
- A deployed ERC-4337 EntryPoint in your local chain (or your target chain)

```bash
npm install
npm run build
```

## License

MIT License.

You are free to use, modify, and integrate this software in commercial and non-commercial projects.  
Attribution is appreciated but not required.

See [LICENSE](LICENSE) for full text.
