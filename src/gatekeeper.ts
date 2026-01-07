import http from "node:http";
import { ethers } from "ethers";
import crypto from "crypto";

/**
 * Gatekeeper B2 (local bundler-ish) + Phase-1 classifier (signal bundle)
 *
 * Env:
 *   ANVIL_RPC        = http://127.0.0.1:8545
 *   ENTRYPOINTS      = 0xEntryPoint1[,0xEntryPoint2...]
 *   BENEFICIARY      = 0x...
 *   BUNDLER_KEY      = 0x...
 *   PORT             = 4337   (optional)
 *   HOST             = 127.0.0.1 (optional)
 *
 * RPC method:
 *   aa_classifyUserOperation
 *     params: [{ userOp: <RPC UserOperation>, entryPoint?: "0x..." }]
 *     returns: { ok, deterministic, signals[], meta }
 *
 * Enforced precheck inside:
 *   eth_sendUserOperation (rejects deterministic high-severity signals before handleOps)
 */

/* ------------------------- types ------------------------- */

type RpcReq = {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: any[];
};

type RpcRes = {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: any;
  error?: { code: number; message: string; data?: any };
};

type StoredUO = {
  userOperation: any; // RPC-style UserOperation
  entryPoint: string;

  // filled after inclusion
  transactionHash?: string;
  blockHash?: string;
  blockNumber?: string;

  // decoded from UserOperationEvent
  success?: boolean;
  actualGasCost?: string; // hex
  actualGasUsed?: string; // hex
};

/* ------------------------- env/helpers ------------------------- */

function nowIso() {
  return new Date().toISOString();
}

function makeRequestId() {
  return crypto.randomBytes(8).toString("hex"); // 16 hex chars
}

function logJson(obj: Record<string, unknown>) {
  console.log(JSON.stringify(obj));
}

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env ${name}`);
  return v;
}

function mustHexEnv(name: string): string {
  const v = mustEnv(name);
  if (!v.startsWith("0x")) throw new Error(`Invalid hex env ${name}`);
  return v;
}

function normalizeAddr(a: string): string {
  return ethers.getAddress(a);
}

function isHexStr(x: any): x is string {
  return typeof x === "string" && x.startsWith("0x");
}

function lower(a: string): string {
  return a.toLowerCase();
}

/* ------------------------- EntryPoint ABI ------------------------- */

const ENTRYPOINT_ABI = [
  "function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,bytes paymasterAndData,bytes signature)[] ops,address beneficiary)",
  "function balanceOf(address account) view returns (uint256)",
  "event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)",
];

const epIface = new ethers.Interface(ENTRYPOINT_ABI);

function logInfo(...args: any[]) {
  console.log("[gatekeeper-b2]", ...args);
}

function jsonRpcError(
  id: any,
  code: number,
  message: string,
  data?: any,
  requestId?: string
): RpcRes {
  const mergedData =
    requestId
      ? data && typeof data === "object"
        ? { ...data, requestId }
        : { data, requestId }
      : data;

  return { jsonrpc: "2.0", id, error: { code, message, data: mergedData } };
}

function jsonRpcResult(id: any, result: any): RpcRes {
  return { jsonrpc: "2.0", id, result };
}

function parseEntryPoints(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(normalizeAddr);
}

/**
 * Convert a RPC-style UserOperation (all hex strings) into the struct tuple
 * EntryPoint.handleOps expects.
 */
function toEntryPointTuple(uo: any) {
  return {
    sender: normalizeAddr(uo.sender),
    nonce: BigInt(uo.nonce),
    initCode: uo.initCode ?? "0x",
    callData: uo.callData ?? "0x",
    callGasLimit: BigInt(uo.callGasLimit),
    verificationGasLimit: BigInt(uo.verificationGasLimit),
    preVerificationGas: BigInt(uo.preVerificationGas),
    maxFeePerGas: BigInt(uo.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(uo.maxPriorityFeePerGas),
    paymasterAndData: uo.paymasterAndData ?? "0x",
    signature: uo.signature ?? "0x",
  };
}

/**
 * Decode UserOperationEvent from a tx receipt and return gas fields for the given userOpHash.
 */
function decodeUserOpEventFromReceipt(
  receipt: ethers.TransactionReceipt,
  userOpHash: string,
  entryPoint: string
) {
  const wantHash = lower(userOpHash);
  const wantEP = lower(entryPoint);

  for (const l of receipt.logs) {
    if (lower(l.address) !== wantEP) continue;
    if (!l.topics || l.topics.length < 1) continue;

    let parsed: ethers.LogDescription | null = null;
    try {
      parsed = epIface.parseLog({ topics: l.topics as string[], data: l.data });
    } catch {
      continue;
    }
    if (!parsed || parsed.name !== "UserOperationEvent") continue;

    const evHash = String(parsed.args.userOpHash);
    if (lower(evHash) !== wantHash) continue;

    const success: boolean = Boolean(parsed.args.success);
    const actualGasCost: bigint = BigInt(parsed.args.actualGasCost);
    const actualGasUsed: bigint = BigInt(parsed.args.actualGasUsed);

    return {
      success,
      actualGasCostHex: ethers.toBeHex(actualGasCost),
      actualGasUsedHex: ethers.toBeHex(actualGasUsed),
    };
  }

  return null;
}

/* ------------------------- Classifier (Phase 1: Signal Bundle) ------------------------- */

type SignalSeverity = "info" | "low" | "medium" | "high";

type ClassifierSignal = {
  code:
    | "SENDER_NOT_CONTRACT"
    | "INITCODE_SUPPLIED_BUT_SENDER_ALREADY_DEPLOYED"
    | "INSUFFICIENT_ACCOUNT_BALANCE_FOR_VALUE"
    | "UNSUPPORTED_CALLDATA_SHAPE"
    | "INVALID_SIGNATURE_LENGTH"
    | "PREFUND_TOO_LOW";
  severity: SignalSeverity;
  deterministic: true;
  confidence: 1;
  summary: string;
  evidence?: Record<string, string>;
  fix?: string;
};

type ClassifierBundle = {
  ok: boolean;
  deterministic: true;
  signals: ClassifierSignal[];
  meta: { version: "phase1-bundle" };
};

function bundleFromSignals(signals: ClassifierSignal[]): ClassifierBundle {
  return {
    ok: signals.length === 0,
    deterministic: true,
    signals,
    meta: { version: "phase1-bundle" },
  };
}

function shouldReject(signals: ClassifierSignal[]): boolean {
  // Phase-1 enforcement rule: reject only deterministic high severity signals
  return signals.some((s) => s.deterministic && s.severity === "high");
}

// SimpleAccount execute(address dest,uint256 value,bytes func)
const EXECUTE_IFACE = new ethers.Interface([
  "function execute(address dest,uint256 value,bytes calldata func)",
]);
const EXECUTE_SELECTOR = EXECUTE_IFACE.getFunction("execute")!.selector;

/**
 * Deterministic signal:
 * - If sender has no code AND initCode is empty, the account is not deployed.
 */
async function sigSenderNotDeployed(params: {
  provider: ethers.Provider;
  userOp: { sender: string; initCode?: string };
}): Promise<ClassifierSignal | null> {
  const { provider, userOp } = params;

  const sender = ethers.getAddress(userOp.sender);
  const initCode = userOp.initCode ?? "0x";

  const code = await provider.getCode(sender);
  const hasInitCode = initCode !== "0x";

  if (code === "0x" && !hasInitCode) {
    return {
      code: "SENDER_NOT_CONTRACT",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary: "sender has no contract code and initCode is empty; account is not deployed.",
      evidence: { sender, senderCode: "0x", initCodeLen: String(initCode.length) },
      fix: "Use a deployed smart account as sender OR provide initCode to deploy it via a factory.",
    };
  }

  return null;
}

/**
 * Deterministic signal:
 * - If sender HAS code AND initCode is non-empty, caller is likely mistaken.
 */
async function sigInitCodeSuppliedButSenderAlreadyDeployed(params: {
  provider: ethers.Provider;
  userOp: { sender: string; initCode?: string };
}): Promise<ClassifierSignal | null> {
  const { provider, userOp } = params;

  const sender = ethers.getAddress(userOp.sender);
  const initCode = userOp.initCode ?? "0x";

  const code = await provider.getCode(sender);
  const hasInitCode = initCode !== "0x";

  if (code !== "0x" && hasInitCode) {
    return {
      code: "INITCODE_SUPPLIED_BUT_SENDER_ALREADY_DEPLOYED",
      severity: "high", // enforce reject
      deterministic: true,
      confidence: 1,
      summary:
        "sender already has contract code, but initCode is non-empty; EntryPoint will revert (@AA10 sender already constructed).",
      evidence: {
        sender,
        senderCode: "<nonzero>",
        initCodeLen: String(initCode.length),
      },
      fix: "Set initCode to 0x when sending from an already-deployed account.",
    };
  }

  return null;
}

/**
 * Deterministic signal:
 * - If callData is execute(dest,value,bytes) and value > 0, then sender ETH balance must be >= value.
 * - If callData is not decodable to that shape, we emit an INFO signal (non-blocking).
 */
async function sigValueOutOfFunds(params: {
  provider: ethers.Provider;
  userOp: { sender: string; callData?: string };
}): Promise<ClassifierSignal | null> {
  const { provider, userOp } = params;

  const sender = ethers.getAddress(userOp.sender);
  const callData = userOp.callData ?? "0x";

  if (callData === "0x" || callData.length < 10) {
    return {
      code: "UNSUPPORTED_CALLDATA_SHAPE",
      severity: "info",
      deterministic: true,
      confidence: 1,
      summary: "callData missing or too short to decode execute(dest,value,bytes).",
      evidence: { sender, callDataLen: String(callData.length) },
      fix: "Provide callData for execute(dest,value,bytes) or extend classifier for your account type.",
    };
  }

  const selector = callData.slice(0, 10).toLowerCase();
  if (selector !== EXECUTE_SELECTOR.toLowerCase()) {
    return {
      code: "UNSUPPORTED_CALLDATA_SHAPE",
      severity: "info",
      deterministic: true,
      confidence: 1,
      summary: "callData selector is not SimpleAccount.execute(address,uint256,bytes).",
      evidence: { sender, selector, expected: EXECUTE_SELECTOR },
      fix: "Use execute(dest,value,bytes) callData or extend classifier to support additional selectors.",
    };
  }

  let decoded: any;
  try {
    decoded = EXECUTE_IFACE.decodeFunctionData("execute", callData);
  } catch {
    return {
      code: "UNSUPPORTED_CALLDATA_SHAPE",
      severity: "info",
      deterministic: true,
      confidence: 1,
      summary: "Failed to decode execute(dest,value,bytes) callData.",
      evidence: { sender, selector },
      fix: "Ensure callData is ABI-encoded for execute(address,uint256,bytes).",
    };
  }

  const valueWei: bigint = BigInt(decoded.value);

  // If value is 0, no failure signal
  if (valueWei === 0n) return null;

  const balWei = await provider.getBalance(sender);

  if (balWei < valueWei) {
    return {
      code: "INSUFFICIENT_ACCOUNT_BALANCE_FOR_VALUE",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary: "Account ETH balance is lower than value being sent in callData.",
      evidence: {
        sender,
        senderBalanceWei: balWei.toString(),
        requiredValueWei: valueWei.toString(),
      },
      fix: "Fund the account address with at least requiredValueWei (plus small headroom).",
    };
  }

  return null;
}

/**
 * Deterministic signal:
 * - SimpleAccount expects a 65-byte ECDSA signature.
 *
 * NOTE: We check BYTES length, not hex-string length, to avoid false positives.
 */
async function sigInvalidSignatureLength(params: {
  userOp: { signature?: string; sender: string };
}): Promise<ClassifierSignal | null> {
  const { userOp } = params;
  const sender = ethers.getAddress(userOp.sender);
  const sig = userOp.signature ?? "0x";

  if (!isHexStr(sig)) {
    return {
      code: "INVALID_SIGNATURE_LENGTH",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary: "signature is not a valid hex string.",
      evidence: { sender, signature: String(sig) },
      fix: "Provide a valid hex signature (0x...).",
    };
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = ethers.getBytes(sig);
  } catch {
    return {
      code: "INVALID_SIGNATURE_LENGTH",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary: "signature is not valid hex-encoded bytes.",
      evidence: { sender, signatureLen: String(sig.length) },
      fix: "Provide hex-encoded signature bytes (0x...).",
    };
  }

  if (sigBytes.length !== 65) {
    return {
      code: "INVALID_SIGNATURE_LENGTH",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary: "signature length is not 65 bytes; SimpleAccount will revert during signature validation.",
      evidence: { sender, sigBytesLen: String(sigBytes.length) },
      fix: "Provide a 65-byte ECDSA signature (r,s,v) for the account owner.",
    };
  }

  return null;
}

/**
 * Deterministic signal:
 * - Sender must have enough EntryPoint deposit to pay required prefund (unless paymaster is present).
 *
 * This is a Phase-1 approximation that matches the AA21 'didn't pay prefund' class well.
 * requiredPrefund ≈ (callGasLimit + verificationGasLimit + preVerificationGas) * maxFeePerGas
 *
 * FIX: Don't emit PREFUND_TOO_LOW for "sender not deployed + initCode empty" cases.
 */
async function sigPrefundTooLow(params: {
  provider: ethers.Provider;
  entryPoint?: string;
  userOp: {
    sender: string;
    initCode?: string;
    callGasLimit?: string;
    verificationGasLimit?: string;
    preVerificationGas?: string;
    maxFeePerGas?: string;
    paymasterAndData?: string;
  };
}): Promise<ClassifierSignal | null> {
  const { provider, entryPoint, userOp } = params;

  // If caller didn't provide entryPoint, skip (aa_classifyUserOperation may omit it)
  if (!entryPoint) return null;

  const sender = ethers.getAddress(userOp.sender);
  const initCode = userOp.initCode ?? "0x";

  // ✅ FIX: If sender isn't deployed AND initCode is empty, prefund check is irrelevant noise.
  const senderCode = await provider.getCode(sender);
  const hasInitCode = initCode !== "0x";
  if (senderCode === "0x" && !hasInitCode) return null;

  const paymasterAndData = userOp.paymasterAndData ?? "0x";
  const hasPaymaster = paymasterAndData.length > 2;
  if (hasPaymaster) return null;

  const callGasLimit = BigInt(userOp.callGasLimit ?? "0x0");
  const verificationGasLimit = BigInt(userOp.verificationGasLimit ?? "0x0");
  const preVerificationGas = BigInt(userOp.preVerificationGas ?? "0x0");
  const maxFeePerGas = BigInt(userOp.maxFeePerGas ?? "0x0");

  const gasTotal = callGasLimit + verificationGasLimit + preVerificationGas;
  const requiredPrefund = gasTotal * maxFeePerGas;

  const ep = new ethers.Contract(
    entryPoint,
    ["function balanceOf(address) view returns (uint256)"],
    provider
  );
  const depositRaw = await ep.balanceOf(sender);
  const deposit: bigint = BigInt(depositRaw);

  if (deposit < requiredPrefund) {
    return {
      code: "PREFUND_TOO_LOW",
      severity: "high",
      deterministic: true,
      confidence: 1,
      summary:
        "EntryPoint deposit for sender is below required prefund; EntryPoint will revert (@AA21 didn't pay prefund).",
      evidence: {
        sender,
        entryPoint: ethers.getAddress(entryPoint),
        depositWei: deposit.toString(),
        requiredPrefundWei: requiredPrefund.toString(),
        gasTotal: gasTotal.toString(),
        maxFeePerGas: maxFeePerGas.toString(),
      },
      fix: "Call EntryPoint.depositTo(sender) to raise deposit above requiredPrefundWei (plus headroom), or use a paymaster.",
    };
  }

  return null;
}

async function classifyUserOperationBundle(params: {
  provider: ethers.Provider;
  entryPoint?: string;
  userOp: {
    sender: string;
    initCode?: string;
    callData?: string;
    signature?: string;
    callGasLimit?: string;
    verificationGasLimit?: string;
    preVerificationGas?: string;
    maxFeePerGas?: string;
    paymasterAndData?: string;
  };
}): Promise<ClassifierBundle> {
  const { provider, entryPoint, userOp } = params;

  const signals: ClassifierSignal[] = [];

  const s0 = await sigSenderNotDeployed({
    provider,
    userOp: { sender: userOp.sender, initCode: userOp.initCode ?? "0x" },
  });
  if (s0) signals.push(s0);

  const sInit = await sigInitCodeSuppliedButSenderAlreadyDeployed({
    provider,
    userOp: { sender: userOp.sender, initCode: userOp.initCode ?? "0x" },
  });
  if (sInit) signals.push(sInit);

  const s1 = await sigValueOutOfFunds({
    provider,
    userOp: { sender: userOp.sender, callData: userOp.callData ?? "0x" },
  });
  if (s1) signals.push(s1);

  const sSig = await sigInvalidSignatureLength({
    userOp: { sender: userOp.sender, signature: userOp.signature ?? "0x" },
  });
  if (sSig) signals.push(sSig);

  const sPre = await sigPrefundTooLow({
    provider,
    entryPoint,
    userOp: {
      sender: userOp.sender,
      initCode: userOp.initCode ?? "0x",
      callGasLimit: userOp.callGasLimit ?? "0x0",
      verificationGasLimit: userOp.verificationGasLimit ?? "0x0",
      preVerificationGas: userOp.preVerificationGas ?? "0x0",
      maxFeePerGas: userOp.maxFeePerGas ?? "0x0",
      paymasterAndData: userOp.paymasterAndData ?? "0x",
    },
  });
  if (sPre) signals.push(sPre);

  return bundleFromSignals(signals);
}

/* ------------------------- main ------------------------- */

async function main() {
  const HOST = process.env.HOST ?? "127.0.0.1";
  const PORT = Number(process.env.PORT ?? "4337");

  const ANVIL_RPC = mustEnv("ANVIL_RPC");
  const ENTRYPOINTS = parseEntryPoints(mustEnv("ENTRYPOINTS"));
  const BENEFICIARY = normalizeAddr(mustHexEnv("BENEFICIARY"));
  const BUNDLER_KEY = mustHexEnv("BUNDLER_KEY");

  const provider = new ethers.JsonRpcProvider(ANVIL_RPC);
  const bundler = new ethers.Wallet(BUNDLER_KEY, provider);

  logInfo(`listening on http://${HOST}:${PORT}`);
  logInfo(`anvil rpc: ${ANVIL_RPC}`);
  logInfo(`allowed entrypoints: ${ENTRYPOINTS.join(", ")}`);
  logInfo(`beneficiary: ${BENEFICIARY}`);
  logInfo(`bundler: ${bundler.address}`);

  // In-memory store: userOpHash => StoredUO
  const store = new Map<string, StoredUO>();

  const server = http.createServer(async (req, res) => {
    try {
      // --- UX polish: correlation id + end-to-end structured finish log ---
      const requestId = (req.headers["x-request-id"] as string) || makeRequestId();
      const startMs = Date.now();
      res.setHeader("x-request-id", requestId);

      res.once("finish", () => {
        const durationMs = Date.now() - startMs;
        logJson({
          level: res.statusCode >= 400 ? "error" : "info",
          msg: "request.finish",
          requestId,
          method: req.method,
          path: req.url,
          statusCode: res.statusCode,
          durationMs,
          ts: nowIso(),
        });
      });

      // --- Human landing page for demos (doesn't touch JSON-RPC) ---
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>AA Gatekeeper</title>
  </head>
  <body style="font-family: system-ui, -apple-system, sans-serif; padding: 32px;">
    <h1>AA Gatekeeper (B2)</h1>
    <p>JSON-RPC endpoint for ERC-4337 bundling + Phase-1 deterministic classifier.</p>

    <h3>Status</h3>
    <ul>
      <li><a href="/health">GET /health</a></li>
    </ul>

    <h3>JSON-RPC endpoint</h3>
    <p><code>POST /</code></p>

    <h3>Methods</h3>
    <ul>
      <li><code>eth_supportedEntryPoints</code></li>
      <li><code>aa_about</code></li>
      <li><code>aa_classifyUserOperation</code></li>
      <li><code>eth_sendUserOperation</code></li>
      <li><code>eth_getUserOperationByHash</code></li>
      <li><code>eth_getUserOperationReceipt</code></li>
      <li><code>pimlico_getUserOperationStatus</code></li>
    </ul>

    <p style="margin-top:24px;color:#555">
      Every response includes <code>x-request-id</code>. Errors include <code>error.data.requestId</code>.
    </p>
  </body>
</html>`);
        return;
      }

      // --- Additive health endpoint for demos (HTML for browsers, JSON for machines) ---
if (req.method === "GET" && req.url === "/health") {
  const durationMs = Date.now() - startMs;
  const accept = String(req.headers["accept"] ?? "");
  const wantsHtml = accept.includes("text/html");

  if (wantsHtml) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Health — AA Gatekeeper</title>
  </head>
  <body style="font-family: system-ui, -apple-system, sans-serif; padding: 32px;">
    <h1>✅ Gatekeeper Healthy</h1>

    <table style="border-collapse: collapse; margin-top: 16px;">
      <tr><td style="padding:6px 12px;border:1px solid #ddd;">service</td><td style="padding:6px 12px;border:1px solid #ddd;">gatekeeper-b2</td></tr>
      <tr><td style="padding:6px 12px;border:1px solid #ddd;">version</td><td style="padding:6px 12px;border:1px solid #ddd;">phase1-bundle</td></tr>
      <tr><td style="padding:6px 12px;border:1px solid #ddd;">requestId</td><td style="padding:6px 12px;border:1px solid #ddd;"><code>${requestId}</code></td></tr>
      <tr><td style="padding:6px 12px;border:1px solid #ddd;">timestamp</td><td style="padding:6px 12px;border:1px solid #ddd;"><code>${nowIso()}</code></td></tr>
      <tr><td style="padding:6px 12px;border:1px solid #ddd;">durationMs</td><td style="padding:6px 12px;border:1px solid #ddd;"><code>${durationMs}</code></td></tr>
    </table>

    <p style="margin-top: 24px;"><a href="/">← Back to home</a></p>

    <p style="margin-top: 24px; color: #555;">
      Tip: use <code>curl -H 'accept: application/json' /health</code> for machine output.
    </p>
  </body>
</html>`);
    return;
  }

  // Default: JSON for machines / CLI
  res.writeHead(200, { "content-type": "application/json" });
  res.end(
    JSON.stringify(
      {
        ok: true,
        requestId,
        timestamp: nowIso(),
        durationMs,
        service: "gatekeeper-b2",
        version: "phase1-bundle",
      },
      null,
      2
    )
  );
  return;
}

      // Enforce JSON-RPC POST for all other routes
      if (req.method !== "POST") {
        res.writeHead(405, { "content-type": "application/json" });
        res.end(
          JSON.stringify(jsonRpcError(null, -32601, "POST only (JSON-RPC)", undefined, requestId))
        );
        return;
      }

      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.from(c));
      const body = Buffer.concat(chunks).toString("utf8");

      let rpc: RpcReq;
      try {
        rpc = JSON.parse(body);
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(
          JSON.stringify(jsonRpcError(null, -32700, "Parse error: invalid JSON", undefined, requestId))
        );
        return;
      }

      const id = rpc.id ?? null;
      const method = rpc.method;
      const params = rpc.params ?? [];

      // ---------- methods ----------

      if (method === "eth_supportedEntryPoints") {
        // (result is an array; keep it exactly as-is to avoid breaking clients)
        const reply = jsonRpcResult(id, ENTRYPOINTS);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      // Demo/info method (additive)
      if (method === "aa_about") {
        const reply = jsonRpcResult(id, {
          name: "gatekeeper-b2",
          version: "phase1-bundle",
          requestId,
          now: nowIso(),
          entryPoints: ENTRYPOINTS,
          bundler: bundler.address,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      /**
       * Classifier endpoint (Phase 1: bundle)
       * params: [{ userOp: <rpcUserOp>, entryPoint?: "0x..." }]
       * returns: ClassifierBundle
       */
      if (method === "aa_classifyUserOperation") {
        const p0 = params?.[0];
        const userOp = p0?.userOp ?? p0?.userOperation ?? p0;

        // Optional entryPoint for prefund check
        const epMaybe = p0?.entryPoint ? normalizeAddr(p0.entryPoint) : undefined;

        if (!userOp?.sender) {
          const reply = jsonRpcError(
            id,
            -32602,
            "Invalid params: expected { userOp } with sender",
            undefined,
            requestId
          );
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const bundle = await classifyUserOperationBundle({
          provider,
          entryPoint: epMaybe,
          userOp: {
            sender: userOp.sender,
            initCode: userOp.initCode ?? "0x",
            callData: userOp.callData ?? "0x",
            signature: userOp.signature ?? "0x",
            callGasLimit: userOp.callGasLimit ?? "0x0",
            verificationGasLimit: userOp.verificationGasLimit ?? "0x0",
            preVerificationGas: userOp.preVerificationGas ?? "0x0",
            maxFeePerGas: userOp.maxFeePerGas ?? "0x0",
            paymasterAndData: userOp.paymasterAndData ?? "0x",
          },
        });

        // Add requestId + duration to meta (safe, additive, demo-friendly)
        const bundleWithMeta: ClassifierBundle & { meta: any } = {
          ...bundle,
          meta: {
            ...bundle.meta,
            requestId,
            durationMs: Date.now() - startMs,
          },
        };

        const reply = jsonRpcResult(id, bundleWithMeta);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      if (method === "eth_sendUserOperation") {
        const [userOp, entryPoint] = params;

        if (!userOp || !entryPoint) {
          const reply = jsonRpcError(id, -32602, "Invalid params", undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const epAddr = normalizeAddr(entryPoint);
        if (!ENTRYPOINTS.map(lower).includes(lower(epAddr))) {
          const reply = jsonRpcError(id, -32602, `Unsupported entryPoint ${epAddr}`, undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        // Basic validation (avoid crashing later)
        const need = [
          "sender",
          "nonce",
          "initCode",
          "callData",
          "callGasLimit",
          "verificationGasLimit",
          "preVerificationGas",
          "maxFeePerGas",
          "maxPriorityFeePerGas",
          "paymasterAndData",
          "signature",
        ];
        for (const k of need) {
          if (userOp[k] == null) {
            const reply = jsonRpcError(id, -32602, `Missing userOp.${k}`, undefined, requestId);
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify(reply));
            return;
          }
        }

        // ---- Phase 1 enforcement: deterministic failure filter (bundle) ----
        const bundle = await classifyUserOperationBundle({
          provider,
          entryPoint: epAddr,
          userOp: {
            sender: userOp.sender,
            initCode: userOp.initCode ?? "0x",
            callData: userOp.callData ?? "0x",
            signature: userOp.signature ?? "0x",
            callGasLimit: userOp.callGasLimit ?? "0x0",
            verificationGasLimit: userOp.verificationGasLimit ?? "0x0",
            preVerificationGas: userOp.preVerificationGas ?? "0x0",
            maxFeePerGas: userOp.maxFeePerGas ?? "0x0",
            paymasterAndData: userOp.paymasterAndData ?? "0x",
          },
        });

        // Reject only on high severity deterministic signals
        if (shouldReject(bundle.signals)) {
          const top = bundle.signals.find((s) => s.severity === "high") ?? bundle.signals[0];

          // Preserve original bundle shape in data; jsonRpcError will merge requestId into error.data
          const data = {
            ...bundle,
            meta: { ...bundle.meta, durationMs: Date.now() - startMs },
          };

          const reply = jsonRpcError(id, -32602, `[${top.code}] ${top.summary}`, data, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        // Compute userOpHash on-chain (this matches what clients compute)
        const epForHash = new ethers.Contract(
          epAddr,
          [
            // IMPORTANT: named tuple components so ethers v6 accepts object values
            "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,bytes paymasterAndData,bytes signature) op) view returns (bytes32)",
          ],
          provider
        );

        const tuple = toEntryPointTuple(userOp);
        const userOpHash: string = await epForHash.getUserOpHash(tuple);

        // Store immediately
        store.set(lower(userOpHash), {
          userOperation: userOp,
          entryPoint: epAddr,
        });

        // Submit handleOps immediately (local)
        try {
          const ep = new ethers.Contract(epAddr, ENTRYPOINT_ABI, bundler);
          const tx = await ep.handleOps([tuple], BENEFICIARY);
          const rcpt = await tx.wait();

          const stored = store.get(lower(userOpHash));
          if (stored) {
            stored.transactionHash = rcpt?.hash ?? tx.hash;
            stored.blockHash = rcpt?.blockHash ?? undefined;
            stored.blockNumber =
              rcpt?.blockNumber != null ? ethers.toBeHex(rcpt.blockNumber) : undefined;

            // Decode UserOperationEvent for gas fields
            if (rcpt) {
              const decoded = decodeUserOpEventFromReceipt(rcpt, userOpHash, epAddr);
              if (decoded) {
                stored.success = decoded.success;
                stored.actualGasCost = decoded.actualGasCostHex;
                stored.actualGasUsed = decoded.actualGasUsedHex;
              }
            }
          }
        } catch (e: any) {
          const stored = store.get(lower(userOpHash));
          if (stored) stored.success = false;

          const msg = e?.shortMessage ?? e?.message ?? String(e);
          const reply = jsonRpcError(id, -32500, `handleOps failed: ${msg}`, undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const reply = jsonRpcResult(id, userOpHash);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      if (method === "eth_getUserOperationByHash") {
        const [userOpHash] = params;
        if (!isHexStr(userOpHash)) {
          const reply = jsonRpcError(id, -32602, "Invalid params", undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const stored = store.get(lower(userOpHash));
        if (!stored) {
          const reply = jsonRpcResult(id, null);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const result = {
          userOperation: stored.userOperation,
          entryPoint: stored.entryPoint,
          transactionHash: stored.transactionHash ?? null,
          blockHash: stored.blockHash ?? null,
          blockNumber: stored.blockNumber ?? null,
        };

        const reply = jsonRpcResult(id, result);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      if (method === "eth_getUserOperationReceipt") {
        const [userOpHash] = params;
        if (!isHexStr(userOpHash)) {
          const reply = jsonRpcError(id, -32602, "Invalid params", undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const stored = store.get(lower(userOpHash));
        if (!stored || !stored.transactionHash) {
          const reply = jsonRpcResult(id, null);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const result = {
          userOpHash,
          entryPoint: stored.entryPoint,
          sender: stored.userOperation.sender,
          nonce: stored.userOperation.nonce,
          paymaster: "0x0000000000000000000000000000000000000000",
          actualGasUsed: stored.actualGasUsed ?? null,
          actualGasCost: stored.actualGasCost ?? null,
          success: stored.success ?? null,
          receipt: {
            transactionHash: stored.transactionHash,
            blockHash: stored.blockHash ?? null,
            blockNumber: stored.blockNumber ?? null,
          },
        };

        const reply = jsonRpcResult(id, result);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      if (method === "pimlico_getUserOperationStatus") {
        const [userOpHash] = params;
        if (!isHexStr(userOpHash)) {
          const reply = jsonRpcError(id, -32602, "Invalid params", undefined, requestId);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const stored = store.get(lower(userOpHash));
        if (!stored) {
          const reply = jsonRpcResult(id, { status: "not_found", transactionHash: null });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        if (stored.transactionHash) {
          const reply = jsonRpcResult(id, { status: "included", transactionHash: stored.transactionHash });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
          return;
        }

        const reply = jsonRpcResult(id, { status: "submitted", transactionHash: null });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
        return;
      }

      // Unknown
      const reply = jsonRpcError(id, -32601, `Method not found: ${method}`, undefined, requestId);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(reply));
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      const reply = jsonRpcError(null, -32603, `Internal error: ${msg}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(reply));
    }
  });

  server.listen(PORT, HOST);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
