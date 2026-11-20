// Minimal excerpt (class declaration/heritage + field list + the
// handleRequest method's own signature and opening body) reproduced under
// the MIT License from modelcontextprotocol/typescript-sdk,
// src/server/webStandardStreamableHttp.ts, commit
// ced75351af16850ea82fca478b921abc4a5385e4
// (https://github.com/modelcontextprotocol/typescript-sdk).
// Copyright (c) 2024 Anthropic, PBC. MIT License.
//
// Reproduced here as a real-world regression fixture for mcp-safeguard's
// entrypoints_js.py shape I, `interface_method_override_entries` (see
// bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md). This is the real
// CVE-2026-25536 shape: `WebStandardStreamableHTTPServerTransport` implements
// the SDK's own `Transport` interface and dispatches through `handleRequest`
// -- it is never registered via `registerTool`/`.tool()`/`setRequestHandler`
// (shapes A-H have no vocabulary for it), so before this fix the class was
// never recovered as an MCP entrypoint at all.

export class WebStandardStreamableHTTPServerTransport implements Transport {
    private sessionIdGenerator: (() => string) | undefined;
    private _started: boolean = false;
    private _streamMapping: Map<string, StreamMapping> = new Map();
    private _requestToStreamMapping: Map<RequestId, string> = new Map();
    private _initialized: boolean = false;
    private _allowedHosts?: string[];
    private _allowedOrigins?: string[];

    sessionId?: string;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage, extra?: MessageExtraInfo) => void;

    constructor(options: WebStandardStreamableHTTPServerTransportOptions = {}) {
        this.sessionIdGenerator = options.sessionIdGenerator;
        this._allowedHosts = options.allowedHosts;
        this._allowedOrigins = options.allowedOrigins;
    }

    async handleRequest(req: Request, options?: HandleRequestOptions): Promise<Response> {
        // Validate request headers for DNS rebinding protection
        const validationError = this.validateRequestHeaders(req);
        if (validationError) {
            return validationError;
        }

        switch (req.method) {
            case 'POST':
                return this.handlePostRequest(req, options);
            case 'GET':
                return this.handleGetRequest(req);
            case 'DELETE':
                return this.handleDeleteRequest(req);
            default:
                return new Response('Method not allowed', { status: 405 });
        }
    }
}
