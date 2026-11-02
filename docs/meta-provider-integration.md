# Meta Provider Integration (Stage 4, Part 4)

`src/cloudops_agent/meta_provider.py` coordinates one investigation request. It
accepts the existing `BuiltInvestigationInput` produced by
`build_investigation_input()`; it does not rebuild, widen, or redact that context.
Only `payload` is serialized to the provider. Request-local reference maps remain
in application memory and are passed only to `validate_investigation_output()`.

The boundary is:

1. `investigation_input.py` builds a scoped, allowlisted, redacted payload and
request-scoped opaque references.
2. `meta_provider.py` adds the fixed developer instructions, sends the structured
   payload through the injected client, extracts text, and invokes the output
   validator.
3. `investigation_output.py` parses and validates output structure, uncertainty,
   and citation scope. It returns an `InvestigationOutput`; raw model text is never
   returned as a successful result.

## Provider configuration

`DEFAULT_META_CONFIG` centralizes provider name, model ID, mode, endpoint, and the
credential environment variable. Muse Spark Standard mode is selected by the model
ID `muse-spark-1.3`; no separate mode parameter is sent. The live adapter follows
Meta's [Chat Completions quickstart](https://dev.meta.ai/docs/cookbook/quickstart-chat-completions)
and [structured output documentation](https://dev.meta.ai/docs/cookbook/structured-output)
using the OpenAI-compatible Python SDK, base URL `https://api.meta.ai/v1`, and a
strict JSON Schema response format. The schema comes from
`investigation_output_json_schema()` beside the existing validator. The validator
remains mandatory because constrained generation does not check request-scoped
citations or semantic support.

The SDK is imported only when `create_live_meta_client()` is called. It reads
`MODEL_API_KEY` from the environment unless an explicit key is injected. Missing
credentials fail before a request. SDK automatic retries are disabled. No real
request is made at construction time. Never place a real key in source, tests, or
documentation.

## Offline tests and live status

`FakeMetaClient` requires no key, SDK, internet connection, or API credit. It
records model/messages/response-format parameters and can return a configured
response or raise a configured exception. It is used only when explicitly
injected; provider failures never fall back to it. Fake output is test data and
must not be presented as a real model investigation.

The real request path has not been verified with a successful API request. Local
tests prove only request construction, extraction, safe failure handling, and the
existing deterministic output validation boundary. Live behavior, account
availability, and actual constrained-output compatibility remain unverified until
an authorized request succeeds.

Meta designates `muse-spark-1.3` as Standard mode and states that Standard mode
content is not used to train Meta models ([model availability and modes](https://dev.meta.ai/docs/models)).
This is a provider data-handling statement, not a claim that requests remain local
or that the input is not transmitted to Meta. The allowlisted investigation input
still leaves the application when a live client is explicitly used.

There is no investigation UI, AWS integration, tool calling, retry loop, or
automatic remediation in this stage.
