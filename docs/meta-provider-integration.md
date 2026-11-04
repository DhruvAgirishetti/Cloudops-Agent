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
3. `investigation_output.py` parses and validates the output against the output
   contract, including uncertainty fields and citation references against the
   request-local reference map. It returns an `InvestigationOutput`; raw model
   text is never returned as a successful result. Citation validation establishes
   reference scope and existence, not whether a cited item semantically supports
   the associated claim.

## Provider configuration

`DEFAULT_META_CONFIG` centralizes provider name, model ID, mode, endpoint, and the
credential environment variable. Muse Spark Standard mode is selected by the model
ID `muse-spark-1.3`; no separate mode parameter is sent. The live adapter follows
Meta's [Chat Completions quickstart](https://dev.meta.ai/docs/cookbook/quickstart-chat-completions)
and [structured output documentation](https://dev.meta.ai/docs/cookbook/structured-output)
using the OpenAI-compatible Python SDK, base URL `https://api.meta.ai/v1`, and a
strict JSON Schema response format. The schema comes from
`investigation_output_json_schema()` beside the existing validator. The validator
remains mandatory because constrained generation alone does not validate the
application's request-scoped citation references or output contract. Neither the
schema nor citation validation establishes the semantic correctness of claims.

Each request uses `max_completion_tokens=4096`. The provider accepts a response
only when it contains exactly one choice, the finish reason is `stop`, the message
is not a refusal, and its content is text. Empty, malformed, refused, non-text,
or non-stop responses are rejected; in particular, a `length` finish reason is
not treated as a complete result. Response text must parse and pass
`validate_investigation_output()` against the exact request-local references
before an `InvestigationOutput` is returned. The application does not display
unvalidated raw response text.

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

The live Meta integration has successfully completed an investigation using
Muse Spark 1.3 Standard mode. The request goes through the OpenAI-compatible SDK
to Meta Chat Completions using the configured model, developer and scoped user
messages, the 4096-token completion ceiling, and strict JSON Schema response
format described above. A successful request confirms that this path worked for
that investigation; provider availability and successful completion are not
guaranteed for later requests. The offline `FakeMetaClient` tests still cover
request construction, response extraction, safe failure handling, and output
validation without making API calls.

Meta designates `muse-spark-1.3` as Standard mode and states that Standard mode
content is not used to train Meta models ([model availability and modes](https://dev.meta.ai/docs/models)).
This is a provider data-handling statement, not a claim that requests remain local
or that the input is not transmitted to Meta. The allowlisted investigation input
still leaves the application when a live client is explicitly used.

## Streamlit investigation workflow

The Streamlit dashboard offers an explicit **Investigate with AI** action for an
individual current finding and **Investigate correlation with AI** for a current
correlation. After a successful result is cached for that exact scope, the
corresponding control is labeled **Re-investigate** (or **Re-investigate
correlation with AI**). Re-investigation is a deliberate button action. Ordinary
Streamlit reruns display the cached validated result and do not issue another
provider request. A failed re-investigation preserves and continues to display
the previous successful validated result with an error notice; failed initial
investigations are shown as errors and are not cached as successful output.

The dashboard presents the validated report with citations, uncertainty,
limitations, and provider-reported aggregate token counts when available. Its
disclaimer states that recommendations are advisory, are never automatically
executed, and are neither applied nor verified by CloudOps Agent. Citation checks
establish reference scope and existence, not semantic correctness. The provider
does not call tools or AWS, and the application does not automatically remediate
findings. There is no AWS integration or execution of uploaded files.
