# handrail-sdk-rails

Rails/Rack helpers for Handrail project-owned operation endpoints.

## Installation

Add the gem from this repository, then require the SDK:

```ruby
require "handrail/sdk/rails"
```

The public API is exposed from `Handrail::SDK::Rails`:

- `verify_operation_invocation_signature(options)`
- `build_operation_success_envelope(result:, context:)`
- `build_operation_error_envelope(error:, context:)`

## Rails Controller Usage

Read the raw request body before parsing JSON, verify the Handrail signing
headers, then return a typed envelope.

```ruby
class Operations::BillingController < ApplicationController
  skip_before_action :verify_authenticity_token

  def refund
    raw_body = request.raw_post
    verification = Handrail::SDK::Rails.verify_operation_invocation_signature(
      method: request.method,
      path_and_query: request.original_fullpath,
      headers: request.headers.to_h,
      raw_body: raw_body,
      lookup_signing_key: lambda do |key_id, _context|
        OperationSigningCredential.find_by(key_id: key_id)
      end,
      expected: {
        project_id: ENV.fetch("HANDRAIL_PROJECT_ID"),
        environment: "production",
        tool_name: "billing.refund_invoice",
        tool_version: "1"
      }
    )

    unless verification[:ok]
      envelope = Handrail::SDK::Rails.build_operation_error_envelope(
        error: verification[:error].slice(:code, :category, :message, :retryable),
        context: verification[:context]
      )
      return render json: envelope, status: :unauthorized
    end

    payload = JSON.parse(raw_body)
    result = RefundInvoice.call(payload.fetch("input"), verification[:context])

    render json: Handrail::SDK::Rails.build_operation_success_envelope(
      result: result,
      context: verification[:context]
    )
  end
end
```

The lookup callback may return a secret string or a credential hash. Credential
hashes may include `signing_secret`, `enabled`, `status`, `expires_at`, and
scope fields such as `project_id`, `environment`, `tool_name`, and
`tool_version`.

## Rack Usage

```ruby
class OperationEndpoint
  def call(env)
    request = Rack::Request.new(env)
    raw_body = request.body.read
    request.body.rewind

    verification = Handrail::SDK::Rails.verify_operation_invocation_signature(
      method: request.request_method,
      path_and_query: request.fullpath,
      headers: env,
      raw_body: raw_body,
      signing_secret: ENV.fetch("HANDRAIL_OPERATION_SIGNING_SECRET"),
      expected: {
        project_id: ENV.fetch("HANDRAIL_PROJECT_ID"),
        environment: "production",
        tool_name: "billing.refund_invoice"
      }
    )

    return json(401, Handrail::SDK::Rails.build_operation_error_envelope(
      error: verification[:error].slice(:code, :category, :message, :retryable),
      context: verification[:context]
    )) unless verification[:ok]

    payload = JSON.parse(raw_body)
    result = RefundInvoice.call(payload.fetch("input"), verification[:context])
    json(200, Handrail::SDK::Rails.build_operation_success_envelope(result: result, context: verification[:context]))
  end

  private

  def json(status, envelope)
    [status, { "content-type" => "application/json" }, [JSON.generate(envelope)]]
  end
end
```

## Operation Signing Contract

Required headers:

- `X-Handrail-Project-Id`
- `X-Handrail-Environment`
- `X-Handrail-Tool-Name`
- `X-Handrail-Tool-Version`
- `X-Handrail-Invocation-Id`
- `X-Handrail-Request-Id`
- `X-Handrail-Audit-Id`
- `X-Handrail-Timestamp`
- `X-Handrail-Body-SHA256`
- `X-Handrail-Signature-Key-Id`
- `X-Handrail-Signature`
- `X-Handrail-Timeout-Ms`
- `X-Handrail-Dry-Run`

`Idempotency-Key` is optional. The canonical string uses an empty line when it
is absent.

The canonical HMAC input is joined by newlines in this exact order:

```text
HANDRAIL-OPERATION-V1
<METHOD>
<path-and-query>
<timestamp>
<project-id>
<environment>
<tool-name>
<tool-version>
<invocation-id>
<request-id>
<audit-id>
<dry-run true|false>
<idempotency-key or empty>
<body-sha256>
```

The signature header format is `v1,hmac-sha256,<base64url-hmac-sha256>`.
Verification errors intentionally omit signing secrets, raw signatures, and the
canonical string.
