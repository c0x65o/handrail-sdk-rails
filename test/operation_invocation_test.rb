# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "minitest/autorun"
require "openssl"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "handrail/sdk/rails"

class OperationInvocationTest < Minitest::Test
  SECRET = "hop_test_secret_123"
  NOW = "2026-06-11T14:45:00.000Z"

  def base_request(overrides = {})
    raw_body = JSON.generate(
      version: 1,
      input: { invoice_id: "inv_123" },
      context: {
        project_id: "project-uuid",
        environment: "production",
        tool_name: "billing.refund_invoice",
        tool_version: "1",
        invocation_id: "invocation-uuid",
        request_id: "request-uuid",
        audit_id: "audit-uuid",
        dry_run: false
      }
    )
    body_sha256 = Digest::SHA256.hexdigest(raw_body)
    headers = {
      "X-Handrail-Project-Id" => "project-uuid",
      "X-Handrail-Environment" => "production",
      "X-Handrail-Tool-Name" => "billing.refund_invoice",
      "X-Handrail-Tool-Version" => "1",
      "X-Handrail-Invocation-Id" => "invocation-uuid",
      "X-Handrail-Request-Id" => "request-uuid",
      "X-Handrail-Audit-Id" => "audit-uuid",
      "X-Handrail-Timestamp" => NOW,
      "X-Handrail-Body-SHA256" => body_sha256,
      "X-Handrail-Signature-Key-Id" => "hop_live_key_123",
      "X-Handrail-Timeout-Ms" => "30000",
      "X-Handrail-Dry-Run" => "false",
      "Idempotency-Key" => "hop:project-uuid:production:billing.refund_invoice:invocation-uuid"
    }.merge(overrides.fetch(:headers, {}))

    request = {
      method: overrides.fetch(:method, "post"),
      path_and_query: overrides.fetch(:path_and_query, "/operations/billing/refund?attempt=1"),
      raw_body: overrides.fetch(:raw_body, raw_body),
      headers: headers
    }
    request[:headers]["X-Handrail-Signature"] = sign_request(request.merge(secret: overrides.fetch(:secret, SECRET)))
    request[:headers].merge!(overrides[:after_sign_headers]) if overrides[:after_sign_headers]
    request[:raw_body] = overrides[:after_sign_raw_body] if overrides[:after_sign_raw_body]
    request
  end

  def sign_request(request)
    headers = request[:headers]
    get = lambda do |name|
      headers[name] || headers[name.downcase]
    end
    canonical = [
      "HANDRAIL-OPERATION-V1",
      request[:method].to_s.upcase,
      request[:path_and_query],
      get.call("X-Handrail-Timestamp"),
      get.call("X-Handrail-Project-Id"),
      get.call("X-Handrail-Environment"),
      get.call("X-Handrail-Tool-Name"),
      get.call("X-Handrail-Tool-Version"),
      get.call("X-Handrail-Invocation-Id"),
      get.call("X-Handrail-Request-Id"),
      get.call("X-Handrail-Audit-Id"),
      get.call("X-Handrail-Dry-Run"),
      get.call("Idempotency-Key") || "",
      get.call("X-Handrail-Body-SHA256")
    ].join("\n")
    signature = Base64.urlsafe_encode64(OpenSSL::HMAC.digest("SHA256", request[:secret], canonical), padding: false)
    "v1,hmac-sha256,#{signature}"
  end

  def verify(request, overrides = {})
    Handrail::SDK::Rails.verify_operation_invocation_signature(
      {
        now: NOW,
        signing_secret: SECRET,
        expected: {
          project_id: "project-uuid",
          environment: "production",
          tool_name: "billing.refund_invoice",
          tool_version: "1"
        }
      }.merge(request).merge(overrides)
    )
  end

  def test_verifies_valid_operation_invocation_signature_and_returns_safe_context
    request = base_request
    result = verify(request)

    assert_equal true, result[:ok]
    assert_equal "POST", result[:context][:method]
    assert_equal "/operations/billing/refund?attempt=1", result[:context][:path_and_query]
    assert_equal "project-uuid", result[:context][:project_id]
    assert_equal "production", result[:context][:environment]
    assert_equal "billing.refund_invoice", result[:context][:tool_name]
    assert_equal "1", result[:context][:tool_version]
    assert_equal "invocation-uuid", result[:context][:invocation_id]
    assert_equal "request-uuid", result[:context][:request_id]
    assert_equal "audit-uuid", result[:context][:audit_id]
    assert_equal "hop_live_key_123", result[:context][:signature_key_id]
    assert_equal false, result[:context][:dry_run]
    assert_equal "hop:project-uuid:production:billing.refund_invoice:invocation-uuid", result[:context][:idempotency_key]
    assert_match(/\A[a-f0-9]{64}\z/, result[:context][:body_sha256])
    refute_includes JSON.generate(result), SECRET
    refute_includes JSON.generate(result), "HANDRAIL-OPERATION-V1"
  end

  def test_looks_up_signing_keys_case_insensitively_and_accepts_scoped_credentials
    request = base_request
    request[:headers] = request[:headers].transform_keys(&:downcase)
    result = Handrail::SDK::Rails.verify_operation_invocation_signature(
      request.merge(
        now: NOW,
        lookup_signing_key: lambda do |key_id, context|
          assert_equal "hop_live_key_123", key_id
          assert_equal "billing.refund_invoice", context[:tool_name]
          {
            signing_secret: SECRET,
            enabled: true,
            expires_at: "2026-06-11T15:45:00.000Z",
            scope: {
              project_id: "project-uuid",
              environment: "production",
              tool_name: "billing.refund_invoice",
              tool_version: "1"
            }
          }
        end
      )
    )

    assert_equal true, result[:ok]
  end

  def test_rejects_invalid_signatures_without_exposing_signature_material
    request = base_request(
      after_sign_headers: {
        "X-Handrail-Signature" => "v1,hmac-sha256,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      }
    )
    result = verify(request)

    assert_equal false, result[:ok]
    assert_equal "operation_signature_invalid", result[:error][:code]
    assert_equal "auth", result[:error][:category]
    assert_equal "signature_mismatch", result[:error][:reason]
    serialized = JSON.generate(result)
    refute_includes serialized, SECRET
    refute_includes serialized, "HANDRAIL-OPERATION-V1"
    refute_includes serialized, request[:headers]["X-Handrail-Signature"]
  end

  def test_rejects_missing_required_handrail_headers
    request = base_request
    request[:headers].delete("X-Handrail-Audit-Id")
    result = verify(request)

    assert_equal false, result[:ok]
    assert_equal "missing_required_header", result[:error][:reason]
    assert_equal({ header: "x-handrail-audit-id" }, result[:error][:details])
  end

  def test_rejects_body_hash_mismatches_over_exact_raw_bytes
    request = base_request(after_sign_raw_body: '{"version":1,"input":{"invoice_id":"inv_999"}}')
    result = verify(request)

    assert_equal false, result[:ok]
    assert_equal "body_hash_mismatch", result[:error][:reason]
  end

  def test_rejects_stale_and_future_timestamps_outside_replay_window
    stale = base_request(headers: { "X-Handrail-Timestamp" => "2026-06-11T14:35:00.000Z" })
    future = base_request(headers: { "X-Handrail-Timestamp" => "2026-06-11T14:55:01.000Z" })

    assert_equal "timestamp_stale", verify(stale)[:error][:reason]
    assert_equal "timestamp_in_future", verify(future)[:error][:reason]
  end

  def test_rejects_unknown_disabled_and_expired_signing_keys_from_lookup_callbacks
    request = base_request
    unknown = Handrail::SDK::Rails.verify_operation_invocation_signature(request.merge(now: NOW, lookup_signing_key: ->(_key_id, _context) {}))
    assert_equal false, unknown[:ok]
    assert_equal "credential_unknown", unknown[:error][:reason]

    disabled = Handrail::SDK::Rails.verify_operation_invocation_signature(
      request.merge(now: NOW, lookup_signing_key: ->(_key_id, _context) { { signing_secret: SECRET, enabled: false } })
    )
    assert_equal "credential_disabled", disabled[:error][:reason]

    expired = Handrail::SDK::Rails.verify_operation_invocation_signature(
      request.merge(now: NOW, lookup_signing_key: ->(_key_id, _context) { { signing_secret: SECRET, expires_at: "2026-06-11T14:44:59.000Z" } })
    )
    assert_equal "credential_expired", expired[:error][:reason]
  end

  def test_rejects_endpoint_expected_scope_and_credential_scope_mismatches
    request = base_request
    expected_scope_mismatch = verify(
      request,
      expected: {
        project_id: "project-uuid",
        environment: "staging",
        tool_name: "billing.refund_invoice"
      }
    )
    assert_equal false, expected_scope_mismatch[:ok]
    assert_equal "operation_scope_forbidden", expected_scope_mismatch[:error][:code]
    assert_equal "scope_mismatch", expected_scope_mismatch[:error][:reason]
    assert_equal({ mismatches: ["environment"] }, expected_scope_mismatch[:error][:details])

    credential_scope_mismatch = Handrail::SDK::Rails.verify_operation_invocation_signature(
      request.merge(
        now: NOW,
        lookup_signing_key: ->(_key_id, _context) { { signing_secret: SECRET, project_id: "project-uuid", environment: "production", tool_name: "billing.void_invoice" } }
      )
    )
    assert_equal false, credential_scope_mismatch[:ok]
    assert_equal "operation_scope_forbidden", credential_scope_mismatch[:error][:code]
    assert_equal "credential_scope_mismatch", credential_scope_mismatch[:error][:reason]
  end

  def test_allows_missing_idempotency_key_by_signing_empty_canonical_line
    request = base_request
    request[:headers].delete("Idempotency-Key")
    request[:headers]["X-Handrail-Signature"] = sign_request(request.merge(secret: SECRET))

    result = verify(request)

    assert_equal true, result[:ok]
    assert_nil result[:context][:idempotency_key]
  end

  def test_builds_success_and_error_envelopes_with_audit_echo_and_bounded_safe_details
    context = {
      invocation_id: "invocation-uuid",
      audit_id: "audit-uuid",
      request_id: "request-uuid",
      idempotency_key: "hop:project-uuid:production:billing.refund_invoice:invocation-uuid",
      dry_run: true
    }

    success = Handrail::SDK::Rails.build_operation_success_envelope(
      result: {
        version: 1,
        status: "completed",
        summary: "Refund queued"
      },
      context: context
    )
    assert_equal(
      {
        ok: true,
        result: {
          version: 1,
          status: "completed",
          summary: "Refund queued"
        },
        audit: {
          invocation_id: "invocation-uuid",
          audit_id: "audit-uuid",
          request_id: "request-uuid",
          idempotency_key: "hop:project-uuid:production:billing.refund_invoice:invocation-uuid",
          dry_run: true
        }
      },
      success
    )

    error = Handrail::SDK::Rails.build_operation_error_envelope(
      error: {
        code: "idempotency_conflict",
        category: "conflict",
        message: "The idempotency key was already used for a different request.",
        retryable: false,
        details: {
          safe_reason: "request_hash_mismatch",
          token: "secret-token",
          nested: {
            signature: "raw-signature"
          }
        }
      },
      context: context
    )
    assert_equal false, error[:ok]
    assert_equal "idempotency_conflict", error[:error][:code]
    assert_equal "conflict", error[:error][:category]
    assert_equal false, error[:error][:retryable]
    assert_equal(
      {
        safe_reason: "request_hash_mismatch",
        token: "[REDACTED]",
        nested: {
          signature: "[REDACTED]"
        }
      },
      error[:error][:details]
    )
    assert_equal true, error[:audit][:dry_run]

    assert_raises(TypeError) do
      Handrail::SDK::Rails.build_operation_error_envelope(code: "BadCode", category: "validation", message: "bad", retryable: false, context: context)
    end
    assert_raises(TypeError) do
      Handrail::SDK::Rails.build_operation_error_envelope(code: "operation_failed", category: "not_allowed", message: "bad", retryable: false, context: context)
    end
    assert_raises(TypeError) do
      Handrail::SDK::Rails.build_operation_error_envelope(code: "operation_failed", category: "application", message: "bad", context: context)
    end
  end
end
