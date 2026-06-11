# frozen_string_literal: true

require "base64"
require "digest"
require "openssl"
require "time"

require_relative "rails/version"

module Handrail
  module SDK
    module Rails
      OPERATION_REPLAY_WINDOW_SECONDS = 300
      OPERATION_MAX_DETAILS_DEPTH = 4
      OPERATION_MAX_DETAILS_KEYS = 50
      OPERATION_MAX_DETAILS_ARRAY_ITEMS = 20
      OPERATION_MAX_DETAILS_STRING_LENGTH = 1000
      OPERATION_MAX_TAG_KEY_LENGTH = 80
      OPERATION_REDACTED = "[REDACTED]"
      TRUNCATED = "[Truncated]"
      SENSITIVE_KEY_PATTERN = /(?:authorization|cookie|password|passwd|secret|token|signature|hmac|api[-_]?key|access[-_]?key|session|credential|private[-_]?key)/i
      OPERATION_ERROR_CATEGORIES = %w[
        auth
        validation
        approval
        conflict
        rate_limit
        timeout
        dependency
        application
        unknown
      ].freeze
      OPERATION_REQUIRED_HEADERS = %w[
        x-handrail-project-id
        x-handrail-environment
        x-handrail-tool-name
        x-handrail-tool-version
        x-handrail-invocation-id
        x-handrail-request-id
        x-handrail-audit-id
        x-handrail-timestamp
        x-handrail-body-sha256
        x-handrail-signature-key-id
        x-handrail-signature
        x-handrail-timeout-ms
        x-handrail-dry-run
      ].freeze

      class << self
        def verify_operation_invocation_signature(options = {})
          headers = normalize_operation_headers(value_at(options, :headers))
          missing_header = OPERATION_REQUIRED_HEADERS.find { |header| blank?(headers[header]) }
          if missing_header
            return operation_verification_error("missing_required_header",
                                                message: "A required Handrail operation signing header is missing.",
                                                details: { header: missing_header })
          end

          method = value_at(options, :method).to_s.strip.upcase
          if method.empty?
            return operation_verification_error("missing_method", message: "The HTTP method is required.")
          end

          path_and_query = normalize_operation_path_and_query(options)
          if path_and_query.empty?
            return operation_verification_error("missing_path_and_query",
                                                message: "The request path and query string are required.")
          end

          dry_run_header = headers["x-handrail-dry-run"]
          unless %w[true false].include?(dry_run_header)
            return operation_verification_error("invalid_dry_run_header",
                                                message: "The Handrail dry-run header must be true or false.")
          end

          body = normalize_operation_raw_body(options)
          body_sha256 = Digest::SHA256.hexdigest(body)
          unless secure_compare(body_sha256, headers["x-handrail-body-sha256"])
            return operation_verification_error("body_hash_mismatch",
                                                message: "The Handrail operation request body hash does not match.")
          end

          timestamp = parse_time(headers["x-handrail-timestamp"])
          unless timestamp
            return operation_verification_error("invalid_timestamp",
                                                message: "The Handrail operation timestamp is invalid.")
          end

          now = operation_now(options)
          replay_window_seconds = numeric_option(options, :replay_window_seconds, :replayWindowSeconds,
                                                 :tolerance_seconds, :toleranceSeconds) ||
                                  OPERATION_REPLAY_WINDOW_SECONDS
          if ((now.to_f - timestamp.to_f).abs > replay_window_seconds.to_f)
            return operation_verification_error(timestamp < now ? "timestamp_stale" : "timestamp_in_future",
                                                message: "The Handrail operation timestamp is outside the allowed replay window.")
          end

          parsed_signature = parse_operation_signature(headers["x-handrail-signature"])
          unless parsed_signature
            return operation_verification_error("signature_malformed",
                                                message: "The Handrail operation signature is malformed.")
          end

          context = build_operation_verification_context(
            method: method,
            path_and_query: path_and_query,
            headers: headers,
            body_sha256: body_sha256,
            timestamp: timestamp
          )

          expected_scope = validate_expected_operation_scope(context, value_at(options, :expected) || value_at(options, :scope) || options)
          unless expected_scope[:ok]
            return operation_verification_error("scope_mismatch",
                                                { code: "operation_scope_forbidden",
                                                  message: "The Handrail operation request is outside the expected endpoint scope.",
                                                  details: expected_scope[:details] },
                                                context)
          end

          credential_result = resolve_operation_signing_credential(headers["x-handrail-signature-key-id"], context, options)
          unless credential_result[:ok]
            return operation_verification_error(credential_result[:reason],
                                                { code: credential_result[:code] || "operation_signature_invalid",
                                                  message: credential_result[:message] || "The Handrail operation credential could not be used.",
                                                  details: credential_result[:details] },
                                                context)
          end

          credential_scope = validate_credential_operation_scope(context, credential_result[:credential])
          unless credential_scope[:ok]
            return operation_verification_error("credential_scope_mismatch",
                                                { code: "operation_scope_forbidden",
                                                  message: "The Handrail operation credential is outside the request scope.",
                                                  details: credential_scope[:details] },
                                                context)
          end

          expected_signature = operation_hmac_signature(credential_result[:secret], build_operation_canonical_string(context))
          unless secure_compare(expected_signature, parsed_signature[:value])
            return operation_verification_error("signature_mismatch",
                                                { message: "The Handrail operation signature is invalid." },
                                                context)
          end

          { ok: true, context: context }
        end

        def build_operation_success_envelope(input = {})
          result = value_at(input, :result)
          result = {} if result.nil?
          unless result.is_a?(Hash)
            raise TypeError, "Operation success result must be a JSON object."
          end

          {
            ok: true,
            result: result,
            audit: build_operation_audit_echo(input)
          }
        end

        def build_operation_error_envelope(input = {})
          error = value_at(input, :error)
          error = input unless error.is_a?(Hash)

          code = sanitize_operation_error_code(value_at(error, :code))
          category = sanitize_operation_error_category(value_at(error, :category))
          message = sanitize_operation_error_message(value_at(error, :message))
          retryable = value_at(error, :retryable)

          raise TypeError, "Operation error code must be lower snake case." if code.empty?
          if category.empty?
            raise TypeError, "Operation error category must be one of #{OPERATION_ERROR_CATEGORIES.join(", ")}."
          end
          raise TypeError, "Operation error message is required." if message.empty?
          raise TypeError, "Operation error retryable must be a boolean." unless retryable == true || retryable == false

          envelope_error = {
            code: code,
            category: category,
            message: message,
            retryable: retryable
          }

          details = sanitize_operation_details(value_at(error, :details))
          envelope_error[:details] = details unless details.nil?

          {
            ok: false,
            error: envelope_error,
            audit: build_operation_audit_echo(input)
          }
        end

        private

        def normalize_operation_headers(headers)
          normalized = {}
          return normalized unless headers.respond_to?(:each)

          headers.each do |raw_name, raw_value|
            name = normalize_header_name(raw_name)
            next if name.empty?

            value = raw_value.is_a?(Array) ? raw_value.join(", ") : raw_value
            normalized[name] = trim_ascii_whitespace(value)
          end

          normalized
        end

        def normalize_header_name(name)
          value = name.to_s.strip
          return "" if value.empty?

          if value.start_with?("HTTP_")
            value = value.delete_prefix("HTTP_").tr("_", "-")
          else
            value = value.tr("_", "-")
          end

          value.downcase
        end

        def normalize_operation_raw_body(options)
          body = first_defined(options, :raw_body, :rawBody, :body)
          return "".b if body.nil?
          return body.b if body.is_a?(String)
          return body.read.b if body.respond_to?(:read)

          body.to_s.b
        end

        def normalize_operation_path_and_query(options)
          value = first_defined(options, :path_and_query, :pathAndQuery, :path, :url, :original_url, :originalUrl)
          return "" if value.nil?

          path = value.to_s
          path.start_with?("/") ? path : ""
        end

        def operation_now(options)
          clock = first_defined(options, :now, :clock)
          raw_now = clock.respond_to?(:call) ? clock.call : clock
          parsed = parse_time(raw_now)
          parsed || Time.now
        end

        def parse_time(value)
          return value if value.is_a?(Time)
          return Time.at(value) if value.is_a?(Numeric)
          return nil if value.nil? || value.to_s.empty?

          Time.parse(value.to_s)
        rescue ArgumentError
          nil
        end

        def build_operation_verification_context(method:, path_and_query:, headers:, body_sha256:, timestamp:)
          {
            method: method,
            path_and_query: path_and_query,
            timestamp: headers["x-handrail-timestamp"],
            timestamp_ms: (timestamp.to_f * 1000).to_i,
            project_id: headers["x-handrail-project-id"],
            environment: headers["x-handrail-environment"],
            tool_name: headers["x-handrail-tool-name"],
            tool_version: headers["x-handrail-tool-version"],
            invocation_id: headers["x-handrail-invocation-id"],
            request_id: headers["x-handrail-request-id"],
            audit_id: headers["x-handrail-audit-id"],
            signature_key_id: headers["x-handrail-signature-key-id"],
            timeout_ms: integer_or_nil(headers["x-handrail-timeout-ms"]),
            dry_run: headers["x-handrail-dry-run"] == "true",
            idempotency_key: presence(headers["idempotency-key"]),
            body_sha256: body_sha256,
            approval_id: presence(headers["x-handrail-approval-id"]),
            actor: build_operation_actor(headers),
            trace_id: presence(headers["x-handrail-trace-id"]),
            correlation_id: presence(headers["x-handrail-correlation-id"]),
            work_request_id: presence(headers["x-handrail-work-request-id"]),
            owner_goal_id: presence(headers["x-handrail-owner-goal-id"])
          }
        end

        def build_operation_actor(headers)
          type = presence(headers["x-handrail-actor-type"])
          id = presence(headers["x-handrail-actor-id"])
          display = presence(headers["x-handrail-actor-display"])
          return nil unless type || id || display

          { type: type, id: id, display: display }
        end

        def build_operation_canonical_string(context)
          [
            "HANDRAIL-OPERATION-V1",
            context[:method],
            context[:path_and_query],
            context[:timestamp],
            context[:project_id],
            context[:environment],
            context[:tool_name],
            context[:tool_version],
            context[:invocation_id],
            context[:request_id],
            context[:audit_id],
            context[:dry_run] ? "true" : "false",
            context[:idempotency_key] || "",
            context[:body_sha256]
          ].join("\n")
        end

        def parse_operation_signature(signature_header)
          parts = signature_header.to_s.split(",")
          return nil unless parts.length == 3 && parts[0] == "v1" && parts[1] == "hmac-sha256"
          return nil unless parts[2].match?(/\A[A-Za-z0-9_-]+\z/)

          { value: parts[2] }
        end

        def resolve_operation_signing_credential(key_id, context, options)
          direct_secret = first_defined(options, :signing_secret, :signingSecret, :secret)
          if direct_secret
            return {
              ok: true,
              secret: direct_secret,
              credential: value_at(options, :credential)
            }
          end

          lookup = first_defined(options, :lookup_signing_key, :lookupSigningKey, :key_lookup, :keyLookup, :get_signing_key, :getSigningKey)
          unless lookup.respond_to?(:call)
            return {
              ok: false,
              reason: "signing_secret_missing",
              message: "No Handrail operation signing secret or key lookup callback was provided."
            }
          end

          lookup_context = {
            project_id: context[:project_id],
            environment: context[:environment],
            tool_name: context[:tool_name],
            tool_version: context[:tool_version],
            signature_key_id: key_id
          }
          credential = lookup.arity == 1 ? lookup.call(key_id) : lookup.call(key_id, lookup_context)

          if credential.nil? || credential == false
            return {
              ok: false,
              reason: "credential_unknown",
              message: "The Handrail operation signing key is unknown.",
              details: { key_id: key_id }
            }
          end

          return { ok: true, secret: credential, credential: nil } if credential.is_a?(String)

          status = value_at(credential, :status, :state).to_s.strip.downcase
          if status == "unknown"
            return credential_rejection("credential_unknown", "The Handrail operation signing key is unknown.", key_id)
          end
          if status == "disabled" || value_at(credential, :disabled) == true || value_at(credential, :enabled) == false
            return credential_rejection("credential_disabled", "The Handrail operation signing key is disabled.", key_id)
          end
          if status == "expired" || value_at(credential, :expired) == true || operation_credential_expired?(credential, operation_now(options))
            return credential_rejection("credential_expired", "The Handrail operation signing key is expired.", key_id)
          end

          secret = first_defined(credential, :signing_secret, :signingSecret, :secret, :key)
          unless secret
            return {
              ok: false,
              reason: "credential_secret_missing",
              message: "The Handrail operation signing credential does not include a usable secret."
            }
          end

          { ok: true, secret: secret, credential: credential }
        end

        def credential_rejection(reason, message, key_id)
          {
            ok: false,
            reason: reason,
            message: message,
            details: { key_id: key_id }
          }
        end

        def operation_credential_expired?(credential, now)
          expires_at = first_defined(credential, :expires_at, :expiresAt, :expiry, :expired_at, :expiredAt)
          parsed = parse_time(expires_at)
          parsed && parsed <= now
        end

        def validate_expected_operation_scope(context, expected)
          validate_operation_scope(context, normalize_expected_operation_scope(expected))
        end

        def validate_credential_operation_scope(context, credential)
          return { ok: true } unless credential.is_a?(Hash)

          credential_scope = value_at(credential, :scope)
          credential_scopes = value_at(credential, :scopes)
          scope = {}
          scope.merge!(credential_scope) if credential_scope.is_a?(Hash)
          scope.merge!(credential_scopes) if credential_scopes.is_a?(Hash)
          scope[:project_id] = first_defined(credential, :project_id, :projectId, :project, :projectID) ||
                               first_defined(scope, :project_id, :projectId)
          scope[:environment] = first_defined(credential, :environment, :env) ||
                                first_defined(scope, :environment, :env)
          scope[:tool_name] = first_defined(credential, :tool_name, :toolName) ||
                              first_defined(scope, :tool_name, :toolName)
          scope[:tool_version] = first_defined(credential, :tool_version, :toolVersion) ||
                                 first_defined(scope, :tool_version, :toolVersion)

          validate_operation_scope(context, scope)
        end

        def normalize_expected_operation_scope(expected)
          return {} unless expected.is_a?(Hash)

          {
            project_id: first_defined(expected, :project_id, :projectId, :expected_project_id, :expectedProjectId),
            environment: first_defined(expected, :environment, :env, :expected_environment, :expectedEnvironment),
            tool_name: first_defined(expected, :tool_name, :toolName, :expected_tool_name, :expectedToolName),
            tool_version: first_defined(expected, :tool_version, :toolVersion, :expected_tool_version, :expectedToolVersion)
          }
        end

        def validate_operation_scope(context, scope)
          mismatches = []
          mismatches << "project_id" unless operation_scope_value_matches?(scope[:project_id], context[:project_id])
          mismatches << "environment" unless operation_scope_value_matches?(scope[:environment], context[:environment])
          mismatches << "tool_name" unless operation_scope_value_matches?(scope[:tool_name], context[:tool_name])
          if !blank?(scope[:tool_version]) && !operation_scope_value_matches?(scope[:tool_version], context[:tool_version])
            mismatches << "tool_version"
          end

          mismatches.empty? ? { ok: true } : { ok: false, details: { mismatches: mismatches } }
        end

        def operation_scope_value_matches?(expected, actual)
          return true if blank?(expected)
          return expected.map(&:to_s).include?(actual.to_s) if expected.is_a?(Array)

          expected.to_s == actual.to_s
        end

        def operation_verification_error(reason, overrides = {}, context = nil)
          result = {
            ok: false,
            error: {
              code: overrides[:code] || "operation_signature_invalid",
              category: overrides[:category] || "auth",
              message: overrides[:message] || "The Handrail operation signature is invalid.",
              retryable: false,
              reason: reason
            }
          }
          result[:error][:details] = sanitize_operation_details(overrides[:details]) if overrides.key?(:details)
          result[:context] = operation_safe_context(context) if context
          result
        end

        def operation_safe_context(context)
          {
            method: context[:method],
            path_and_query: context[:path_and_query],
            project_id: context[:project_id],
            environment: context[:environment],
            tool_name: context[:tool_name],
            tool_version: context[:tool_version],
            invocation_id: context[:invocation_id],
            request_id: context[:request_id],
            audit_id: context[:audit_id],
            signature_key_id: context[:signature_key_id],
            dry_run: context[:dry_run],
            idempotency_key: context[:idempotency_key],
            body_sha256: context[:body_sha256]
          }
        end

        def build_operation_audit_echo(input = {})
          context = operation_context_from_input(input)
          audit = value_at(input, :audit)
          audit = {} unless audit.is_a?(Hash)

          echo = {
            invocation_id: first_defined(audit, :invocation_id, :invocationId) ||
                           first_defined(input, :invocation_id, :invocationId) ||
                           first_defined(context, :invocation_id, :invocationId),
            audit_id: first_defined(audit, :audit_id, :auditId) ||
                      first_defined(input, :audit_id, :auditId) ||
                      first_defined(context, :audit_id, :auditId),
            request_id: first_defined(audit, :request_id, :requestId) ||
                        first_defined(input, :request_id, :requestId) ||
                        first_defined(context, :request_id, :requestId),
            idempotency_key: first_defined(audit, :idempotency_key, :idempotencyKey) ||
                             first_defined(input, :idempotency_key, :idempotencyKey) ||
                             first_defined(context, :idempotency_key, :idempotencyKey),
            dry_run: !!(first_defined(audit, :dry_run, :dryRun) ||
                        first_defined(input, :dry_run, :dryRun) ||
                        first_defined(context, :dry_run, :dryRun) ||
                        false)
          }

          endpoint_audit_id = first_defined(audit, :endpoint_audit_id, :endpointAuditId) ||
                              first_defined(input, :endpoint_audit_id, :endpointAuditId)
          echo[:endpoint_audit_id] = endpoint_audit_id.to_s if endpoint_audit_id
          echo
        end

        def operation_context_from_input(input = {})
          context = value_at(input, :context)
          return context if context.is_a?(Hash)

          verified_context = value_at(input, :verified_context, :verifiedContext)
          return verified_context if verified_context.is_a?(Hash)

          verification = value_at(input, :verification)
          verification_context = value_at(verification, :context) if verification.is_a?(Hash)
          verification_context.is_a?(Hash) ? verification_context : {}
        end

        def sanitize_operation_error_code(code)
          value = code.to_s.strip
          value.match?(/\A[a-z][a-z0-9_]{0,127}\z/) ? value : ""
        end

        def sanitize_operation_error_category(category)
          value = category.to_s.strip
          OPERATION_ERROR_CATEGORIES.include?(value) ? value : ""
        end

        def sanitize_operation_error_message(message)
          value = message.to_s.strip
          return "" if value.empty?

          value[0, OPERATION_MAX_DETAILS_STRING_LENGTH]
        end

        def sanitize_operation_details(value, depth = 0, seen = {})
          return nil if value.nil?
          return value[0, OPERATION_MAX_DETAILS_STRING_LENGTH] if value.is_a?(String)
          return value if value == true || value == false
          return value.finite? ? value : nil if value.is_a?(Numeric)

          if value.is_a?(Array)
            return TRUNCATED if depth >= OPERATION_MAX_DETAILS_DEPTH

            return value.first(OPERATION_MAX_DETAILS_ARRAY_ITEMS)
                        .map { |item| sanitize_operation_details(item, depth + 1, seen) }
                        .compact
          end

          return nil unless value.is_a?(Hash)
          return TRUNCATED if seen[value.object_id]
          return TRUNCATED if depth >= OPERATION_MAX_DETAILS_DEPTH

          seen[value.object_id] = true
          output = {}
          value.to_a.first(OPERATION_MAX_DETAILS_KEYS).each do |raw_key, raw_value|
            key = sanitize_operation_detail_key(raw_key)
            next if key.empty?

            sanitized = if key.match?(SENSITIVE_KEY_PATTERN)
                          OPERATION_REDACTED
                        else
                          sanitize_operation_details(raw_value, depth + 1, seen)
                        end
            output[key.to_sym] = sanitized unless sanitized.nil?
          end
          output
        ensure
          seen.delete(value.object_id) if value.is_a?(Hash)
        end

        def sanitize_operation_detail_key(key)
          key.to_s.strip.gsub(/[^\w.\/:-]+/, "_")[0, OPERATION_MAX_TAG_KEY_LENGTH].to_s
        end

        def operation_hmac_signature(secret, canonical_string)
          digest = OpenSSL::HMAC.digest("SHA256", secret.to_s, canonical_string)
          Base64.urlsafe_encode64(digest, padding: false)
        end

        def secure_compare(left, right)
          left = left.to_s
          right = right.to_s
          return false unless left.bytesize == right.bytesize

          result = 0
          left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
          result.zero?
        end

        def trim_ascii_whitespace(value)
          value.to_s.gsub(/\A[\t\n\f\r ]+|[\t\n\f\r ]+\z/, "")
        end

        def first_defined(hash, *keys)
          keys.each do |key|
            value = value_at(hash, key)
            return value unless value.nil?
          end
          nil
        end

        def value_at(hash, *keys)
          return nil unless hash.respond_to?(:key?)

          keys.each do |key|
            return hash[key] if hash.key?(key)
            string_key = key.to_s
            return hash[string_key] if hash.key?(string_key)
            symbol_key = string_key.to_sym
            return hash[symbol_key] if hash.key?(symbol_key)
          end
          nil
        end

        def numeric_option(options, *keys)
          value = first_defined(options, *keys)
          return nil if blank?(value)

          Float(value)
        rescue ArgumentError, TypeError
          nil
        end

        def integer_or_nil(value)
          return nil if blank?(value)

          Integer(value)
        rescue ArgumentError, TypeError
          nil
        end

        def presence(value)
          blank?(value) ? nil : value
        end

        def blank?(value)
          value.nil? || value.to_s.empty?
        end
      end
    end
  end
end
