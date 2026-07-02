# Limitations

ToolGateKit is a policy middleware library. It reduces risk by enforcing explicit checks around tool handlers, but it is not a sandbox, container, authentication system, or complete security solution.

Put invariants that must hold even if a gateway is bypassed in handler middleware. A gateway is
better suited for organization-wide policy distribution, traffic shaping, and observability; it
should not be the only enforcement point for destructive or sensitive tools.

Important limitations:

- It cannot stop code inside a handler from doing something unsafe if the handler ignores policy inputs.
- It cannot fully prevent prompt injection.
- It cannot guarantee that a tool is safe.
- It cannot sandbox Node.js execution.
- Timeout cannot always kill underlying work if the handler ignores `AbortSignal`.
- Approval UI must be implemented by the surrounding host or application.
- The default rate-limit store is process-local. High-cardinality untrusted keys can grow memory;
  distributed deployments should supply a bounded, atomic external `RateLimitStore`.
