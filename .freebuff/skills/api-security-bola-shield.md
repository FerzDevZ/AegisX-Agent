# [Skill: api-security-bola-shield]

Mitigate Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA) in REST and GraphQL APIs.

## Defensive Implementation Patterns:
- **Tenant Scoping**: Always append `WHERE tenant_id = :current_tenant AND user_id = :current_user` to data mutations.
- **UUIDs/Hashids**: Use opaque UUIDv4 or NanoID rather than sequential auto-incrementing integer IDs to prevent object enumeration.
- **Role-Based Guards**: Apply declarative middleware guards before executing controller logic (`@RequireRole('admin')`).
- **Resource Ownership Verification**: Validate that the requesting subject explicitly owns the target resource before mutation.
