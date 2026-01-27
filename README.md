# Redaction

`redaction` helps you keep sensitive values (tokens, secrets, PII) out of places they don't belong by:

- Deriving `Sensitive` on your types with `#[derive(Sensitive)]`
- Marking sensitive fields with `#[sensitive]` or `#[sensitive(Classification)]`
- Calling `.redact()` to produce a copy that is safe to log or serialize
- Generating `Debug` output that prints `"[REDACTED]"` for sensitive fields (independent of policies)

## Design (DDD / Clean Architecture friendly)

- **Classifications are domain concepts**: marker types like `Secret`, `Token`, or your own `InternalId` represent *what kind* of data a field contains.
- **Policies belong in the application layer**: policies are attached to classification types (`impl RedactionPolicy for MyClassification`) in the layer where you define "what is safe to expose", typically close to logging/serialization boundaries.
- **Sinks are optional adapters**: integrations like `slog` live behind feature flags; your domain types don't depend on a logging framework.
- **Layering is optional**: you can put classifications, policies, and redaction calls in a single crate if you prefer. The library supports both "clean architecture" layering and simple, pragmatic project layouts.

## The Problem

Sensitive data ends up places it shouldn't:

- **Logging**: Structured logs capture request/response bodies containing passwords, tokens, PII
- **Serialization**: API responses, database exports, and message queues include fields that should be hidden
- **Error reporting**: Stack traces and error contexts expose sensitive state
- **Debug output**: `#[derive(Debug)]` prints everything, including secrets

Once sensitive data reaches these systems, it is often:

- Stored long-term (retention policies, backups)
- Indexed and searchable
- Replicated across environments
- Visible to anyone with access to logs/telemetry

```rust
#[derive(Debug, serde::Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

let request = LoginRequest {
    username: "alice".into(),
    password: "hunter2".into(),
};

// Debug output exposes the password
println!("{:?}", request);
// → LoginRequest { username: "alice", password: "hunter2" }

// Serialization also exposes the password
let json = serde_json::to_string(&request).unwrap();
// → {"username":"alice","password":"hunter2"}
//
// (This example uses `serde_json` to make the risk concrete. The same problem
// exists with any serializer that includes `password`.)
```

## The Solution

Mark sensitive fields explicitly. This crate provides:

- **Safe Debug**: sensitive fields print as `[REDACTED]`
- **Explicit redaction**: call `.redact()` to get a copy safe for serialization and logging
- **Policy control**: choose how each classification is redacted (full, keep, mask)
- **External type support**: types you don't control (like `chrono::DateTime`) just work

```rust
use redaction::{Redactable, Secret, Token, Sensitive};

#[derive(Clone, Sensitive)]
struct LoginRequest {
    username: String,
    #[sensitive(Secret)]
    password: String,
    #[sensitive(Token)]
    api_key: String,
}

let request = LoginRequest {
    username: "alice".into(),
    password: "hunter2".into(),
    api_key: "tok_live_abcdef".into(),
};

// Get a redacted copy for serialization, APIs, and logging
let safe = request.redact();
assert_eq!(safe.password, "[REDACTED]");       // Secret: fully redacted
assert_eq!(safe.api_key, "***********cdef");  // Token: only last 4 visible
assert_eq!(safe.username, "alice");            // Not sensitive: unchanged

// Debug output is also safe, but it does NOT apply policies:
// it always prints `"[REDACTED]"` for `#[sensitive(...)]` fields.
println!("{:?}", request);
// → LoginRequest { username: "alice", password: "[REDACTED]", api_key: "[REDACTED]" }
```

## Installation

```toml
[dependencies]
redaction = "0.1"
```

## Basic Usage

- Add `#[derive(Clone, Sensitive)]` to your type
- Mark sensitive fields with `#[sensitive]` or `#[sensitive(Classification)]`
- Call `.redact()` before you log, serialize, return, or persist the value

```rust
use redaction::{Redactable, Secret, Token, Sensitive};

#[derive(Clone, Sensitive)]
struct ApiCredentials {
    #[sensitive(Secret)]
    password: String,
    #[sensitive(Token)]
    api_key: String,
    user_id: String,  // not sensitive, passed through unchanged
}

let creds = ApiCredentials {
    password: "super_secret".into(),
    api_key: "tok_live_abcdef".into(),
    user_id: "user_42".into(),
};

let redacted = creds.redact();
assert_eq!(redacted.password, "[REDACTED]");  // Secret → fully redacted
assert_eq!(redacted.api_key, "***********cdef"); // Token → only last 4 visible
assert_eq!(redacted.user_id, "user_42");      // unchanged
```

## Field Attributes

The `#[sensitive(...)]` attribute controls how each field is handled:

| Attribute | Use For | Behavior |
|-----------|---------|----------|
| *(none)* | Non-sensitive fields, external types | Pass through unchanged |
| `#[sensitive]` | Scalars OR nested `Sensitive` types | Walk containers, or redact scalars to default |
| `#[sensitive(Class)]` | String-like leaf values | Apply classification's redaction policy |

### Examples

```rust
use redaction::{Redactable, Secret, Sensitive};

#[derive(Clone, Sensitive)]
struct Address {
    #[sensitive(Secret)]
    street: String,
    city: String,        // Not sensitive
}

#[derive(Clone, Sensitive)]
struct User {
    #[sensitive(Secret)]
    ssn: String,         // Leaf value: apply Secret policy
    
    #[sensitive]
    address: Address,    // Nested struct: walk into it
    
    #[sensitive]
    age: i32,            // Scalar: redact to default (0)
    
    created_at: DateTime<Utc>,  // External type: passes through unchanged
    balance: Decimal,           // External type: passes through unchanged
}
```

### External Types Just Work

Fields without `#[sensitive]` pass through unchanged. This means external types like `chrono::DateTime`, `rust_decimal::Decimal`, `uuid::Uuid`, or any type you don't control work automatically:

```rust
use chrono::{DateTime, Utc};

#[derive(Clone, Sensitive)]
struct Transaction {
    #[sensitive(Secret)]
    account_number: String,
    
    // No annotation needed - external types pass through!
    timestamp: DateTime<Utc>,
    amount: Decimal,
    id: Uuid,
}
```

### Nested Sensitive Types

When a field's type also derives `Sensitive`, use `#[sensitive]` to walk into it:

```rust
#[derive(Clone, Sensitive)]
struct Credentials {
    #[sensitive(Secret)]
    password: String,
}

#[derive(Clone, Sensitive)]
struct User {
    #[sensitive]  // Walk into Credentials
    creds: Credentials,
}
```

**Important**: Without `#[sensitive]`, nested structs pass through unchanged (even if they derive `Sensitive`). This is by design - you explicitly choose what to redact.

### Nested Wrapper Classifications

Classifications work on nested wrapper types like `Option<Vec<String>>` automatically:

```rust
#[derive(Clone, Sensitive)]
struct User {
    #[sensitive(Pii)]
    emails: Option<Vec<String>>,  // Works! Recursively applies Pii to each String
    
    #[sensitive(Secret)]
    backup_codes: Vec<Option<String>>,  // Also works!
    
    #[sensitive(Secret)]
    metadata: HashMap<String, Vec<String>>,  // Maps work too!
}
```

The classification is applied recursively through any nesting depth of:
- `Option<T>`
- `Vec<T>`
- `Box<T>`
- `HashMap<K, V>` (values only)
- `BTreeMap<K, V>` (values only)
- `HashSet<T>` / `BTreeSet<T>`
- `Result<T, E>`

## Built-in Classifications

Each classification has a default redaction policy. Use the one that matches your data:

| Classification | Use for | Example output |
| --- | --- | --- |
| `Secret` | Passwords, private keys | `[REDACTED]` |
| `Token` | API keys, bearer tokens | `…abcd` (last 4) |
| `Email` | Email addresses | `jo…` (first 2) |
| `CreditCard` | Card numbers (PANs) | `…1234` (last 4) |
| `Pii` | Generic PII | `…_doe` (last 4) |
| `PhoneNumber` | Phone numbers | `…12` (last 2) |
| `NationalId` | SSN, passport numbers | `…6789` (last 4) |
| `AccountId` | Account identifiers | `…abcd` (last 4) |
| `SessionId` | Session tokens | `…wxyz` (last 4) |
| `IpAddress` | IP addresses | `…1.1` (last 4 chars) |
| `DateOfBirth` | Birth dates | `[REDACTED]` |
| `BlockchainAddress` | Wallet addresses | `…abc123` (last 6) |

## Custom Classifications

When built-in classifications don't fit, create your own:

```rust
use redaction::{Classification, RedactionPolicy, TextRedactionPolicy};

#[derive(Clone, Copy)]
struct InternalId;
impl Classification for InternalId {}

impl RedactionPolicy for InternalId {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)  // Show only last 2 characters
    }
}
```

Clean architecture note:

- Put the **classification type** (`InternalId`) in your **domain** crate/module.
- Put the **policy implementation** (`impl RedactionPolicy for InternalId`) in your **application** or **infrastructure** layer (where you define what is safe to expose and where logging/serialization happens).

Then use it like any built-in:

```rust
#[derive(Clone, Sensitive)]
struct Record {
    #[sensitive(InternalId)]
    id: String,
}
```

## Policies

Three policy types control how values are transformed:

- **Full**: replace the entire value with a placeholder

```rust
TextRedactionPolicy::default_full()           // → "[REDACTED]"
TextRedactionPolicy::full_with("<hidden>")    // → "<hidden>"
```

- **Keep**: keep specified characters visible, mask everything else

```rust
TextRedactionPolicy::keep_first(4)            // "secret123" → "secr*****"
TextRedactionPolicy::keep_last(4)             // "secret123" → "*****t123"
TextRedactionPolicy::keep_with(KeepConfig::both(2, 2))  // "secret" → "se**et"
```

- **Mask**: mask specified characters, keep the rest visible

```rust
TextRedactionPolicy::mask_first(4)            // "secret123" → "****et123"
TextRedactionPolicy::mask_last(4)             // "secret123" → "secre****"
```

## Logging with slog

With the `slog` feature, `Sensitive` types automatically redact when logged:

```toml
[dependencies]
redaction = { version = "0.1", features = ["slog"] }
```

```rust
#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct LoginEvent {
    #[sensitive(Secret)]
    password: String,
    username: String,
}

// Redacts automatically (no explicit .redact() needed)
slog::info!(logger, "login"; "event" => event);
```

**Requirements:**
- Type must implement `Clone`
- Type must implement `serde::Serialize` (for the redacted output)

---

## Reference

### Trait Concepts

The library uses these core traits, organized by layer:

**Domain Layer** (what is sensitive):
| Trait | Purpose | Implemented By |
|-------|---------|----------------|
| `SensitiveType` | Types that *contain* sensitive data | Structs/enums deriving `Sensitive` |
| `SensitiveValue` | Types that *are* sensitive data | `String`, `Cow<str>`, custom newtypes |

**Policy Layer** (how to redact):
| Trait | Purpose | Implemented By |
|-------|---------|----------------|
| `RedactionPolicy` | Maps classification → redaction strategy | Your custom classifications |
| `TextRedactionPolicy` | Concrete string transformations | Built-in (Full, Keep, Mask) |

**Application Layer** (redaction machinery):
| Trait | Purpose | Implemented By |
|-------|---------|----------------|
| `Classifiable` | Types that can have classifications applied | `String`, wrappers (`Option`, `Vec`, etc.) |
| `Redactable` | User-facing `.redact()` method | Auto-implemented for `SensitiveType` |
| `RedactionMapper` | Internal traversal machinery | `#[doc(hidden)]` |

- Use `#[sensitive]` on fields of `SensitiveType` types (to walk into them)
- Use `#[sensitive(Classification)]` on fields of `Classifiable` types (supports nested wrappers)

### Supported Field Types

**String-like** (`SensitiveValue`): Use `#[sensitive(Classification)]`:
- `String`
- `Cow<'_, str>` (redaction returns an owned value)

**Scalars**: Use bare `#[sensitive]` (no classification):
- Integers: `i8`-`i128`, `u8`-`u128`, `isize`, `usize`
- Floats: `f32`, `f64`
- `bool` → redacts to `false`
- `char` → redacts to `'X'`

**Containers** (`SensitiveType`): Use `#[sensitive]` to walk, or omit for pass-through:
- `Option<T>`: redacts inner value if present
- `Vec<T>`: redacts all elements
- `Box<T>`: redacts inner value
- `HashMap<K, V>`, `BTreeMap<K, V>`: redacts values only (keys unchanged)
- `HashSet<T>`, `BTreeSet<T>`: redacts elements
- `Result<T, E>`: redacts both `Ok` and `Err` sides

**External types**: No annotation needed (pass through):
- `chrono::DateTime<Tz>`, `rust_decimal::Decimal`, `uuid::Uuid`, etc.
- Any type that doesn't implement `SensitiveType`

**PhantomData**: Automatically handled (pass through, no trait bounds added).

### Compiler Error Messages

The library provides helpful error messages for common mistakes:

**Using a classification on a struct:**
```
error[E0277]: `Address` is not a `SensitiveValue`
   = note: classifications like `#[sensitive(Secret)]` are for leaf values (String, etc.)
   = note: if `Address` is a struct that derives `Sensitive`, use `#[sensitive]` instead
```

**Using `#[sensitive]` on an external type:**
```
error[E0277]: `DateTime<Utc>` does not implement `SensitiveType`
   = note: use `#[derive(Sensitive)]` on the type definition
   = note: or remove the #[sensitive] attribute to pass through unchanged
```

### Policy Behavior

- **Empty string (`""`)**:
  - **Keep/Mask**: returns `""`
  - **Full**: returns the placeholder (default: `"[REDACTED]"`)
- **Keep policies** (`keep_first`, `keep_last`, `KeepConfig::both`) operate on Unicode scalar values:
  - If `visible_prefix + visible_suffix >= length`, the value is returned unchanged
- **Mask policies** (`mask_first`, `mask_last`, `MaskConfig::both`) operate on Unicode scalar values:
  - If `mask_prefix + mask_suffix >= length`, the entire value is masked
- **Length**: keep/mask policies preserve the input length (full does not)

### Edge Cases

**Scalar type aliases**: Only bare primitive names (`i32`, `bool`) are recognized as scalars. Type aliases like `type MyInt = i32` or qualified paths like `std::primitive::i32` are treated as string-like and require a classification.

**Foreign string types**: For string-like types from other crates, wrap in a newtype:

```rust
use redaction::SensitiveValue;

struct WrappedId(external_crate::Id);

impl SensitiveValue for WrappedId {
    fn as_str(&self) -> &str { self.0.as_str() }
    fn from_redacted(s: String) -> Self { WrappedId(external_crate::Id::from(s)) }
}
```

**Map keys**: Never redacted. Move sensitive data into values.

**Debug vs `redact()`**: The derived `Debug` formats the type normally, but replaces the values of `#[sensitive(...)]` fields with the string `\"[REDACTED]\"`. It does not apply the field's policy. Use `.redact()` when you need policy-based output.

**Testing**: Enable the `testing` feature to get unredacted `Debug` output in tests:

```toml
[dev-dependencies]
redaction = { version = "0.1", features = ["testing"] }
```

### Security Considerations

- **Length preservation**: Keep/Mask policies preserve input length, which can leak information about value size. Use Full redaction for maximum privacy.
- **Timing**: Redaction is not constant-time. Do not use in cryptographic contexts.
- **Memory**: Original values may persist in memory until overwritten. Consider secure memory handling for highly sensitive data.

---

## Documentation

- [API Documentation](https://docs.rs/redaction)

## Development

To set up git hooks for pre-commit checks (fmt, clippy, tests):

```bash
git config core.hooksPath .githooks
```

## License

Licensed under the MIT license ([LICENSE.md](LICENSE.md) or [opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)).
