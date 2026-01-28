//! Redaction policies, traversal, and entrypoints.
//!
//! This module ties the pieces together:
//!
//! - **`sensitive`**: Domain layer - what is sensitive (`SensitiveType`, `SensitiveValue`)
//! - **`policy`**: Policy layer - how to redact (`RedactionPolicy`, `TextRedactionPolicy`)
//! - **`redact`**: Application layer - the redaction machinery (`Classifiable`, `RedactionMapper`)
//!
//! Classification markers live in `crate::classification`.

mod policy;
mod redact;
mod sensitive;

pub use policy::{
    KeepConfig, MaskConfig, RedactionPolicy, TextRedactionPolicy, REDACTED_PLACEHOLDER,
};
pub use redact::{apply_classification, redact, Classifiable, RedactionMapper, ScalarRedaction};
pub use sensitive::{redact_boxed, Redactable, RedactableBoxed, SensitiveType, SensitiveValue};
