//! Type-directed redaction for structured data.
//!
//! This crate separates:
//! - **Classification**: what kind of sensitive data this is.
//! - **Policy**: how that data should be redacted.
//!
//! The derive macro walks your data and applies the policy at the boundary when
//! you call `redact()` or `Redactable::redact()`.
//!
//! Key rules:
//! - Use `#[sensitive(Classification)]` for string-like leaf values.
//! - Use `#[sensitive]` for scalars and nested `Sensitive` types.
//! - Unannotated fields pass through unchanged.
//! - `Debug` always prints `"[REDACTED]"` for sensitive fields; policies apply only
//!   when calling `.redact()`.
//!
//! Boxed trait objects:
//! - `#[sensitive]` supports `Box<dyn Trait>` by calling `redact_boxed`.
//! - Detection is conservative and only matches the simple `Box<dyn Trait>` syntax,
//!   not qualified paths or type aliases.
//!
//! What this crate does:
//! - defines classification marker types and the [`Classification`] trait
//! - defines redaction policies and the `redact` entrypoint
//! - provides integrations behind feature flags (e.g. `slog`)
//!
//! What it does not do:
//! - perform I/O or logging
//! - validate your policy choices
//!
//! The `Sensitive` derive macro lives in `redaction-derive` and is re-exported when
//! the `derive` feature is enabled.

// <https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html>
#![warn(
    anonymous_parameters,
    bare_trait_objects,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces
)]
// <https://rust-lang.github.io/rust-clippy/stable>
#![warn(
    clippy::all,
    clippy::cargo,
    clippy::dbg_macro,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::mem_forget,
    clippy::nursery,
    clippy::pedantic,
    clippy::todo,
    clippy::unwrap_used,
    clippy::uninlined_format_args
)]
// Allow some clippy lints
#![allow(
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::needless_ifs,
    clippy::use_self,
    clippy::cargo_common_metadata,
    clippy::missing_errors_doc,
    clippy::enum_glob_use,
    clippy::struct_excessive_bools,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::result_large_err,
    clippy::future_not_send,
    clippy::option_if_let_else,
    clippy::from_over_into,
    clippy::manual_inspect
)]
// Allow some lints while testing
#![cfg_attr(test, allow(clippy::non_ascii_literal, clippy::unwrap_used))]

pub use redaction_derive::{Sensitive, SensitiveError};

#[allow(unused_extern_crates)]
extern crate self as redact;

// Module declarations
#[cfg(feature = "classification")]
mod classification;
#[cfg(feature = "policy")]
mod redaction;
#[cfg(feature = "slog")]
pub mod slog;

// Re-exports
#[cfg(feature = "classification")]
pub use classification::{
    AccountId, BlockchainAddress, Classification, CreditCard, DateOfBirth, Email, IpAddress,
    NationalId, PhoneNumber, Pii, Secret, SessionId, Token,
};
#[cfg(feature = "policy")]
pub use redaction::{
    apply_classification, redact, redact_boxed, KeepConfig, MaskConfig, Redactable,
    RedactableBoxed, RedactionPolicy, ScalarRedaction, SensitiveValue, TextRedactionPolicy,
    REDACTED_PLACEHOLDER,
};
#[doc(hidden)]
#[cfg(feature = "policy")]
pub use redaction::{Classifiable, RedactionMapper, SensitiveType};
