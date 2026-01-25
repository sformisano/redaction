//! Adapters for emitting redacted values through `slog`.
//!
//! This module exists to connect `crate::redaction::Redactable` with `slog` by
//! providing `slog::Value` implementations that serialize redacted outputs as
//! structured JSON via `slog`'s nested-value support.
//!
//! It is responsible for:
//! - Ensuring the logged representation is derived from `Redactable::redact()`,
//!   not from the original value.
//! - Avoiding fallible logging APIs: serialization failures are represented as
//!   placeholder strings rather than propagated as errors.
//!
//! It does not configure `slog`, define redaction policy, or attempt to validate
//! that a `Redactable` implementation performs correct redaction.

use std::fmt;

use serde::Serialize;
use serde_json::Value as JsonValue;
use slog::{Key, Record, Result as SlogResult, Serializer, Value as SlogValue};

use crate::redaction::Redactable;

/// A `slog::Value` that emits an owned redacted payload as structured JSON.
///
/// The payload is stored as a `serde_json::Value` and emitted via
/// `slog`'s nested-value support.
///
/// This type does not return serialization errors to `slog`; if converting the
/// redacted output into a JSON value fails, it falls back to a JSON string value.
pub struct RedactedJson {
    value: JsonValue,
}

impl RedactedJson {
    fn new(value: JsonValue) -> Self {
        Self { value }
    }
}

impl SlogValue for RedactedJson {
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        let nested = slog::Serde(self.value.clone());
        SlogValue::serialize(&nested, record, key, serializer)
    }
}

/// Converts values into a `slog::Value` that logs their redacted form as JSON.
///
/// Calling `into_redacted_json` consumes the value, computes `self.redact()`,
/// and stores the result as a `serde_json::Value`. The original (unredacted)
/// value is not serialized.
///
/// ## Example
/// ```ignore
/// use redaction::slog::IntoRedactedJson;
///
/// info!(logger, "event"; "data" => event.into_redacted_json());
/// ```
pub trait IntoRedactedJson: Redactable + fmt::Debug + Serialize + Sized {
    /// Redacts `self` and returns a `slog::Value` that serializes as structured JSON.
    ///
    /// If converting the redacted output into `serde_json::Value` fails, the
    /// returned value stores a JSON string with the message
    /// `"Failed to serialize redacted value"`.
    fn into_redacted_json(self) -> RedactedJson {
        let redacted = self.redact();
        let json_value = serde_json::to_value(redacted).unwrap_or_else(|_| {
            JsonValue::String("Failed to serialize redacted value".to_string())
        });
        RedactedJson::new(json_value)
    }
}

impl<T> IntoRedactedJson for T where T: Redactable + fmt::Debug + Serialize {}
