//! Domain layer: Types that contain or are sensitive data.
//!
//! This module defines the core traits for identifying sensitive data:
//!
//! - [`SensitiveType`]: Types that *contain* sensitive data (structs, enums)
//! - [`SensitiveValue`]: Types that *are* sensitive data (String, Cow<str>)
//! - [`Redactable`]: User-facing `.redact()` method
//!
//! ## Field Handling
//!
//! The derive macro generates different code based on field annotations:
//!
//! | Annotation | Generated Code | Behavior |
//! |------------|----------------|----------|
//! | None | Pass through | Field unchanged (external types work!) |
//! | `#[sensitive]` | `SensitiveType::redact_with` or `map_scalar` | Walk or default |
//! | `#[sensitive(Class)]` | `map_sensitive` | Apply classification policy |
//!
//! ## Container Implementations
//!
//! This module provides `SensitiveType` implementations for common std
//! containers (`Option`, `Vec`, `Box`, maps, sets). When walking into these
//! containers, they recursively apply redaction to their contents.
//!
//! ## External Types
//!
//! External types (like `chrono::DateTime`) don't implement `SensitiveType`,
//! and that's fine! Fields without `#[sensitive]` pass through unchanged, so
//! external types work automatically without any special handling.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::Hash,
};

use super::redact::RedactionMapper;

// =============================================================================
// SensitiveValue - Types that ARE sensitive data (leaf values)
// =============================================================================

/// String-like payloads that can be redacted via policies.
///
/// The redaction engine treats these values as strings for the purpose of policy
/// application. Scalar values (numbers, booleans, chars) are not `SensitiveValue`
/// and instead redact to their defaults via `#[sensitive]` and `map_scalar`.
///
/// ## Relationship with `SensitiveType`
///
/// - `SensitiveValue`: A type that *is* sensitive data (String, custom newtypes)
/// - `SensitiveType`: A type that *contains* sensitive data (structs, enums)
///
/// Use `#[sensitive(Classification)]` on fields of `SensitiveValue` types.
/// Use `#[sensitive]` on fields of `SensitiveType` types to walk into them.
///
/// ## Foreign string-like types
///
/// If the sensitive field type comes from another crate, you cannot implement
/// `SensitiveValue` for it directly (Rust's orphan rules). The recommended
/// pattern is to define a local newtype in your project and implement
/// `SensitiveValue` for that wrapper.
///
/// `from_redacted` is not required to preserve the original representation; it
/// only needs to construct a value that corresponds to the redacted string
/// returned by the applied policy.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a `SensitiveValue`",
    label = "this type cannot have a classification applied directly",
    note = "classifications like `#[sensitive(Secret)]` are for leaf values (String, etc.)",
    note = "if `{Self}` is a struct that derives `Sensitive`, use `#[sensitive]` instead to walk into it"
)]
pub trait SensitiveValue: Sized {
    /// Returns a read-only view of the sensitive value.
    fn as_str(&self) -> &str;
    /// Reconstructs the value from a redacted string.
    #[must_use]
    fn from_redacted(redacted: String) -> Self;
}

impl SensitiveValue for String {
    fn as_str(&self) -> &str {
        self.as_str()
    }

    fn from_redacted(redacted: String) -> Self {
        redacted
    }
}

impl SensitiveValue for Cow<'_, str> {
    fn as_str(&self) -> &str {
        self.as_ref()
    }

    fn from_redacted(redacted: String) -> Self {
        Cow::Owned(redacted)
    }
}

// =============================================================================
// SensitiveType - Types that CONTAIN sensitive data (containers)
// =============================================================================

/// A type that contains sensitive data and can be traversed for redaction.
///
/// This trait is implemented by types that derive `Sensitive`. It walks the
/// type's fields and applies redaction to any fields marked with `#[sensitive]`.
///
/// ## When to use
///
/// - Structs/enums containing sensitive fields should derive `Sensitive`
/// - Use `#[sensitive]` on fields to mark them for walking (containers)
/// - Use `#[sensitive(Classification)]` on leaf values (strings, etc.)
///
/// ## Relationship with `SensitiveValue`
///
/// - `SensitiveType`: A type that *contains* sensitive data (structs, enums)
/// - `SensitiveValue`: A type that *is* sensitive data (String, custom newtypes)
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `SensitiveType`",
    label = "this type cannot be walked for sensitive data",
    note = "use `#[derive(Sensitive)]` on the type definition",
    note = "or use `#[sensitive(Classification)]` if this is a leaf value like String"
)]
#[doc(hidden)]
pub trait SensitiveType: Sized {
    /// Applies redaction to this value using the provided mapper.
    #[must_use]
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self;
}

// =============================================================================
// Redactable - User-facing .redact() method
// =============================================================================

/// Public entrypoint for redaction on traversable types.
///
/// This trait is blanket-implemented for all [`SensitiveType`] types and
/// provides a convenience `redact()` method.
///
/// `redact` is implemented in terms of the default mapping behavior provided by
/// [`super::redact::redact`], which applies policies associated with classification
/// types.
pub trait Redactable: SensitiveType {
    /// Redacts the value using classification-bound policies.
    ///
    /// This consumes `self` and returns a redacted copy.
    #[must_use]
    fn redact(self) -> Self {
        super::redact::redact(self)
    }
}

impl<T> Redactable for T where T: SensitiveType {}

// =============================================================================
// RedactableBoxed - Object-safe boxed redaction helper
// =============================================================================

/// Redacts boxed trait objects that expose their own boxed redaction.
///
/// This is intentionally minimal and does not require `RedactionMapper` since
/// boxed trait objects typically provide their own redaction behavior.
pub trait RedactableBoxed {
    /// Redacts the boxed value in-place and returns it.
    #[must_use]
    fn redact_boxed(self: Box<Self>) -> Box<Self>;
}

/// Convenience helper for redacting boxed trait objects.
#[must_use]
pub fn redact_boxed<T>(value: Box<T>) -> Box<T>
where
    T: ?Sized + RedactableBoxed,
{
    value.redact_boxed()
}

// =============================================================================
// SensitiveType implementations for standard library types
// =============================================================================

macro_rules! impl_sensitive_type_passthrough {
    ($ty:ty) => {
        impl SensitiveType for $ty {
            fn redact_with<M: RedactionMapper>(self, _mapper: &M) -> Self {
                self
            }
        }
    };
}

impl_sensitive_type_passthrough!(String);
impl_sensitive_type_passthrough!(bool);
impl_sensitive_type_passthrough!(i8);
impl_sensitive_type_passthrough!(i16);
impl_sensitive_type_passthrough!(i32);
impl_sensitive_type_passthrough!(i64);
impl_sensitive_type_passthrough!(i128);
impl_sensitive_type_passthrough!(isize);
impl_sensitive_type_passthrough!(u8);
impl_sensitive_type_passthrough!(u16);
impl_sensitive_type_passthrough!(u32);
impl_sensitive_type_passthrough!(u64);
impl_sensitive_type_passthrough!(u128);
impl_sensitive_type_passthrough!(usize);
impl_sensitive_type_passthrough!(f32);
impl_sensitive_type_passthrough!(f64);
impl_sensitive_type_passthrough!(());

impl SensitiveType for Cow<'_, str> {
    fn redact_with<M: RedactionMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl<T> SensitiveType for Option<T>
where
    T: SensitiveType,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.redact_with(mapper))
    }
}

impl<T, E> SensitiveType for Result<T, E>
where
    T: SensitiveType,
    E: SensitiveType,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        match self {
            Ok(value) => Ok(value.redact_with(mapper)),
            Err(err) => Err(err.redact_with(mapper)),
        }
    }
}

impl<T> SensitiveType for Vec<T>
where
    T: SensitiveType,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

impl<T> SensitiveType for Box<T>
where
    T: SensitiveType,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        Box::new((*self).redact_with(mapper))
    }
}

impl<K, V, S> SensitiveType for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: SensitiveType,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_hasher(hasher);
        result.extend(self.into_iter().map(|(k, v)| (k, v.redact_with(mapper))));
        result
    }
}

impl<K, V> SensitiveType for BTreeMap<K, V>
where
    K: Ord,
    V: SensitiveType,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|(k, v)| (k, v.redact_with(mapper)))
            .collect()
    }
}

impl<T, S> SensitiveType for HashSet<T, S>
where
    T: SensitiveType + Hash + Eq,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_hasher(hasher);
        result.extend(self.into_iter().map(|value| value.redact_with(mapper)));
        result
    }
}

impl<T> SensitiveType for BTreeSet<T>
where
    T: SensitiveType + Ord,
{
    fn redact_with<M: RedactionMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    };

    use super::{Redactable, SensitiveValue};
    use crate::{Secret, Sensitive};

    // =========================================================================
    // SensitiveValue tests
    // =========================================================================

    #[test]
    fn string_sensitive_value_round_trip() {
        let original = "secret".to_string();
        assert_eq!(original.as_str(), "secret");
        let redacted = String::from_redacted("[REDACTED]".to_string());
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn cow_sensitive_value_round_trip() {
        let original: Cow<'static, str> = Cow::Borrowed("secret");
        assert_eq!(original.as_str(), "secret");
        let redacted = Cow::from_redacted("[REDACTED]".to_string());
        match redacted {
            Cow::Owned(value) => assert_eq!(value, "[REDACTED]"),
            Cow::Borrowed(_) => panic!("redacted Cow should be owned"),
        }
    }

    // =========================================================================
    // SensitiveType tests
    // =========================================================================

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SecretString {
        #[sensitive(Secret)]
        value: String,
    }

    #[test]
    fn option_traversal_redacts_inner() {
        let value = Some(SecretString {
            value: "secret".to_string(),
        });
        let redacted = value.redact();
        assert_eq!(redacted.unwrap().value, "[REDACTED]");
    }

    #[test]
    fn result_traversal_redacts_ok_and_err() {
        let ok_value: Result<SecretString, SecretString> = Ok(SecretString {
            value: "ok_secret".to_string(),
        });
        let redacted_ok = ok_value.redact().unwrap();
        assert_eq!(redacted_ok.value, "[REDACTED]");

        let err_value: Result<SecretString, SecretString> = Err(SecretString {
            value: "err_secret".to_string(),
        });
        let redacted_err = err_value.redact().unwrap_err();
        assert_eq!(redacted_err.value, "[REDACTED]");
    }

    #[test]
    fn vec_traversal_redacts_all_elements() {
        let values = vec![
            SecretString {
                value: "first".to_string(),
            },
            SecretString {
                value: "second".to_string(),
            },
        ];
        let redacted = values.redact();
        assert!(redacted
            .into_iter()
            .all(|value| value.value == "[REDACTED]"));
    }

    #[test]
    fn map_traversal_redacts_values() {
        let mut map: HashMap<String, SecretString> = HashMap::new();
        map.insert(
            "key".to_string(),
            SecretString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert_eq!(redacted["key"].value, "[REDACTED]");
    }

    #[test]
    fn btreemap_traversal_redacts_values() {
        let mut map: BTreeMap<String, SecretString> = BTreeMap::new();
        map.insert(
            "key".to_string(),
            SecretString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert_eq!(redacted["key"].value, "[REDACTED]");
    }

    #[test]
    fn btreeset_traversal_keeps_elements() {
        let mut set: BTreeSet<String> = BTreeSet::new();
        set.insert("public".to_string());
        let redacted = set.redact();
        assert!(redacted.contains("public"));
    }

    #[test]
    fn hashset_traversal_keeps_elements() {
        let mut set: HashSet<String> = HashSet::new();
        set.insert("public".to_string());
        let redacted = set.redact();
        assert!(redacted.contains("public"));
    }

    #[test]
    fn nested_container_traversal_redacts_inner() {
        let values = vec![Some(SecretString {
            value: "secret".to_string(),
        })];
        let redacted = values.redact();
        assert_eq!(redacted[0].as_ref().unwrap().value, "[REDACTED]");
    }

    #[test]
    fn map_keys_are_not_redacted_by_default() {
        let mut map: HashMap<String, SecretString> = HashMap::new();
        map.insert(
            "public_key".to_string(),
            SecretString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert!(redacted.contains_key("public_key"));
        assert_eq!(redacted["public_key"].value, "[REDACTED]");
    }

    #[test]
    fn map_keys_are_never_redacted() {
        #[derive(Clone, Hash, Eq, PartialEq, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct SensitiveKey {
            #[sensitive(Secret)]
            value: String,
        }

        let mut map: HashMap<SensitiveKey, SecretString> = HashMap::new();
        let key = SensitiveKey {
            value: "key_secret".to_string(),
        };
        map.insert(
            key.clone(),
            SecretString {
                value: "secret".to_string(),
            },
        );

        let redacted = map.redact();
        assert!(redacted.contains_key(&key));
        assert_eq!(redacted[&key].value, "[REDACTED]");
    }
}
