//! End-to-end tests for the public redaction API.
//!
//! These tests exercise the integration of:
//! - `Sensitive` derive traversal,
//! - classification-bound policy selection, and
//! - container traversal for common standard library types.

#![allow(clippy::redundant_locals)]

use std::collections::{BTreeMap, HashMap};

use redaction::{
    Classification, Redactable, RedactionPolicy, Secret, Sensitive, TextRedactionPolicy, Token,
};

#[test]
fn test_text_policy_apply() {
    let sensitive = String::from("my_secret_password");
    let policy = TextRedactionPolicy::default_full();
    let redacted = policy.apply_to(&sensitive);
    assert_eq!(redacted, "[REDACTED]");
}

#[test]
fn test_engine_redacts_classified() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Token {
        #[sensitive(Secret)]
        value: String,
    }

    let token = Token {
        value: "secret123".to_string(),
    };
    let redacted = token.redact();
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_engine_redacts_nested_maps() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct TokenValue {
        #[sensitive(Token)]
        value: String,
    }

    let mut map: HashMap<String, TokenValue> = HashMap::new();
    map.insert(
        "token".to_string(),
        TokenValue {
            value: "abcd1234".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted.get("token").unwrap().value, "****1234");
}

#[test]
fn test_derive_classification_struct() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct User {
        #[sensitive(Secret)]
        password: String,
        username: String,
    }

    let user = User {
        password: "my_secret_password".into(),
        username: "john_doe".into(),
    };

    let redacted: User = user.redact();

    assert_eq!(redacted.password, "[REDACTED]");
    assert_eq!(redacted.username, "john_doe");
}

#[test]
fn test_enum_derive() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum Credential {
        ApiKey {
            #[sensitive(Token)]
            key: String,
        },
        Password {
            #[sensitive(Secret)]
            value: String,
        },
    }

    let api_key = Credential::ApiKey {
        key: "sk_live_abcdef123456".into(),
    };
    let redacted = api_key.redact();

    match &redacted {
        Credential::ApiKey { key } => {
            assert_eq!(key, "****************3456");
        }
        _ => panic!("Wrong variant"),
    }

    let password = Credential::Password {
        value: "super_secret".into(),
    };
    let redacted = password.redact();
    match &redacted {
        Credential::Password { value } => {
            assert_eq!(value, "[REDACTED]");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_redacted_guard_type() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SecretData {
        #[sensitive(Secret)]
        data: String,
    }

    let secret = SecretData {
        data: "confidential".into(),
    };

    let guarded = secret.redact();
    assert_eq!(guarded.data, "[REDACTED]");
}

#[test]
fn test_nested_struct_derive() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Address {
        #[sensitive(Secret)]
        street: String,
        city: String,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Person {
        #[sensitive(Secret)]
        name: String,
        #[sensitive] // Walk into nested struct
        address: Address,
    }

    let person = Person {
        name: "John Doe".into(),
        address: Address {
            street: "123 Main Street".into(),
            city: "Springfield".into(),
        },
    };

    let redacted = person.redact();

    assert_eq!(redacted.name, "[REDACTED]");
    assert_eq!(redacted.address.street, "[REDACTED]");
    assert_eq!(redacted.address.city, "Springfield");
}

#[test]
fn test_btreemap_traversal() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SecretValue {
        #[sensitive(Secret)]
        value: String,
    }

    let mut map: BTreeMap<String, SecretValue> = BTreeMap::new();
    map.insert(
        "key".to_string(),
        SecretValue {
            value: "value".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted.get("key").unwrap().value, "[REDACTED]");
}

#[test]
fn test_custom_classification() {
    // Users can define their own classification types
    #[derive(Clone, Copy)]
    struct InternalId;
    impl Classification for InternalId {}

    impl RedactionPolicy for InternalId {
        fn policy() -> TextRedactionPolicy {
            // Custom policy: mask all but last 2 characters
            TextRedactionPolicy::keep_last(2)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Record {
        #[sensitive(InternalId)]
        id: String,
        name: String,
    }

    let record = Record {
        id: "user_abc123".into(),
        name: "Test".into(),
    };

    let redacted = record.redact();
    assert_eq!(redacted.id, "*********23");
    assert_eq!(redacted.name, "Test");
}

// ============================================================================
// Additional coverage tests for edge cases and type variations
// ============================================================================

#[test]
fn test_tuple_struct() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct TupleSecret(#[sensitive(Secret)] String, String);

    let tuple = TupleSecret("secret_value".into(), "public_value".into());
    let redacted = tuple.redact();

    assert_eq!(redacted.0, "[REDACTED]");
    assert_eq!(redacted.1, "public_value");
}

#[test]
fn test_tuple_struct_multiple_sensitive() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MultiSecret(
        #[sensitive(Secret)] String,
        #[sensitive(Token)] String,
        String,
    );

    let tuple = MultiSecret("password".into(), "token12345678".into(), "public".into());
    let redacted = tuple.redact();

    assert_eq!(redacted.0, "[REDACTED]");
    assert_eq!(redacted.1, "*********5678"); // Token keeps last 4
    assert_eq!(redacted.2, "public");
}

#[test]
fn test_enum_tuple_variant() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum Auth {
        Token(#[sensitive(Token)] String),
        Basic(#[sensitive(Secret)] String, String),
        None,
    }

    // Test tuple variant with single field
    // "tok_abcdefghij1234" is 18 chars, keep_last(4) masks 14
    let token = Auth::Token("tok_abcdefghij1234".into());
    let redacted = token.redact();
    match redacted {
        Auth::Token(t) => assert_eq!(t, "**************1234"),
        _ => panic!("Wrong variant"),
    }

    // Test tuple variant with multiple fields
    let basic = Auth::Basic("super_secret_password".into(), "user@example.com".into());
    let redacted = basic.redact();
    match redacted {
        Auth::Basic(password, username) => {
            assert_eq!(password, "[REDACTED]");
            assert_eq!(username, "user@example.com");
        }
        _ => panic!("Wrong variant"),
    }

    // Test unit variant
    let none = Auth::None;
    let redacted = none.redact();
    match redacted {
        Auth::None => {}
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_unit_struct() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UnitMarker;

    let marker = UnitMarker;
    let redacted = marker.redact();
    // Unit structs just return themselves
    let _ = redacted; // Ensure it compiles and doesn't panic
}

#[test]
fn test_box_traversal() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct BoxedSecret {
        #[sensitive(Secret)]
        value: String,
    }

    let boxed: Box<BoxedSecret> = Box::new(BoxedSecret {
        value: "secret_in_box".into(),
    });
    let redacted = boxed.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_nested_box_traversal() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepSecret {
        #[sensitive(Secret)]
        value: String,
    }

    let nested: Box<Box<DeepSecret>> = Box::new(Box::new(DeepSecret {
        value: "deeply_nested".into(),
    }));
    let redacted = nested.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_nested_generics() {
    // Test nested structs with concrete types - use #[sensitive] to walk into them
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Inner {
        #[sensitive(Secret)]
        secret: String,
        public: i32,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Outer {
        #[sensitive] // Walk into nested struct
        inner: Inner,
        label: String,
    }

    let outer = Outer {
        inner: Inner {
            secret: "inner_secret".into(),
            public: 42,
        },
        label: "test".into(),
    };

    let redacted = outer.redact();

    assert_eq!(redacted.inner.secret, "[REDACTED]");
    assert_eq!(redacted.inner.public, 42);
    assert_eq!(redacted.label, "test");
}

#[test]
fn test_generic_container_with_sensitive() {
    // Test that generic containers work with Sensitive types
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SecretWrapper {
        #[sensitive(Secret)]
        value: String,
    }

    // Vec<T> where T: Sensitive
    let vec_data = vec![
        SecretWrapper {
            value: "secret1".into(),
        },
        SecretWrapper {
            value: "secret2".into(),
        },
    ];
    let redacted = vec_data.redact();
    assert_eq!(redacted[0].value, "[REDACTED]");
    assert_eq!(redacted[1].value, "[REDACTED]");

    // Option<T> where T: Sensitive
    let opt_data = Some(SecretWrapper {
        value: "secret".into(),
    });
    let redacted = opt_data.redact();
    assert_eq!(redacted.unwrap().value, "[REDACTED]");

    // HashMap<K, V> where V: Sensitive
    let mut map_data: HashMap<String, SecretWrapper> = HashMap::new();
    map_data.insert(
        "key".into(),
        SecretWrapper {
            value: "secret".into(),
        },
    );
    let redacted = map_data.redact();
    assert_eq!(redacted["key"].value, "[REDACTED]");
}

#[test]
fn test_option_vec_nesting() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SecretItem {
        #[sensitive(Secret)]
        value: String,
    }

    let data: Option<Vec<SecretItem>> = Some(vec![
        SecretItem {
            value: "first".into(),
        },
        SecretItem {
            value: "second".into(),
        },
    ]);

    let redacted = data.redact();

    let items = redacted.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].value, "[REDACTED]");
    assert_eq!(items[1].value, "[REDACTED]");
}

#[test]
fn test_scalar_redaction() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ScalarData {
        #[sensitive]
        secret_number: i32,
        #[sensitive]
        secret_flag: bool,
        #[sensitive]
        secret_char: char,
        public_number: i32,
    }

    let data = ScalarData {
        secret_number: 42,
        secret_flag: true,
        secret_char: 'X',
        public_number: 100,
    };

    let redacted = data.redact();

    assert_eq!(redacted.secret_number, 0); // Default for i32
    assert!(!redacted.secret_flag); // Default for bool is false
    assert_eq!(redacted.secret_char, 'X'); // char redacts to 'X'
    assert_eq!(redacted.public_number, 100); // Non-sensitive unchanged
}

#[test]
fn test_scalar_types_comprehensive() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AllScalars {
        #[sensitive]
        i8_val: i8,
        #[sensitive]
        i16_val: i16,
        #[sensitive]
        i32_val: i32,
        #[sensitive]
        i64_val: i64,
        #[sensitive]
        u8_val: u8,
        #[sensitive]
        u16_val: u16,
        #[sensitive]
        u32_val: u32,
        #[sensitive]
        u64_val: u64,
        #[sensitive]
        f32_val: f32,
        #[sensitive]
        f64_val: f64,
        #[sensitive]
        bool_val: bool,
        #[sensitive]
        char_val: char,
    }

    let data = AllScalars {
        i8_val: 1,
        i16_val: 2,
        i32_val: 3,
        i64_val: 4,
        u8_val: 5,
        u16_val: 6,
        u32_val: 7,
        u64_val: 8,
        f32_val: 9.5,
        f64_val: 10.5,
        bool_val: true,
        char_val: 'A',
    };

    let redacted = data.redact();

    // All numeric types redact to 0
    assert_eq!(redacted.i8_val, 0);
    assert_eq!(redacted.i16_val, 0);
    assert_eq!(redacted.i32_val, 0);
    assert_eq!(redacted.i64_val, 0);
    assert_eq!(redacted.u8_val, 0);
    assert_eq!(redacted.u16_val, 0);
    assert_eq!(redacted.u32_val, 0);
    assert_eq!(redacted.u64_val, 0);
    assert_eq!(redacted.f32_val, 0.0);
    assert_eq!(redacted.f64_val, 0.0);

    // bool redacts to false (default)
    assert!(!redacted.bool_val);

    // char redacts to 'X' (special case)
    assert_eq!(redacted.char_val, 'X');
}

#[test]
fn test_mixed_named_and_sensitive_fields() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MixedRecord {
        id: u64,
        #[sensitive(Secret)]
        ssn: String,
        name: String,
        #[sensitive]
        internal_score: i32,
        #[sensitive(Token)]
        api_key: String,
        public_data: String,
    }

    let record = MixedRecord {
        id: 12345,
        ssn: "123-45-6789".into(),
        name: "John Doe".into(),
        internal_score: 95,
        api_key: "sk_test_abc123456789".into(),
        public_data: "visible".into(),
    };

    let redacted = record.redact();

    assert_eq!(redacted.id, 12345); // Non-sensitive, unchanged
    assert_eq!(redacted.ssn, "[REDACTED]"); // Secret: full redaction
    assert_eq!(redacted.name, "John Doe"); // Non-sensitive, unchanged
    assert_eq!(redacted.internal_score, 0); // Bare sensitive scalar
    assert_eq!(redacted.api_key, "****************6789"); // Token: keep last 4 (20 - 4 = 16 asterisks)
    assert_eq!(redacted.public_data, "visible"); // Non-sensitive, unchanged
}

// ============================================================================
// Nested wrapper classification tests (Classifiable)
// ============================================================================

#[test]
fn test_nested_wrapper_option_vec() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Secret)]
        addresses: Option<Vec<String>>,
    }

    let n = NestedWrappers {
        addresses: Some(vec!["123 Main St".into(), "456 Oak Ave".into()]),
    };
    let redacted = n.redact();

    let addrs = redacted.addresses.unwrap();
    assert_eq!(addrs[0], "[REDACTED]");
    assert_eq!(addrs[1], "[REDACTED]");
}

#[test]
fn test_nested_wrapper_vec_option() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Secret)]
        values: Vec<Option<String>>,
    }

    let n = NestedWrappers {
        values: vec![Some("secret1".into()), None, Some("secret2".into())],
    };
    let redacted = n.redact();

    assert_eq!(redacted.values[0], Some("[REDACTED]".into()));
    assert_eq!(redacted.values[1], None);
    assert_eq!(redacted.values[2], Some("[REDACTED]".into()));
}

#[test]
fn test_nested_wrapper_deeply_nested() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepNest {
        #[sensitive(Secret)]
        values: Option<Vec<Option<String>>>,
    }

    let n = DeepNest {
        values: Some(vec![Some("secret".into()), None]),
    };
    let redacted = n.redact();

    let values = redacted.values.unwrap();
    assert_eq!(values[0], Some("[REDACTED]".into()));
    assert_eq!(values[1], None);
}

#[test]
fn test_nested_wrapper_hashmap_vec() {
    use std::collections::HashMap;

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MapWithVec {
        #[sensitive(Secret)]
        data: HashMap<String, Vec<String>>,
    }

    let mut data = HashMap::new();
    data.insert("emails".into(), vec!["a@b.com".into(), "c@d.com".into()]);

    let n = MapWithVec { data };
    let redacted = n.redact();

    assert_eq!(
        redacted.data.get("emails"),
        Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
    );
}

#[test]
fn test_external_types_pass_through() {
    // Simulate external types that don't implement SensitiveType
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalTimestamp(u64);

    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalDecimal(f64);

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Transaction {
        #[sensitive(Secret)]
        account_number: String,
        // External types pass through unchanged - no annotation needed!
        timestamp: ExternalTimestamp,
        amount: ExternalDecimal,
        description: String,
    }

    let tx = Transaction {
        account_number: "1234567890".into(),
        timestamp: ExternalTimestamp(1704067200),
        amount: ExternalDecimal(99.99),
        description: "Coffee".into(),
    };

    let redacted = tx.redact();

    assert_eq!(redacted.account_number, "[REDACTED]");
    assert_eq!(redacted.timestamp, ExternalTimestamp(1704067200)); // Unchanged
    assert_eq!(redacted.amount, ExternalDecimal(99.99)); // Unchanged
    assert_eq!(redacted.description, "Coffee"); // Unchanged
}

#[test]
fn test_nested_struct_requires_sensitive_annotation() {
    // Nested structs that derive Sensitive must be explicitly marked with #[sensitive]
    // to be walked. Without the annotation, they pass through unchanged.
    #[derive(Clone, Sensitive, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    #[sensitive(skip_debug)]
    struct Credentials {
        #[sensitive(Secret)]
        password: String,
        username: String,
    }

    impl std::fmt::Debug for Credentials {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Credentials")
                .field("password", &self.password)
                .field("username", &self.username)
                .finish()
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UserWithAnnotation {
        #[sensitive]
        creds: Credentials,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UserWithoutAnnotation {
        creds: Credentials,
    }

    let creds = Credentials {
        password: "secret123".into(),
        username: "alice".into(),
    };

    // With #[sensitive], the inner struct is walked
    let user_annotated = UserWithAnnotation {
        creds: creds.clone(),
    };
    let redacted_annotated = user_annotated.redact();
    assert_eq!(redacted_annotated.creds.password, "[REDACTED]");
    assert_eq!(redacted_annotated.creds.username, "alice");

    // Without annotation, the inner struct passes through unchanged
    let user_unannotated = UserWithoutAnnotation {
        creds: creds.clone(),
    };
    let redacted_unannotated = user_unannotated.redact();
    assert_eq!(redacted_unannotated.creds.password, "secret123"); // NOT redacted!
    assert_eq!(redacted_unannotated.creds.username, "alice");
}
