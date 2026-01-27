//! Integration tests for the slog module.
//!
//! These tests verify that:
//! - `into_redacted_json()` produces correctly redacted JSON values
//! - The `slog::Value` implementation works with slog's serialization API
//! - Nested structures are properly redacted when logged

#![cfg(feature = "slog")]

use redaction::slog::IntoRedactedJson;
use redaction::{
    Classification, Pii, RedactionPolicy, Secret, Sensitive, TextRedactionPolicy, Token,
};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Arguments;

// A test serializer that captures serialized key-value pairs
struct CapturingSerializer {
    captured: RefCell<HashMap<String, CapturedValue>>,
}

#[derive(Debug, Clone, PartialEq)]
enum CapturedValue {
    Str(String),
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Unit,
    None,
    // For nested serde values, we capture the JSON representation
    Serde(JsonValue),
}

impl CapturingSerializer {
    fn new() -> Self {
        Self {
            captured: RefCell::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<CapturedValue> {
        self.captured.borrow().get(key).cloned()
    }
}

impl slog::Serializer for CapturingSerializer {
    fn emit_arguments(&mut self, key: slog::Key, val: &Arguments<'_>) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.to_string()));
        Ok(())
    }

    fn emit_str(&mut self, key: slog::Key, val: &str) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.into()));
        Ok(())
    }

    fn emit_bool(&mut self, key: slog::Key, val: bool) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Bool(val));
        Ok(())
    }

    fn emit_i64(&mut self, key: slog::Key, val: i64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::I64(val));
        Ok(())
    }

    fn emit_u64(&mut self, key: slog::Key, val: u64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::U64(val));
        Ok(())
    }

    fn emit_f64(&mut self, key: slog::Key, val: f64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::F64(val));
        Ok(())
    }

    fn emit_unit(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Unit);
        Ok(())
    }

    fn emit_none(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::None);
        Ok(())
    }

    fn emit_serde(&mut self, key: slog::Key, val: &dyn slog::SerdeValue) -> slog::Result {
        // Serialize the value to JSON to capture it
        let json = serde_json::to_value(val.as_serde()).unwrap_or(JsonValue::Null);
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Serde(json));
        Ok(())
    }
}

/// Helper function to serialize a slog::Value into any Serializer.
fn serialize_to_capture<V: slog::Value, S: slog::Serializer>(
    value: &V,
    key: &'static str,
    serializer: &mut S,
) {
    // The record is created and used in a single expression to avoid lifetime issues
    static RS: slog::RecordStatic<'static> = slog::record_static!(slog::Level::Info, "");
    // We need to ensure format_args! result lives long enough
    let args = format_args!("");
    let record = slog::Record::new(&RS, &args, slog::b!());
    value.serialize(&record, key.into(), serializer).unwrap();
}

// ============================================================================
// Basic functionality tests
// ============================================================================

#[test]
fn test_into_redacted_json_simple_struct() {
    #[derive(Clone, Sensitive, Serialize)]
    struct User {
        username: String,
        #[sensitive(Secret)]
        password: String,
    }

    let user = User {
        username: "alice".into(),
        password: "super_secret_password".into(),
    };

    let redacted = user.into_redacted_json();

    // Serialize through slog's Value trait
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "user", &mut serializer);

    // Verify the captured value contains redacted password
    if let Some(CapturedValue::Serde(json)) = serializer.get("user") {
        assert_eq!(json["username"], "alice");
        // Password should be fully redacted (Secret classification = Full policy)
        assert_eq!(json["password"], "[REDACTED]");
    } else {
        panic!("Expected Serde value for 'user' key");
    }
}

#[test]
fn test_into_redacted_json_with_pii() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Contact {
        #[sensitive(Pii)]
        email: String,
        #[sensitive(Pii)]
        phone: String,
    }

    let contact = Contact {
        email: "alice@example.com".into(),
        phone: "555-123-4567".into(),
    };

    let redacted = contact.into_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "contact", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("contact") {
        // PII uses Keep(last 4) policy - shows last 4 chars, masks rest
        let email = json["email"].as_str().unwrap();
        let phone = json["phone"].as_str().unwrap();

        // Email should be partially masked (last 4 visible)
        assert!(email.ends_with(".com"));
        assert!(email.contains('*'));

        // Phone should be partially masked (last 4 visible)
        assert!(phone.ends_with("4567"));
        assert!(phone.contains('*'));
    } else {
        panic!("Expected Serde value for 'contact' key");
    }
}

#[test]
fn test_into_redacted_json_nested_struct() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Address {
        #[sensitive(Pii)]
        street: String,
        city: String,
    }

    #[derive(Clone, Sensitive, Serialize)]
    struct Person {
        name: String,
        #[sensitive(Secret)]
        ssn: String,
        #[sensitive]
        address: Address,
    }

    let person = Person {
        name: "Bob".into(),
        ssn: "123-45-6789".into(),
        address: Address {
            street: "123 Main Street".into(),
            city: "Springfield".into(),
        },
    };

    let redacted = person.into_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "person", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("person") {
        // Name should be unchanged (no classification)
        assert_eq!(json["name"], "Bob");

        // SSN should be fully redacted
        assert_eq!(json["ssn"], "[REDACTED]");

        // Address street should be partially masked (Pii = last 4 visible)
        let street = json["address"]["street"].as_str().unwrap();
        assert!(street.contains('*'));

        // City should be unchanged (no classification)
        assert_eq!(json["address"]["city"], "Springfield");
    } else {
        panic!("Expected Serde value for 'person' key");
    }
}

#[test]
fn test_into_redacted_json_with_vec() {
    #[derive(Clone, Sensitive, Serialize)]
    struct TokenList {
        #[sensitive(Token)]
        tokens: Vec<String>,
    }

    let list = TokenList {
        tokens: vec![
            "token_abc123".into(),
            "token_xyz789".into(),
            "token_def456".into(),
        ],
    };

    let redacted = list.into_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "list", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("list") {
        let tokens = json["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 3);

        // Token classification uses Keep(last 4) - shows last 4 chars, masks rest
        for token in tokens {
            let s = token.as_str().unwrap();
            assert!(s.contains('*'));
        }
    } else {
        panic!("Expected Serde value for 'list' key");
    }
}

#[test]
fn test_into_redacted_json_with_option() {
    #[derive(Clone, Sensitive, Serialize)]
    struct OptionalSecret {
        #[sensitive(Secret)]
        secret: Option<String>,
        public: String,
    }

    // Test with Some value
    let with_secret = OptionalSecret {
        secret: Some("my_secret".into()),
        public: "visible".into(),
    };

    let redacted = with_secret.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        assert_eq!(json["secret"], "[REDACTED]");
        assert_eq!(json["public"], "visible");
    } else {
        panic!("Expected Serde value");
    }

    // Test with None value
    let without_secret = OptionalSecret {
        secret: None,
        public: "visible".into(),
    };

    let redacted = without_secret.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        assert!(json["secret"].is_null());
        assert_eq!(json["public"], "visible");
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn test_into_redacted_json_with_hashmap() {
    use std::collections::HashMap;

    #[derive(Clone, Sensitive, Serialize)]
    struct Config {
        #[sensitive(Secret)]
        secrets: HashMap<String, String>,
    }

    let mut secrets = HashMap::new();
    secrets.insert("api_key".into(), "sk_live_abc123".into());
    secrets.insert("db_password".into(), "p4ssw0rd!".into());

    let config = Config { secrets };
    let redacted = config.into_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "config", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("config") {
        let secrets = json["secrets"].as_object().unwrap();

        // All values should be redacted
        for (_key, value) in secrets {
            assert_eq!(value, "[REDACTED]");
        }
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Enum tests
// ============================================================================

#[test]
fn test_into_redacted_json_enum() {
    #[derive(Clone, Sensitive, Serialize)]
    enum Credential {
        ApiKey {
            #[sensitive(Token)]
            key: String,
        },
        Password {
            username: String,
            #[sensitive(Secret)]
            password: String,
        },
    }

    // Test ApiKey variant
    let api_key = Credential::ApiKey {
        key: "api_key_12345678".into(),
    };

    let redacted = api_key.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "cred", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
        let key = json["ApiKey"]["key"].as_str().unwrap();
        assert!(key.contains('*'));
    } else {
        panic!("Expected Serde value");
    }

    // Test Password variant
    let password = Credential::Password {
        username: "admin".into(),
        password: "supersecret".into(),
    };

    let redacted = password.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "cred", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
        assert_eq!(json["Password"]["username"], "admin");
        assert_eq!(json["Password"]["password"], "[REDACTED]");
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_into_redacted_json_empty_string() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Data {
        #[sensitive(Secret)]
        value: String,
    }

    let data = Data { value: "".into() };

    let redacted = data.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        // Empty string with Full policy should become the placeholder
        assert_eq!(json["value"], "[REDACTED]");
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn test_into_redacted_json_unicode() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Greeting {
        #[sensitive(Pii)]
        message: String,
    }

    let greeting = Greeting {
        message: "こんにちは世界".into(), // "Hello World" in Japanese (7 chars)
    };

    let redacted = greeting.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "greeting", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("greeting") {
        let message = json["message"].as_str().unwrap();
        // Should be partially masked (Pii keeps last 4)
        // The original has 7 characters, so last 4 should be visible
        assert!(message.contains('*'));
        assert!(message.ends_with("ちは世界"));
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn test_into_redacted_json_no_sensitive_fields() {
    #[derive(Clone, Sensitive, Serialize)]
    struct PublicData {
        name: String,
        count: i32,
    }

    let data = PublicData {
        name: "test".into(),
        count: 42,
    };

    let redacted = data.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        // No sensitive fields, so everything should be unchanged
        assert_eq!(json["name"], "test");
        assert_eq!(json["count"], 42);
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Custom classification tests
// ============================================================================

#[test]
fn test_into_redacted_json_custom_classification() {
    // Define a custom classification that shows only last 4 digits with X masking
    #[derive(Clone, Copy)]
    struct CustomCreditCard;

    impl Classification for CustomCreditCard {}

    impl RedactionPolicy for CustomCreditCard {
        fn policy() -> TextRedactionPolicy {
            // Show last 4 digits only, mask rest with X
            TextRedactionPolicy::keep_last(4).with_mask_char('X')
        }
    }

    #[derive(Clone, Sensitive, Serialize)]
    struct Payment {
        #[sensitive(CustomCreditCard)]
        card_number: String,
        amount: f64,
    }

    let payment = Payment {
        card_number: "4111111111111111".into(),
        amount: 99.99,
    };

    let redacted = payment.into_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "payment", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("payment") {
        let card = json["card_number"].as_str().unwrap();
        // Should show only last 4 digits
        assert!(card.ends_with("1111"));
        assert!(card.contains('X'));
        assert_eq!(json["amount"], 99.99);
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Verify redaction happens before serialization (not after)
// ============================================================================

#[test]
fn test_redaction_happens_before_serialization() {
    // This test verifies that the original sensitive data never reaches slog
    use std::sync::atomic::{AtomicBool, Ordering};

    static SAW_SECRET: AtomicBool = AtomicBool::new(false);

    #[derive(Clone, Sensitive, Serialize)]
    struct Canary {
        #[sensitive(Secret)]
        secret: String,
    }

    // Create a custom serializer that checks for the secret value
    struct SecretDetector;

    impl slog::Serializer for SecretDetector {
        fn emit_arguments(&mut self, _key: slog::Key, val: &Arguments<'_>) -> slog::Result {
            if val.to_string().contains("the_actual_secret") {
                SAW_SECRET.store(true, Ordering::SeqCst);
            }
            Ok(())
        }

        fn emit_str(&mut self, _key: slog::Key, val: &str) -> slog::Result {
            if val.contains("the_actual_secret") {
                SAW_SECRET.store(true, Ordering::SeqCst);
            }
            Ok(())
        }

        fn emit_serde(&mut self, _key: slog::Key, val: &dyn slog::SerdeValue) -> slog::Result {
            let json = serde_json::to_string(val.as_serde()).unwrap_or_default();
            if json.contains("the_actual_secret") {
                SAW_SECRET.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    let canary = Canary {
        secret: "the_actual_secret".into(),
    };

    let redacted = canary.into_redacted_json();
    let mut detector = SecretDetector;
    serialize_to_capture(&redacted, "canary", &mut detector);

    // The secret should never have been seen by the serializer
    assert!(
        !SAW_SECRET.load(Ordering::SeqCst),
        "Secret value leaked to slog serializer!"
    );
}
