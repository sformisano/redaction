//! Marker types for "what kind of sensitive data is this?"
//!
//! These types are zero-sized. They exist only at the type level so policies can
//! be attached without storing any runtime data.

/// Marker trait for classification categories.
///
/// Implement this for zero-sized marker types (unit structs):
///
/// ```rust
/// use redaction::Classification;
///
/// #[derive(Clone, Copy)]
/// struct MyClassification;
///
/// impl Classification for MyClassification {}
/// ```
pub trait Classification {}

/// Classification marker for account identifiers.
#[derive(Clone, Copy)]
pub struct AccountId;
impl Classification for AccountId {}

/// Classification marker for blockchain addresses (e.g., Ethereum, Bitcoin).
#[derive(Clone, Copy)]
pub struct BlockchainAddress;
impl Classification for BlockchainAddress {}

/// Classification marker for credit card numbers or PANs.
#[derive(Clone, Copy)]
pub struct CreditCard;
impl Classification for CreditCard {}

/// Classification marker for dates of birth.
#[derive(Clone, Copy)]
pub struct DateOfBirth;
impl Classification for DateOfBirth {}

/// Classification marker for email addresses.
#[derive(Clone, Copy)]
pub struct Email;
impl Classification for Email {}

/// Classification marker for IP addresses.
#[derive(Clone, Copy)]
pub struct IpAddress;
impl Classification for IpAddress {}

/// Classification marker for government-issued identifiers.
#[derive(Clone, Copy)]
pub struct NationalId;
impl Classification for NationalId {}

/// Classification marker for phone numbers.
#[derive(Clone, Copy)]
pub struct PhoneNumber;
impl Classification for PhoneNumber {}

/// Classification marker for personally identifiable information.
#[derive(Clone, Copy)]
pub struct Pii;
impl Classification for Pii {}

/// Classification marker for secrets such as passwords or private keys.
#[derive(Clone, Copy)]
pub struct Secret;
impl Classification for Secret {}

/// Classification marker for session identifiers.
#[derive(Clone, Copy)]
pub struct SessionId;
impl Classification for SessionId {}

/// Classification marker for authentication tokens and API keys.
#[derive(Clone, Copy)]
pub struct Token;
impl Classification for Token {}
