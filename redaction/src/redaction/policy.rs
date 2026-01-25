//! Redaction policies for string-like values.
//!
//! Policies are pure string transformations. They do not traverse structures,
//! pick classifications, or make runtime decisions about sensitivity.

use std::borrow::Cow;

use crate::classification::{
    AccountId, BlockchainAddress, Classification, CreditCard, DateOfBirth, Email, IpAddress,
    NationalId, PhoneNumber, Pii, Secret, SessionId, Token,
};

/// Configuration that keeps selected segments visible while masking the remainder.
///
/// The policy operates on Unicode scalar values. If the configuration keeps the
/// entire value visible, the output is unchanged.
///
/// Use the constructor methods [`KeepConfig::first`] and [`KeepConfig::last`]
/// to create instances.
#[derive(Clone, Copy, Debug)]
pub struct KeepConfig {
    /// Number of leading characters to keep visible.
    visible_prefix: usize,
    /// Number of trailing characters to keep visible.
    visible_suffix: usize,
    /// Symbol used to mask the middle.
    mask_char: char,
}

impl KeepConfig {
    /// Constructs a configuration that keeps only the first `visible_prefix` scalar values.
    #[must_use]
    pub fn first(visible_prefix: usize) -> Self {
        Self {
            visible_prefix,
            visible_suffix: 0,
            mask_char: '*',
        }
    }

    /// Constructs a configuration that keeps only the last `visible_suffix` scalar values.
    #[must_use]
    pub fn last(visible_suffix: usize) -> Self {
        Self {
            visible_prefix: 0,
            visible_suffix,
            mask_char: '*',
        }
    }

    /// Constructs a configuration that keeps both leading and trailing characters visible.
    ///
    /// If `visible_prefix + visible_suffix >= total_length`, the entire value
    /// is kept visible (no masking occurs).
    #[must_use]
    pub fn both(visible_prefix: usize, visible_suffix: usize) -> Self {
        Self {
            visible_prefix,
            visible_suffix,
            mask_char: '*',
        }
    }

    /// Uses a specific masking character.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        self.mask_char = mask_char;
        self
    }

    /// Sets the masking character in place.
    pub(crate) fn set_mask_char(&mut self, mask_char: char) {
        self.mask_char = mask_char;
    }

    /// Applies the policy to a string value.
    ///
    /// Empty strings are returned as-is.
    ///
    /// If `visible_prefix + visible_suffix >= total_length`, the entire value
    /// is kept visible (no masking occurs).
    pub(crate) fn apply_to(&self, value: &str) -> String {
        let mut chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total == 0 {
            return String::new();
        }

        // If keep spans cover or exceed the total length, return unchanged
        if self.visible_prefix + self.visible_suffix >= total {
            return chars.into_iter().collect();
        }

        // Mask the middle portion
        for ch in &mut chars[self.visible_prefix..(total - self.visible_suffix)] {
            *ch = self.mask_char;
        }
        chars.into_iter().collect()
    }
}

/// Configuration that masks selected segments while leaving the remainder unchanged.
///
/// Masking operates on Unicode scalar values and bounds the masked spans for
/// short inputs.
///
/// Use the constructor methods [`MaskConfig::first`] and [`MaskConfig::last`]
/// to create instances.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_field_names)] // Field names are descriptive for internal use
pub struct MaskConfig {
    /// Number of leading characters to mask.
    mask_prefix: usize,
    /// Number of trailing characters to mask.
    mask_suffix: usize,
    /// Symbol used to mask the selected segments.
    mask_char: char,
}

impl MaskConfig {
    /// Masks only the initial `mask_prefix` characters.
    #[must_use]
    pub fn first(mask_prefix: usize) -> Self {
        Self {
            mask_prefix,
            mask_suffix: 0,
            mask_char: '*',
        }
    }

    /// Masks only the final `mask_suffix` characters.
    #[must_use]
    pub fn last(mask_suffix: usize) -> Self {
        Self {
            mask_prefix: 0,
            mask_suffix,
            mask_char: '*',
        }
    }

    /// Masks both leading and trailing characters.
    ///
    /// If `mask_prefix + mask_suffix >= total_length`, the entire value
    /// is masked.
    #[must_use]
    pub fn both(mask_prefix: usize, mask_suffix: usize) -> Self {
        Self {
            mask_prefix,
            mask_suffix,
            mask_char: '*',
        }
    }

    /// Uses a specific masking character.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        self.mask_char = mask_char;
        self
    }

    /// Sets the masking character in place.
    pub(crate) fn set_mask_char(&mut self, mask_char: char) {
        self.mask_char = mask_char;
    }

    /// Applies the policy to a string value.
    ///
    /// Empty strings are returned as-is.
    ///
    /// If `mask_prefix + mask_suffix >= total_length`, the entire value
    /// is masked.
    pub(crate) fn apply_to(&self, value: &str) -> String {
        let mut chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total == 0 {
            return String::new();
        }

        // If mask spans cover or exceed total length, mask everything
        if self.mask_prefix + self.mask_suffix >= total {
            chars.fill(self.mask_char);
            return chars.into_iter().collect();
        }

        // Mask the prefix portion
        for ch in &mut chars[..self.mask_prefix] {
            *ch = self.mask_char;
        }

        // Mask the suffix portion
        if self.mask_suffix > 0 {
            let start = total - self.mask_suffix;
            for ch in &mut chars[start..] {
                *ch = self.mask_char;
            }
        }

        chars.into_iter().collect()
    }
}

/// Associates a classification type with a concrete string redaction policy.
///
/// The policy is defined per classification type and is independent of runtime context.
pub trait RedactionPolicy: Classification {
    /// Returns the policy for this classification.
    fn policy() -> TextRedactionPolicy;
}

/// Default placeholder used for full redaction.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// A redaction strategy for string-like values.
///
/// All strategies operate on Unicode scalar values and return an owned `String`.
// Use `Cow` so callers can provide borrowed or owned placeholders.
#[derive(Clone, Debug)]
pub enum TextRedactionPolicy {
    /// Replace the entire value with a fixed placeholder.
    Full {
        /// The placeholder text to use.
        placeholder: Cow<'static, str>,
    },
    /// Keep configured segments visible while masking everything else.
    Keep(KeepConfig),
    /// Mask configured segments while leaving the remainder untouched.
    Mask(MaskConfig),
}

impl TextRedactionPolicy {
    /// Constructs [`TextRedactionPolicy::Full`] using [`REDACTED_PLACEHOLDER`].
    #[must_use]
    pub fn default_full() -> Self {
        Self::Full {
            placeholder: Cow::Borrowed(REDACTED_PLACEHOLDER),
        }
    }

    /// Constructs [`TextRedactionPolicy::Full`] using a custom placeholder.
    #[must_use]
    pub fn full_with<P>(placeholder: P) -> Self
    where
        P: Into<Cow<'static, str>>,
    {
        Self::Full {
            placeholder: placeholder.into(),
        }
    }

    /// Constructs [`TextRedactionPolicy::Keep`] from an explicit configuration.
    #[must_use]
    pub fn keep_with(config: KeepConfig) -> Self {
        Self::Keep(config)
    }

    /// Keeps only the first `visible_prefix` scalar values in clear text.
    #[must_use]
    pub fn keep_first(visible_prefix: usize) -> Self {
        Self::keep_with(KeepConfig::first(visible_prefix))
    }

    /// Keeps only the last `visible_suffix` scalar values in clear text.
    #[must_use]
    pub fn keep_last(visible_suffix: usize) -> Self {
        Self::keep_with(KeepConfig::last(visible_suffix))
    }

    /// Masks segments using the provided configuration.
    #[must_use]
    pub fn mask_with(config: MaskConfig) -> Self {
        Self::Mask(config)
    }

    /// Masks the first `mask_prefix` scalar values.
    #[must_use]
    pub fn mask_first(mask_prefix: usize) -> Self {
        Self::mask_with(MaskConfig::first(mask_prefix))
    }

    /// Masks the last `mask_suffix` scalar values.
    #[must_use]
    pub fn mask_last(mask_suffix: usize) -> Self {
        Self::mask_with(MaskConfig::last(mask_suffix))
    }

    /// Overrides the masking character used by keep/mask policies.
    ///
    /// This method has no effect on [`TextRedactionPolicy::Full`] because full
    /// redaction replaces the entire value with a placeholder string rather
    /// than masking individual characters.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        match &mut self {
            TextRedactionPolicy::Full { .. } => {}
            TextRedactionPolicy::Keep(config) => {
                config.set_mask_char(mask_char);
            }
            TextRedactionPolicy::Mask(config) => {
                config.set_mask_char(mask_char);
            }
        }
        self
    }

    /// Applies the policy to `value`.
    ///
    /// This method is total (it does not return errors).
    #[must_use]
    pub fn apply_to(&self, value: &str) -> String {
        match self {
            TextRedactionPolicy::Full { placeholder } => placeholder.clone().into_owned(),
            TextRedactionPolicy::Keep(config) => config.apply_to(value),
            TextRedactionPolicy::Mask(config) => config.apply_to(value),
        }
    }
}

impl Default for TextRedactionPolicy {
    fn default() -> Self {
        Self::default_full()
    }
}

/// Default policies for built-in classifications.
impl RedactionPolicy for Secret {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

impl RedactionPolicy for Pii {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for Token {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for Email {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_first(2)
    }
}

impl RedactionPolicy for CreditCard {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for PhoneNumber {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

impl RedactionPolicy for IpAddress {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for AccountId {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for SessionId {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for NationalId {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

impl RedactionPolicy for DateOfBirth {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

impl RedactionPolicy for BlockchainAddress {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(6)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountId, BlockchainAddress, KeepConfig, MaskConfig, RedactionPolicy, Secret,
        TextRedactionPolicy, Token, REDACTED_PLACEHOLDER,
    };

    #[test]
    fn keep_policy_allows_full_visibility() {
        let policy = TextRedactionPolicy::keep_with(KeepConfig::first(3));
        assert_eq!(policy.apply_to("ab"), "ab");
    }

    #[test]
    fn keep_policy_respects_mask_char() {
        let policy = TextRedactionPolicy::keep_first(2).with_mask_char('#');
        assert_eq!(policy.apply_to("abcdef"), "ab####");
    }

    #[test]
    fn full_policy_uses_default_placeholder() {
        let policy = TextRedactionPolicy::default_full();
        assert_eq!(policy.apply_to("secret"), REDACTED_PLACEHOLDER);
    }

    #[test]
    fn full_policy_uses_custom_placeholder() {
        let policy = TextRedactionPolicy::full_with("<redacted>");
        assert_eq!(policy.apply_to("secret"), "<redacted>");
    }

    #[test]
    fn mask_policy_masks_first_and_last_segments() {
        let policy = TextRedactionPolicy::mask_first(2);
        assert_eq!(policy.apply_to("abcdef"), "**cdef");

        let policy = TextRedactionPolicy::mask_last(3);
        assert_eq!(policy.apply_to("abcdef"), "abc***");
    }

    #[test]
    fn mask_policy_respects_custom_mask_char() {
        let policy = TextRedactionPolicy::mask_with(MaskConfig::last(2)).with_mask_char('#');
        assert_eq!(policy.apply_to("abcd"), "ab##");
    }

    #[test]
    fn classification_policies_use_expected_defaults() {
        let policy = Secret::policy();
        assert_eq!(policy.apply_to("secret"), REDACTED_PLACEHOLDER);

        let policy = Token::policy();
        assert_eq!(policy.apply_to("abcdef"), "**cdef");

        let policy = AccountId::policy();
        assert_eq!(policy.apply_to("acct_123456"), "*******3456");

        let policy = BlockchainAddress::policy();
        assert_eq!(policy.apply_to("abcdef123456"), "******123456");
    }

    #[test]
    fn empty_string_returns_empty_for_keep_and_mask() {
        // Empty strings are left unchanged for keep/mask policies.
        let keep_policy = TextRedactionPolicy::keep_first(4);
        assert_eq!(keep_policy.apply_to(""), "");

        let mask_policy = TextRedactionPolicy::mask_first(4);
        assert_eq!(mask_policy.apply_to(""), "");

        let full_policy = TextRedactionPolicy::default_full();
        assert_eq!(full_policy.apply_to(""), REDACTED_PLACEHOLDER);
    }

    #[test]
    fn keep_both_overlap_keeps_entire_value() {
        // When prefix + suffix >= total, keep everything visible
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abc"), "abc"); // 2 + 2 = 4 >= 3

        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(3, 3));
        assert_eq!(policy.apply_to("abcd"), "abcd"); // 3 + 3 = 6 >= 4

        // Edge case: exactly equals total
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcd"), "abcd"); // 2 + 2 = 4 >= 4
    }

    #[test]
    fn mask_both_overlap_masks_entire_value() {
        // When prefix + suffix >= total, mask everything
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abc"), "***"); // 2 + 2 = 4 >= 3

        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(3, 3));
        assert_eq!(policy.apply_to("abcd"), "****"); // 3 + 3 = 6 >= 4

        // Edge case: exactly equals total
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcd"), "****"); // 2 + 2 = 4 >= 4
    }

    #[test]
    fn keep_both_no_overlap() {
        // Normal case: prefix + suffix < total
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcdef"), "ab**ef"); // keep first 2 and last 2
    }

    #[test]
    fn mask_both_no_overlap() {
        // Normal case: prefix + suffix < total
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcdef"), "**cd**"); // mask first 2 and last 2
    }
}
