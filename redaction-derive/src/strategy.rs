//! Parsing of `#[sensitive(...)]` field attributes.
//!
//! This module maps attribute syntax to traversal decisions and produces
//! structured errors for invalid forms.

use proc_macro2::Span;
use syn::{spanned::Spanned, Attribute, Meta, Result};

/// Field transformation strategy based on `#[sensitive(...)]` attributes.
///
/// ## Strategy Mapping
///
/// | Attribute | Strategy | Behavior |
/// |-----------|----------|----------|
/// | None | `PassThrough` | Field passes through unchanged |
/// | `#[sensitive]` | `Walk` | Walk containers OR redact scalars |
/// | `#[sensitive(Class)]` | `Classify(Class)` | Apply classification policy |
#[derive(Clone, Debug)]
pub(crate) enum Strategy {
    /// No annotation: pass through unchanged.
    ///
    /// This is the default for fields without `#[sensitive(...)]`.
    /// External types like `DateTime<Utc>` or `Decimal` work automatically.
    PassThrough,
    /// Bare `#[sensitive]`: walk containers or redact scalars.
    ///
    /// - For scalars (i32, bool, etc.): redact to default value
    /// - For structs: walk using `SensitiveContainer::redact_with`
    Walk,
    /// `#[sensitive(Classification)]`: apply classification policy.
    ///
    /// The classification type (e.g., `Secret`, `Pii`) determines how
    /// the value is redacted via `RedactionPolicy`.
    Classify(syn::Path),
}

fn set_strategy(target: &mut Option<Strategy>, next: Strategy, span: Span) -> Result<()> {
    if target.is_some() {
        return Err(syn::Error::new(
            span,
            "multiple #[sensitive] attributes specified on the same field",
        ));
    }
    *target = Some(next);
    Ok(())
}

pub(crate) fn parse_field_strategy(attrs: &[Attribute]) -> Result<Strategy> {
    let mut strategy: Option<Strategy> = None;
    for attr in attrs {
        if !attr.path().is_ident("sensitive") {
            continue;
        }

        match &attr.meta {
            Meta::Path(_) => {
                // Bare #[sensitive] - walk containers or redact scalars
                set_strategy(&mut strategy, Strategy::Walk, attr.span())?;
            }
            Meta::List(list) => {
                // Parse as a classification path (e.g., #[sensitive(Secret)])
                match syn::parse2::<syn::Path>(list.tokens.clone()) {
                    Ok(path) => {
                        set_strategy(&mut strategy, Strategy::Classify(path), attr.span())?;
                    }
                    Err(_) => {
                        return Err(syn::Error::new(
                            attr.span(),
                            "expected a classification type (e.g., #[sensitive(Secret)])",
                        ));
                    }
                }
            }
            Meta::NameValue(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "name-value syntax is not supported for #[sensitive]",
                ));
            }
        }
    }

    // Default: no annotation means pass through unchanged
    Ok(strategy.unwrap_or(Strategy::PassThrough))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::DeriveInput;

    use super::*;

    fn parse_attrs(tokens: proc_macro2::TokenStream) -> Vec<Attribute> {
        let input: DeriveInput = syn::parse2(quote! {
            #tokens
            struct Dummy;
        })
        .expect("should parse as DeriveInput");
        input.attrs
    }

    #[test]
    fn no_attribute_returns_passthrough() {
        let attrs = parse_attrs(quote! {});
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::PassThrough));
    }

    #[test]
    fn bare_sensitive_returns_walk() {
        let attrs = parse_attrs(quote! { #[sensitive] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::Walk));
    }

    #[test]
    fn sensitive_with_classification_returns_classify() {
        let attrs = parse_attrs(quote! { #[sensitive(Secret)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Classify(path) => {
                assert!(path.is_ident("Secret"));
            }
            _ => panic!("expected Classify"),
        }
    }

    #[test]
    fn sensitive_with_path_classification() {
        let attrs = parse_attrs(quote! { #[sensitive(my_module::MyClassification)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Classify(path) => {
                assert_eq!(path.segments.len(), 2);
            }
            _ => panic!("expected Classify"),
        }
    }

    #[test]
    fn multiple_sensitive_attributes_error() {
        let attrs = parse_attrs(quote! {
            #[sensitive]
            #[sensitive(Secret)]
        });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("multiple #[sensitive] attributes"));
    }

    #[test]
    fn name_value_syntax_error() {
        let attrs = parse_attrs(quote! { #[sensitive = "value"] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name-value syntax is not supported"));
    }

    #[test]
    fn invalid_classification_syntax_error() {
        let attrs = parse_attrs(quote! { #[sensitive(123)] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected a classification type"));
    }

    #[test]
    fn other_attributes_ignored() {
        let attrs = parse_attrs(quote! {
            #[derive(Clone)]
            #[serde(skip)]
        });
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::PassThrough));
    }
}
