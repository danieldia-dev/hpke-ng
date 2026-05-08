//! Sealed-trait marker preventing external implementations of public traits.

/// Crate-internal seal: only types defined in this crate may implement public traits.
#[allow(dead_code)]
pub trait Sealed {}
