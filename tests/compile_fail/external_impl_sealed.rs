use hpke_ng::{HpkeMode, PskFreeMode};

// Attempting to implement the `sealed` supertrait on an external type.
// sealed::Sealed is pub(crate), so this fails with E0603 (private module),
// proving the set of valid HpkeMode implementors is structurally closed.
struct SomeModeTag;

impl hpke_ng::sealed::Sealed for SomeModeTag {}

impl HpkeMode for SomeModeTag {
	const MODE_BYTE: u8 = 0x00;
}

impl PskFreeMode for SomeModeTag {}

fn main() {}
