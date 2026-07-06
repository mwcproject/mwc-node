use mwc_core::global::{set_local_chain_type, set_local_nrd_enabled, ChainTypes};

pub fn init() {
	set_local_chain_type(ChainTypes::Mainnet);
	set_local_nrd_enabled(true);
}
