// Exercise compact/full block delivery through Peers, the production adapters,
// transaction pool, and chain validation. No network sockets are opened: tests
// inspect the queued full-block request and explicitly deliver the response.
// A receive call can return true while waiting for a full block or its parent,
// so assertions also check chain height, orphan admission, and persisted bans.
// Run these tests from the repository root with:
// cargo test -p mwc_servers --features test-support --offline --lib compact_block_tests

use super::*;
use mwc_chain::types::NoopAdapter;
use mwc_core::core::{transaction, KernelFeatures, OutputFeatures, Weighting};
use mwc_core::libtx::{build, reward, ProofBuilder};
use mwc_core::{consensus, pow};
use mwc_crates::chrono;
use mwc_crates::secp::{ContextFlag, SecretKey};
use mwc_crates::tempfile::TempDir;
use mwc_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use mwc_p2p::store::PeerStore;
use mwc_p2p::types::{Direction, PeerLiveInfo};
use mwc_p2p::{Capabilities, ChainAdapter as _, P2PConfig, Peers};
use mwc_pool::types::{NoopPoolAdapter, PoolConfig};
use mwc_pool::{TransactionPool, TxSource};
use mwc_util::StopState;

type TestPool = TransactionPool<PoolToChainAdapter, NoopPoolAdapter>;

// Each fixture has its own context and temporary chain/peer stores. It starts
// at height 3, with the height-1 coinbase mature enough to spend. Using the real
// chain adapter and PeerStore exposes bans from both chain rejection callbacks
// and the Peers wrapper's handling of a false receive result.
struct Fixture {
	context: u32,
	secp: Secp256k1,
	keychain: ExtKeychain,
	chain: Arc<mwc_chain::Chain>,
	pool: Arc<RwLock<TestPool>>,
	adapter: Arc<NetToChainAdapter<PoolToChainAdapter, NoopPoolAdapter>>,
	manager: Arc<SyncManager>,
	peers: Arc<Peers>,
	peer: PeerInfo,
	history: Vec<core::Block>,
	_chain_dir: TempDir,
	_peer_dir: TempDir,
}

impl Fixture {
	fn new(context: u32) -> Self {
		global::init_global_chain_type(context, global::ChainTypes::AutomatedTesting).unwrap();
		global::init_global_nrd_enabled(context, false).unwrap();
		global::init_global_accept_fee_base(context, 1).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[42; 32], false).unwrap();
		let chain_dir = TempDir::new().unwrap();
		let peer_dir = TempDir::new().unwrap();
		let sync_state = Arc::new(SyncState::new());
		sync_state.reset();
		let pool_chain = Arc::new(PoolToChainAdapter::new());
		let pool = Arc::new(RwLock::new(TransactionPool::new(
			context,
			PoolConfig::default(),
			pool_chain.clone(),
			Arc::new(NoopPoolAdapter {}),
		)));
		let chain_adapter = Arc::new(ChainToPoolAndNetAdapter::new(
			pool.clone(),
			sync_state.clone(),
			vec![],
		));
		let chain = Arc::new(init_chain(
			context,
			&secp,
			&chain_dir,
			chain_adapter.clone(),
		));
		pool_chain.set_chain(chain.clone()).unwrap();
		let manager = Arc::new(SyncManager::new(
			chain.clone(),
			sync_state.clone(),
			Arc::new(StopState::new()),
		));
		let adapter = Arc::new(
			NetToChainAdapter::new(
				context,
				sync_state,
				chain.clone(),
				manager.clone(),
				pool.clone(),
				// Regular block validation stays enabled; skip the optional extra
				// whole-chain diagnostic performed after accepting each block.
				ChainValidationMode::Disabled,
				vec![],
			)
			.unwrap(),
		);
		let peers = Arc::new(Peers::new(
			PeerStore::new(context, peer_dir.path().to_str().unwrap()).unwrap(),
			adapter.clone(),
			&P2PConfig::default(),
		));
		adapter.init(peers.clone()).unwrap();
		chain_adapter.init(peers.clone(), manager.clone()).unwrap();
		let peer = PeerInfo {
			capabilities: Capabilities::BLOCK_EXTRA,
			user_agent: "compact-block-test".into(),
			version: ProtocolVersion::local(),
			addr: PeerAddr::Ip("127.0.0.1:3414".parse().unwrap()),
			direction: Direction::Inbound,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::min()))),
			tx_base_fee: 1,
		};
		let mut fixture = Self {
			context,
			secp,
			keychain,
			chain,
			pool,
			adapter,
			manager,
			peers,
			peer,
			history: vec![],
			_chain_dir: chain_dir,
			_peer_dir: peer_dir,
		};
		// Mature the first coinbase so both proof variants spend a real UTXO.
		for _ in 0..3 {
			let block = fixture.block(&[]);
			fixture
				.chain
				.process_block(
					&mut fixture.secp,
					block.clone(),
					Options::NONE,
					HashSet::new(),
				)
				.unwrap();
			fixture.history.push(block);
		}
		fixture
	}

	fn block(&mut self, txs: &[Transaction]) -> core::Block {
		next_block(&self.chain, &mut self.secp, &self.keychain, txs)
	}

	// Return (mined, local) versions of the same spend. An output owner knows
	// the blinding key and can create different valid rangeproofs for the same
	// commitment. Only proof bytes change; both versions have the same kernel
	// and compact short ID, but produce different rangeproof MMR roots.
	// Validate both versions below so the scenario does not depend on admitting
	// an invalid transaction to the pool.
	fn proof_variants(&mut self) -> (Transaction, Transaction) {
		let input = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let output = ExtKeychain::derive_key_id(3, 0, 0, 30, 0).unwrap();
		let value = consensus::calc_mwc_block_reward(self.context, 1);
		let fee = 20_000_000u64;
		let builder = ProofBuilder::new(&self.secp, &self.keychain).unwrap();
		let tx = build::transaction(
			self.context,
			&mut self.secp,
			KernelFeatures::Plain {
				fee: fee.try_into().unwrap(),
			},
			&[
				build::feature_input(value, OutputFeatures::Coinbase, input),
				build::height_tagged_output(value - fee, output.clone(), 1),
			],
			&self.keychain,
			&builder,
		)
		.unwrap();
		let mut variant = tx.clone();
		let blind = self
			.keychain
			.derive_key(
				&self.secp,
				value - fee,
				&output,
				SwitchCommitmentType::Regular,
			)
			.unwrap();
		let rewind = SecretKey::from_slice(&self.secp, &[17; 32]).unwrap();
		let private = SecretKey::from_slice(&self.secp, &[18; 32]).unwrap();
		variant.body.outputs[0].proof = self
			.secp
			.bullet_proof(value - fee, blind, rewind, private, None, None)
			.unwrap();
		for candidate in [&tx, &variant] {
			candidate
				.validate(self.context, Weighting::AsTransaction, &mut self.secp)
				.unwrap();
			self.chain.validate_tx(candidate).unwrap();
		}
		assert_ne!(tx.outputs()[0].proof, variant.outputs()[0].proof);
		assert_eq!(
			tx.kernels()[0].hash(self.context).unwrap(),
			variant.kernels()[0].hash(self.context).unwrap()
		);
		(tx, variant)
	}

	// Use normal pool admission so reconstruction retrieves an accepted transaction.
	fn add_transaction(&mut self, tx: Transaction) {
		TestPool::submit_to_pool(
			&self.pool,
			TxSource::Broadcast,
			tx,
			false,
			&self.chain.head_header().unwrap(),
			&mut self.secp,
		)
		.unwrap();
	}
}

fn init_chain(
	context: u32,
	secp: &Secp256k1,
	dir: &TempDir,
	adapter: Arc<dyn ChainAdapter + Send + Sync>,
) -> mwc_chain::Chain {
	mwc_chain::Chain::init(
		secp,
		context,
		dir.path().to_str().unwrap().into(),
		adapter,
		global::get_genesis_block(secp, context).unwrap(),
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
		false,
	)
	.unwrap()
}

// Build a valid next block with chain-derived roots, coinbase binding, and real
// proof of work at automated-testing difficulty. The caller controls when this
// block is accepted locally or delivered to another chain in the test.
fn next_block(
	chain: &mwc_chain::Chain,
	secp: &mut Secp256k1,
	keychain: &ExtKeychain,
	txs: &[Transaction],
) -> core::Block {
	let context = chain.get_context_id();
	let parent = chain.head_header().unwrap();
	let height = parent.height + 1;
	let key = ExtKeychain::derive_key_id(1, u32::try_from(height).unwrap(), 0, 0, 0).unwrap();
	let aggregate = transaction::aggregate(context, txs, secp).unwrap();
	let binding = chain
		.coinbase_binding_for_template(secp, &parent, &aggregate.body)
		.unwrap();
	let builder = ProofBuilder::new(secp, keychain).unwrap();
	let (output, kernel, opening) = reward::output_s2c(
		context,
		keychain,
		&builder,
		&key,
		aggregate.fee().unwrap(),
		height,
		secp,
		binding.digest().unwrap(),
	)
	.unwrap();
	let difficulty = consensus::next_difficulty(
		context,
		height,
		chain.difficulty_iter().unwrap(),
		&mut consensus::DifficultyCache::new(),
	)
	.unwrap();
	let mut block = core::Block::new(
		context,
		&parent,
		txs,
		difficulty.difficulty,
		(output, kernel),
		secp,
	)
	.unwrap();
	block.coinbase_opening =
		consensus::is_coinbase_binding_enabled(context, height).then_some(opening);
	block.header.timestamp = parent.timestamp + chrono::Duration::seconds(60);
	block.header.pow.secondary_scaling = difficulty.secondary_scaling;
	chain.set_txhashset_roots(secp, &mut block).unwrap();
	pow::pow_size(
		context,
		&mut block.header,
		difficulty.difficulty,
		global::proofsize(context),
		global::min_edge_bits(context),
	)
	.unwrap();
	block
}

// Workflow: mine height 4 with one proof, put the other proof in the receiver's
// pool, and deliver the compact block twice. Then deliver an incorrect full
// body from another peer and the correct full body from the original sender.
// Expected: reconstruction queues a full-block request without accepting the
// guessed body or banning the sender; the repeat is suppressed by the cooldown.
// Only the peer supplying the incorrect full body is banned. The correct full
// response advances the chain from height 3 to 4.
#[test]
fn compact_proof_variant_requests_full_block_without_banning_sender() {
	let mut f = Fixture::new(1_934_001);
	let (mined, local) = f.proof_variants();
	let block = f.block(&[mined]);
	let compact = CompactBlock::from(block.clone()).unwrap();
	let hash = compact.hash(f.context).unwrap();
	let hydrated = core::Block::hydrate_from(compact.clone(), &[local.clone()]).unwrap();
	// The old stateless precheck succeeds; only complete chain validation finds
	// that our pool's proof differs from the one committed by the mined header.
	hydrated
		.validate(
			f.context,
			&f.chain.head_header().unwrap().total_kernel_offset,
			&mut f.secp,
		)
		.unwrap();
	f.add_transaction(local);
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact.clone(), &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 3);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
	assert!(f.manager.has_block_request(&f.peer.addr, &hash));
	// An immediate repeat must not start another reconstruction attempt. Its
	// cached completion timestamp must remain unchanged throughout the cooldown.
	let finished = f
		.adapter
		.compact_block_reconstruction_cache
		.read_recursive()[&hash];
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert_eq!(
		f.adapter
			.compact_block_reconstruction_cache
			.read_recursive()[&hash],
		finished
	);

	// Suppression applies only to reconstructed guesses. A different peer that
	// actually supplies this incorrect full body must still be penalized.
	let mut bad_peer = f.peer.clone();
	bad_peer.addr = PeerAddr::Ip("127.0.0.2:3414".parse().unwrap());
	assert!(!f
		.peers
		.block_received(&mut f.secp, hydrated, &bad_peer, Options::NONE)
		.unwrap());
	assert!(f.peers.is_banned(&bad_peer.addr).unwrap());
	// Complete the fallback with the exact mined body. The earlier failed local
	// guess must not prevent acceptance or leave the honest sender banned.
	assert!(f
		.peers
		.block_received(&mut f.secp, block, &f.peer, Options::NONE)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 4);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

// Workflow: mine height 4 and place that exact transaction, including its proof,
// in the receiver's pool before delivering the compact block.
// Expected: reconstruction passes full chain validation, advances the head to
// height 4, and neither queues a full-block request nor bans the sender. This
// ensures the fallback fix preserves the successful compact-block path.
#[test]
fn compact_matching_transaction_is_accepted_without_full_block_request() {
	let mut f = Fixture::new(1_934_002);
	let (tx, _) = f.proof_variants();
	let block = f.block(&[tx.clone()]);
	let compact = CompactBlock::from(block).unwrap();
	let hash = compact.hash(f.context).unwrap();
	f.add_transaction(tx);
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 4);
	assert!(!f.manager.has_block_request(&f.peer.addr, &hash));
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

// Workflow: a second chain shares blocks 1..3 and produces parent 4 and child 5.
// The receiver knows only parent 4's header and holds the alternate proof for
// child 5. Deliver compact child 5, full child 5, then full parent 4, in that order.
// Expected: the guessed child stays out of the orphan pool and triggers a full
// request without banning its sender. The complete child can then be cached as
// an orphan; delivering its parent drains that orphan and advances the head to 5.
#[test]
fn compact_missing_parent_fetches_full_body_before_orphan_admission() {
	let mut f = Fixture::new(1_934_003);
	let (mined, local) = f.proof_variants();
	let producer_dir = TempDir::new().unwrap();
	let producer = init_chain(f.context, &f.secp, &producer_dir, Arc::new(NoopAdapter {}));
	for block in &f.history {
		producer
			.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
			.unwrap();
	}
	let parent = next_block(&producer, &mut f.secp, &f.keychain, &[]);
	producer
		.process_block(&mut f.secp, parent.clone(), Options::NONE, HashSet::new())
		.unwrap();
	let child = next_block(&producer, &mut f.secp, &f.keychain, &[mined]);
	let compact = CompactBlock::from(child.clone()).unwrap();
	let hash = compact.hash(f.context).unwrap();
	// Knowing the parent header lets the child's header pass validation, while
	// withholding the parent body forces the reconstructed child down the orphan
	// path. This isolates deferred body validation from missing-header handling.
	f.chain
		.process_block_header(&parent.header, Options::NONE)
		.unwrap();
	f.add_transaction(local);
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert!(!f.chain.is_orphan(&hash));
	assert!(f.manager.has_block_request(&f.peer.addr, &hash));
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());

	// A full response can now occupy the orphan slot with the correct body.
	// When its parent arrives, deferred validation must accept it without
	// inheriting the failed local reconstruction or banning its honest supplier.
	assert!(f
		.peers
		.block_received(&mut f.secp, child, &f.peer, Options::NONE)
		.unwrap());
	assert!(f.chain.is_orphan(&hash));
	// Parent arrival must replay the complete child supplied above, preserving
	// that body and its peer attribution through deferred validation.
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &f.peer, Options::NONE)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 5);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

// Workflow: construct a valid nonempty compact block, then change its header
// height without rebuilding the block or its proof of work and deliver it.
// Expected: reject the peer-supplied header before transaction reconstruction,
// return false, and persist a ban. Reconstruction fallback must preserve peer
// penalties for invalid data that the sender actually supplied.
#[test]
fn compact_invalid_header_still_bans_sender() {
	let mut f = Fixture::new(1_934_004);
	let (tx, _) = f.proof_variants();
	let block = f.block(&[tx]);
	let mut compact = CompactBlock::from(block).unwrap();
	compact.header.height += 1;
	assert!(!f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert!(f.peers.is_banned(&f.peer.addr).unwrap());
}
