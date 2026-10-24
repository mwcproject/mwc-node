// Exercise compact/full block delivery through Peers, the production adapters,
// transaction pool, and chain validation. No network sockets are opened: tests
// inspect the queued full-block request and explicitly deliver the response.
// A receive call can return true while waiting for a full block or its parent,
// so assertions also check chain height, deferred body application, and persisted bans.
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

	fn request_missing_bodies(
		&self,
	) -> mwc_crates::crossbeam::channel::Receiver<mwc_p2p::msg::Msg> {
		let (peer, receiver) =
			mwc_p2p::Peer::connected_for_test(self.peer.clone(), self.context, self.peers.clone());
		self.peers.add_connected(Arc::new(peer)).unwrap();
		self.manager.sync_request(&self.peers).unwrap();
		receiver
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

#[test]
fn peer_head_follows_body_progress_at_activation() {
	let mut f = Fixture::new(1_934_005);
	let block = f.block(&[]);
	let activation = consensus::coinbase_binding_activation_height(f.context);
	assert_eq!(block.header.height, activation);
	f.chain
		.process_block_header(&block.header, Options::NONE)
		.unwrap();
	// Header validation alone must not advance the head used by Ping/Pong and
	// activation-based peer rotation. Both height and work come from the body head.
	assert_eq!(f.chain.header_head().unwrap().height, activation);
	let head = f.peers.get_head().unwrap();
	assert_eq!(head, f.chain.head_header().unwrap());
	assert_eq!(head.height, activation - 1);
	// Applying the body then publishes that complete header as the new head.
	f.chain
		.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
		.unwrap();
	assert_eq!(f.peers.get_head().unwrap(), block.header);
}

#[test]
fn peer_head_stays_current_while_liveness_checks_are_deferred() {
	let mut f = Fixture::new(1_934_032);
	let block = f.block(&[]);
	f.chain
		.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
		.unwrap();

	// Validation defers peer eviction, but the advertised header still comes
	// directly from the committed body head, keeping its height and work paired.
	f.adapter
		.sync_state
		.update(SyncStatus::TxHashsetKernelsValidation {
			kernels: 0,
			kernels_total: 1,
		});
	assert!(f.peers.is_chain_liveness_deferred());
	assert_eq!(f.peers.get_head().unwrap(), block.header);
	// The cleanup grace period does not make the advertised head stale.
	f.adapter.sync_state.update(SyncStatus::NoSync);
	assert!(f.peers.is_chain_liveness_deferred());
	assert_eq!(f.peers.get_head().unwrap(), block.header);
	// Expire the grace period without sleeping; peer liveness checks resume.
	*f.adapter.chain_liveness_deferred_until.write() =
		Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
	assert!(!f.peers.is_chain_liveness_deferred());
	assert_eq!(f.peers.get_head().unwrap(), block.header);
}

#[test]
fn pong_updates_tip_and_sync_loop_starts_header_download_during_body_sync() {
	let f = Fixture::new(1_934_023);
	let head = f.chain.header_head().unwrap();
	let difficulty = (head.total_difficulty + Difficulty::from_num(100)).unwrap();
	let (peer, receiver) =
		mwc_p2p::Peer::connected_for_test(f.peer.clone(), f.context, f.peers.clone());
	assert!(!peer.info.capabilities.contains(Capabilities::HEADER_HIST));
	f.peers.add_connected(Arc::new(peer)).unwrap();
	f.adapter.sync_state.update(SyncStatus::BodySync {
		archive_height: 0,
		current_height: head.height,
		highest_height: head.height + 100,
	});
	assert!(f.adapter.sync_state.is_syncing());

	// Ping/Pong updates the live tip shared with the connected Peer.
	f.peer.update(head.height + 100, difficulty);
	assert_eq!(
		f.peer.get_height_and_difficulty(),
		(head.height + 100, difficulty)
	);
	// Lower work and equal work at a different height must not replace the best pair.
	f.peer.update(head.height + 101, head.total_difficulty);
	f.peer.update(head.height + 101, difficulty);
	assert_eq!(
		f.peer.get_height_and_difficulty(),
		(head.height + 100, difficulty)
	);
	assert_eq!(receiver.try_iter().count(), 0);
	assert!(f.manager.header_download_for_test(&f.peer.addr).is_none());
	let response = f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(receiver.try_iter().count(), 1);
	assert_eq!(
		f.manager.header_download_for_test(&f.peer.addr),
		Some((0, difficulty))
	);
	assert_eq!(response.peers_capabilities, Capabilities::UNKNOWN);
	assert_eq!(receiver.try_iter().count(), 0);
}

#[test]
fn sync_loop_selects_all_ahead_peers_after_pong_updates() {
	let f = Fixture::new(1_934_027);
	let head = f.chain.header_head().unwrap();
	let mut suppliers = Vec::new();
	for (index, extra_work) in [0, 100, 200, 200].into_iter().enumerate() {
		// Convert the total: Difficulty::from_num(0) would add one unit of work.
		let work = Difficulty::from_num(head.total_difficulty.to_num() + extra_work);
		let mut info = f.peer.clone();
		info.addr = PeerAddr::Ip(([127, 0, 0, 1], 3530 + index as u16).into());
		info.live_info = Arc::new(RwLock::new(PeerLiveInfo::new(work)));
		info.update(head.height + extra_work, work);
		let (peer, receiver) = mwc_p2p::Peer::connected_for_test(info, f.context, f.peers.clone());
		let peer = Arc::new(peer);
		f.peers.add_connected(peer.clone()).unwrap();
		suppliers.push((peer, receiver));
	}
	for (peer, _) in &suppliers {
		let (height, difficulty) = peer.info.get_height_and_difficulty();
		peer.info.update(height, difficulty);
	}
	assert!(suppliers
		.iter()
		.all(|(_, receiver)| receiver.try_iter().count() == 0));
	f.manager.sync_request(&f.peers).unwrap();
	for (index, (peer, receiver)) in suppliers.iter().enumerate() {
		assert_eq!(receiver.try_iter().count(), usize::from(index >= 1));
		assert_eq!(
			f.manager
				.header_download_for_test(&peer.info.addr)
				.is_some(),
			index >= 1
		);
	}
	f.manager.sync_request(&f.peers).unwrap();
	assert!(suppliers
		.iter()
		.all(|(_, receiver)| receiver.try_iter().count() == 0));
	assert!(f
		.manager
		.header_download_for_test(&suppliers[0].0.info.addr)
		.is_none());

	// A peer that moves ahead is picked up on the next pass, preserving existing downloads.
	let announced = (head.total_difficulty + Difficulty::from_num(300)).unwrap();
	suppliers[0].0.info.update(head.height + 300, announced);
	assert_eq!(suppliers[0].1.try_iter().count(), 0);
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(suppliers[0].1.try_iter().count(), 1);
	assert_eq!(
		f.manager
			.header_download_for_test(&suppliers[0].0.info.addr),
		Some((0, announced))
	);
	for (peer, receiver) in &suppliers[1..] {
		assert_eq!(receiver.try_iter().count(), 0);
		assert!(f
			.manager
			.header_download_for_test(&peer.info.addr)
			.is_some());
	}
}

#[test]
fn missing_ancestry_announcements_wait_for_the_sync_loop() {
	for (context, full_block) in [(1_934_028, false), (1_934_029, true)] {
		let mut f = Fixture::new(context);
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
		let child = next_block(&producer, &mut f.secp, &f.keychain, &[]);
		let (peer, receiver) =
			mwc_p2p::Peer::connected_for_test(f.peer.clone(), f.context, f.peers.clone());
		let peer = Arc::new(peer);
		f.peers.add_connected(peer.clone()).unwrap();
		if full_block {
			assert!(f
				.peers
				.block_received(&mut f.secp, child.clone(), &peer.info)
				.unwrap());
		} else {
			assert!(f
				.peers
				.header_received(child.header.clone(), &peer.info)
				.unwrap());
		}
		assert_eq!(
			peer.info.get_height_and_difficulty(),
			(child.header.height, child.header.total_difficulty())
		);
		assert_eq!(receiver.try_iter().count(), 0);
		assert!(f
			.manager
			.header_download_for_test(&peer.info.addr)
			.is_none());
		f.manager.sync_request(&f.peers).unwrap();
		assert_eq!(receiver.try_iter().count(), 1);
		assert_eq!(
			f.manager.header_download_for_test(&peer.info.addr),
			Some((0, child.header.total_difficulty()))
		);
		peer.receive_headers_for_test(&[parent.header.clone(), child.header.clone()], 0)
			.unwrap();
		assert_eq!(
			f.chain.header_head().unwrap().last_block_h,
			child.hash(f.context).unwrap()
		);
		assert!(f
			.manager
			.header_download_for_test(&peer.info.addr)
			.is_none());
		// The early body (if supplied) was discarded. The regular loop must
		// request both bodies, and accepting the parent must not replay a child.
		f.manager.sync_request(&f.peers).unwrap();
		assert_eq!(receiver.try_iter().count(), 2);
		assert!(f
			.peers
			.block_received(&mut f.secp, parent, &peer.info)
			.unwrap());
		assert_eq!(f.chain.head().unwrap().height, 4);
		assert!(!f
			.chain
			.block_exists(&child.hash(f.context).unwrap())
			.unwrap());
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
		assert!(f
			.peers
			.block_received(&mut f.secp, child, &peer.info)
			.unwrap());
		assert_eq!(f.chain.head().unwrap().height, 5);
	}
}

#[test]
fn header_progress_accepts_short_batches_and_known_duplicate_goals() {
	let mut f = Fixture::new(1_934_020);
	let known_hash = f.chain.header_head().unwrap().last_block_h;
	let block = f.block(&[]);
	let mut headers: Vec<_> = f.history.iter().map(|block| block.header.clone()).collect();
	headers.push(block.header.clone());
	let last = headers.last().unwrap();
	let mut info = f.peer.clone();
	info.capabilities |= Capabilities::HEADER_HIST;
	info.update(last.height, last.total_difficulty());
	let (first, first_rx) =
		mwc_p2p::Peer::connected_for_test(info.clone(), f.context, f.peers.clone());
	let first = Arc::new(first);
	f.peers.add_connected(first.clone()).unwrap();
	info.addr = PeerAddr::Ip("127.0.0.1:3522".parse().unwrap());
	let (second, second_rx) = mwc_p2p::Peer::connected_for_test(info, f.context, f.peers.clone());
	let second = Arc::new(second);
	f.peers.add_connected(second.clone()).unwrap();
	let original_time = f.chain.get_header_progress_time(&known_hash).unwrap();
	f.manager.sync_request(&f.peers).unwrap();
	// One sync pass starts both peers tied for the best advertised work.
	assert_eq!(first_rx.try_iter().count(), 1);
	assert_eq!(second_rx.try_iter().count(), 1);
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(first_rx.try_iter().count(), 0);
	assert_eq!(second_rx.try_iter().count(), 0);
	// Each peer supplies a complete three-header response below the target.
	// Continue immediately, including after the first peer has reached the target.
	let mut accepted_time = None;
	for (peer, receiver) in [(&first, &first_rx), (&second, &second_rx)] {
		peer.receive_headers_for_test(&headers[..2], 1).unwrap();
		assert_eq!(receiver.try_iter().count(), 0);
		assert_eq!(
			f.manager.header_download_for_test(&peer.info.addr),
			Some((0, last.total_difficulty()))
		);
		peer.receive_headers_for_test(&headers[2..3], 0).unwrap();
		assert_eq!(receiver.try_iter().count(), 1);
		// A sync pass must preserve the continuation, even if our
		// header head has already reached this download's target.
		f.manager.sync_request(&f.peers).unwrap();
		assert_eq!(
			f.manager.header_download_for_test(&peer.info.addr),
			Some((original_time, last.total_difficulty()))
		);
		assert_eq!(receiver.try_iter().count(), 0);
		peer.receive_headers_for_test(&headers[3..], 0).unwrap();
		let time = f
			.chain
			.get_header_progress_time(&last.hash(f.context).unwrap())
			.unwrap();
		if let Some(previous_time) = accepted_time {
			assert_eq!(time, previous_time);
		} else {
			assert!(time > original_time);
			accepted_time = Some(time);
			// Supply the body too, so later sync passes only exercise the
			// second peer's header continuation, without requesting a body.
			f.chain
				.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
				.unwrap();
			// Reaching the header tip now announces the accepted body to both
			// connections. Keep those announcements out of continuation counts.
			for receiver in [&first_rx, &second_rx] {
				let announcements: Vec<_> = receiver.try_iter().collect();
				assert_eq!(announcements.len(), 1);
				assert_eq!(
					announcements[0].message_type_for_test(),
					mwc_p2p::msg::Type::CompactBlock
				);
			}
		}
		assert!(f
			.manager
			.header_download_for_test(&peer.info.addr)
			.is_none());
	}
	f.manager.apply_header_scores_for_test(&f.peers);
	assert_eq!(
		f.chain.get_header_progress_time(&known_hash).unwrap(),
		original_time
	);

	assert_eq!(
		f.chain.header_head().unwrap().last_block_h,
		block.hash(f.context).unwrap()
	);
}

#[test]
fn header_download_survives_local_work_overtaking_its_target() {
	let mut f = Fixture::new(1_934_026);
	let known: Vec<_> = f.history.iter().map(|block| block.header.clone()).collect();
	let known_time = f
		.chain
		.get_header_progress_time(&f.chain.header_head().unwrap().last_block_h)
		.unwrap();
	let fourth = f.block(&[]);
	let promised = fourth.header.total_difficulty();
	let mut info = f.peer.clone();
	info.capabilities |= Capabilities::HEADER_HIST;
	info.update(fourth.header.height, promised);
	let (peer, receiver) = mwc_p2p::Peer::connected_for_test(info, f.context, f.peers.clone());
	let peer = Arc::new(peer);
	f.peers.add_connected(peer.clone()).unwrap();
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(receiver.try_iter().count(), 1);
	// The first response advances the cursor; its replay leaves a retry pending.
	peer.receive_headers_for_test(&known, 0).unwrap();
	assert_eq!(receiver.try_iter().count(), 1);
	peer.receive_headers_for_test(&known, 0).unwrap();
	assert_eq!(receiver.try_iter().count(), 0);
	assert_eq!(
		f.manager.header_download_for_test(&peer.info.addr),
		Some((known_time, promised))
	);

	// Other block arrivals advance our chain past the original advertised target.
	let mut response = vec![fourth.header.clone()];
	f.chain
		.process_block(&mut f.secp, fourth, Options::NONE, HashSet::new())
		.unwrap();
	let fifth = f.block(&[]);
	response.push(fifth.header.clone());
	f.chain
		.process_block(&mut f.secp, fifth, Options::NONE, HashSet::new())
		.unwrap();
	assert!(f.chain.header_head().unwrap().total_difficulty > promised);
	let sixth = f.block(&[]);
	response.push(sixth.header.clone());
	// Discard broadcasts caused by locally accepting the two blocks.
	receiver.try_iter().for_each(drop);
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(receiver.try_iter().count(), 1);
	assert_eq!(
		f.manager.header_download_for_test(&peer.info.addr),
		Some((known_time, promised))
	);

	// Reaching the target in one fragment does not complete the response.
	peer.receive_headers_for_test(&response[..1], 2).unwrap();
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(receiver.try_iter().count(), 0);
	assert_eq!(
		f.manager.header_download_for_test(&peer.info.addr),
		Some((known_time, promised))
	);
	peer.receive_headers_for_test(&response[1..], 0).unwrap();
	assert_eq!(
		f.chain.header_head().unwrap().last_block_h,
		sixth.hash(f.context).unwrap()
	);
	assert!(f
		.manager
		.header_download_for_test(&peer.info.addr)
		.is_none());
	// The response went beyond the advertised goal. Remember its best validated header,
	// then ignore a lower Pong so BodySync can still identify this canonical supplier.
	assert_eq!(
		peer.info.get_height_and_difficulty(),
		(sixth.header.height, sixth.header.total_difficulty())
	);
	peer.info.update(sixth.header.height, promised);
	assert_eq!(
		peer.info.get_height_and_difficulty(),
		(sixth.header.height, sixth.header.total_difficulty())
	);
	f.manager.sync_request(&f.peers).unwrap();
	assert!(f
		.manager
		.has_block_request(&peer.info.addr, &sixth.hash(f.context).unwrap()));
	assert_eq!(receiver.try_iter().count(), 1);
}

#[test]
fn header_continuation_errors_cancel_the_download() {
	for (context, disconnected) in [(1_934_024, false), (1_934_025, true)] {
		let f = Fixture::new(context);
		let headers: Vec<_> = f.history.iter().map(|block| block.header.clone()).collect();
		let last = headers.last().unwrap();
		let promised = (last.total_difficulty() + Difficulty::from_num(100)).unwrap();
		let mut info = f.peer.clone();
		info.capabilities |= Capabilities::HEADER_HIST;
		info.update(last.height + 100, promised);
		let (peer, receiver) = mwc_p2p::Peer::connected_for_test(info, f.context, f.peers.clone());
		let peer = Arc::new(peer);
		f.peers.add_connected(peer.clone()).unwrap();
		f.manager.sync_request(&f.peers).unwrap();
		assert_eq!(receiver.try_iter().count(), 1);
		if disconnected {
			peer.stop();
		}
		drop(receiver);
		let error = peer.receive_headers_for_test(&headers, 0).unwrap_err();
		assert!(error.to_string().contains(&peer.info.addr.to_string()));
		assert!(error.to_string().contains(if disconnected {
			"disconnected before header download could continue"
		} else {
			"Failed to send headers request"
		}));
		assert!(f
			.manager
			.header_download_for_test(&peer.info.addr)
			.is_none());
		assert!(!error.is_bad_data());
	}
}

#[test]
fn header_progress_advances_on_a_fork_before_it_becomes_head() {
	let mut f = Fixture::new(1_934_022);
	let source_dir = TempDir::new().unwrap();
	let source = init_chain(f.context, &f.secp, &source_dir, Arc::new(NoopAdapter {}));
	let keychain = ExtKeychain::from_seed(&f.secp, &[43; 32], false).unwrap();
	let mut fork = Vec::new();
	for _ in 0..4 {
		let block = next_block(&source, &mut f.secp, &keychain, &[]);
		fork.push(block.header.clone());
		source
			.process_block(&mut f.secp, block, Options::NONE, HashSet::new())
			.unwrap();
	}
	let main_head = f.chain.header_head().unwrap();
	let received_at =
		f.chain
			.get_header_progress_time(&main_head.last_block_h)
			.unwrap() + 100;
	let first_time = f
		.chain
		.sync_block_headers(&fork[..2], Options::NONE, received_at)
		.unwrap();
	assert_eq!(first_time, received_at);
	assert_eq!(f.chain.header_head().unwrap(), main_head);
	let fork_tip = mwc_chain::Tip::try_from_header(&fork[1]).unwrap();
	let locator = f.chain.get_locator_hashes(fork_tip, &[2, 1, 0]).unwrap();
	assert_eq!(
		locator,
		vec![
			fork[1].hash(f.context).unwrap(),
			fork[0].hash(f.context).unwrap(),
			fork[0].prev_hash
		]
	);
	assert_eq!(f.chain.header_head().unwrap(), main_head);

	// Another supplier can return these same already validated headers. Their
	// stored marker must remain stable even though this receipt is later.
	let replay_time = f
		.chain
		.sync_block_headers(&fork[..2], Options::NONE, received_at + 1000)
		.unwrap();
	assert_eq!(replay_time, first_time);

	// Checkpoint headers keep their creation timestamp unchanged.
	f.chain
		.sync_block_headers(
			&fork[2..3],
			Options::NONE,
			u64::try_from(fork[2].timestamp.timestamp_micros()).unwrap(),
		)
		.unwrap();
	let third_time = f
		.chain
		.get_header_progress_time(&fork[2].hash(f.context).unwrap())
		.unwrap();
	assert_eq!(
		third_time,
		u64::try_from(fork[2].timestamp.timestamp_micros()).unwrap()
	);
	assert_eq!(f.chain.header_head().unwrap(), main_head);

	let last_hash = fork[3].hash(f.context).unwrap();
	let mut invalid = fork[3].clone();
	invalid.timestamp = fork[2].timestamp;
	assert!(f
		.chain
		.sync_block_headers(&[invalid], Options::NONE, received_at + 2000)
		.is_err());
	assert!(f
		.chain
		.get_header_progress_time(&last_hash)
		.unwrap_err()
		.is_not_found());
	assert_eq!(f.chain.header_head().unwrap(), main_head);

	// The final batch wins by work, even with a backwards-moving local clock.
	let last_time = f
		.chain
		.sync_block_headers(&fork[3..], Options::NONE, received_at - 1)
		.unwrap();
	assert_eq!(last_time, received_at - 1);
	assert_eq!(f.chain.header_head().unwrap().last_block_h, last_hash);
}

#[test]
fn header_progress_replays_keep_cursor_and_advertised_goal_until_banned() {
	let f = Fixture::new(1_934_021);
	let headers: Vec<_> = f.history.iter().map(|block| block.header.clone()).collect();
	let last = headers.last().unwrap();
	let promised = (last.total_difficulty() + Difficulty::from_num(100)).unwrap();
	let mut info = f.peer.clone();
	info.capabilities |= Capabilities::HEADER_HIST;
	info.update(last.height + 100, promised);
	let (peer, receiver) = mwc_p2p::Peer::connected_for_test(info, f.context, f.peers.clone());
	let peer = Arc::new(peer);
	f.peers.add_connected(peer.clone()).unwrap();
	let known_time = f
		.chain
		.get_header_progress_time(&last.hash(f.context).unwrap())
		.unwrap();
	// The first short response makes progress. Seven subsequent replays are fined.
	for attempt in 0..8 {
		if attempt > 0 {
			// A new Ping must neither raise the existing target nor reset its cursor.
			peer.info.update(
				last.height + 100 + attempt,
				(promised + Difficulty::from_num(attempt)).unwrap(),
			);
		}
		f.manager.sync_request(&f.peers).unwrap();
		assert_eq!(receiver.try_iter().count(), 1);
		assert_eq!(
			f.manager.header_download_for_test(&peer.info.addr),
			Some((if attempt == 0 { 0 } else { known_time }, promised))
		);
		peer.receive_headers_for_test(&headers, 0).unwrap();
		assert_eq!(
			f.manager.header_download_for_test(&peer.info.addr),
			Some((known_time, promised))
		);
		f.manager.apply_header_scores_for_test(&f.peers);
		assert_eq!(f.peers.is_banned(&peer.info.addr).unwrap(), attempt == 7);
	}
	f.manager.sync_request(&f.peers).unwrap();
	assert!(f
		.manager
		.header_download_for_test(&peer.info.addr)
		.is_none());
	assert_eq!(
		f.chain
			.get_header_progress_time(&last.hash(f.context).unwrap())
			.unwrap(),
		known_time
	);
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
	let requests = f.request_missing_bodies();
	assert!(requests.try_iter().count() > 0);
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
		.block_received(&mut f.secp, hydrated, &bad_peer)
		.unwrap());
	assert!(f.peers.is_banned(&bad_peer.addr).unwrap());
	// Complete the fallback with the exact mined body. The earlier failed local
	// guess must not prevent acceptance or leave the honest sender banned.
	assert!(f.peers.block_received(&mut f.secp, block, &f.peer).unwrap());
	assert_eq!(f.chain.head().unwrap().height, 4);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

// Workflow: mine height 4 and place that exact transaction, including its proof,
// in the receiver's pool before delivering the compact block.
// Expected: reconstruction passes full chain validation, advances the head to
// height 4, relays a compact block to an observer, and neither queues a full-block
// request nor bans the sender. A duplicate must not produce another relay.
#[test]
fn compact_matching_transaction_is_accepted_without_full_block_request() {
	let mut f = Fixture::new(1_934_002);
	let (tx, _) = f.proof_variants();
	let block = f.block(&[tx.clone()]);
	let compact = CompactBlock::from(block).unwrap();
	let hash = compact.hash(f.context).unwrap();
	f.add_transaction(tx);
	let mut observer_info = f.peer.clone();
	observer_info.addr = PeerAddr::Ip("127.0.0.2:3432".parse().unwrap());
	let (observer, broadcasts) =
		mwc_p2p::Peer::connected_for_test(observer_info, f.context, f.peers.clone());
	f.peers.add_connected(Arc::new(observer)).unwrap();
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact.clone(), &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 4);
	assert_eq!(
		broadcasts.try_recv().unwrap().message_type_for_test(),
		mwc_p2p::msg::Type::CompactBlock
	);
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert_eq!(broadcasts.try_iter().count(), 0);
	let requests = f.request_missing_bodies();
	assert_eq!(requests.try_iter().count(), 0);
	assert!(!f.manager.has_block_request(&f.peer.addr, &hash));
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

#[test]
fn body_catch_up_relays_only_the_completed_header_tip() {
	// Learn two headers before their bodies, then receive the child first.
	// Buffering must announce nothing; applying the parent drains both tasks
	// and announces just the child that makes the body and header heads equal.
	let mut f = Fixture::new(1_934_033);
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
	let child = next_block(&producer, &mut f.secp, &f.keychain, &[]);
	for block in [&parent, &child] {
		f.chain
			.process_block_header(&block.header, Options::NONE)
			.unwrap();
	}
	f.peer
		.update(child.header.height, child.header.total_difficulty());
	let messages = f.request_missing_bodies();
	assert_eq!(messages.try_iter().count(), 2);
	assert!(f
		.peers
		.block_received(&mut f.secp, child.clone(), &f.peer)
		.unwrap());
	assert_eq!(messages.try_iter().count(), 0);
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &f.peer)
		.unwrap());
	assert_eq!(
		f.chain.head().unwrap().last_block_h,
		child.hash(f.context).unwrap()
	);
	let announcements: Vec<_> = messages.try_iter().collect();
	assert_eq!(announcements.len(), 1);
	assert_eq!(
		announcements[0].message_type_for_test(),
		mwc_p2p::msg::Type::CompactBlock
	);
}

#[test]
fn announced_headers_request_their_bodies_and_relay_the_completed_tip() {
	// A single header starts the body queue; an unsolicited headers page from
	// another peer extends it. Each body must be requested from its announcer.
	// A third-party response fulfils the child task, and a later corrupt copy
	// must not replace that response or its supplier. Applying the parent then
	// relays exactly the compact child that makes the two heads equal.
	let mut f = Fixture::new(1_934_035);
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
	let child = next_block(&producer, &mut f.secp, &f.keychain, &[]);
	let (first, first_messages) =
		mwc_p2p::Peer::connected_for_test(f.peer.clone(), f.context, f.peers.clone());
	let first = Arc::new(first);
	f.peers.add_connected(first.clone()).unwrap();
	let second_info = PeerInfo {
		addr: PeerAddr::Ip("127.0.0.2:3435".parse().unwrap()),
		live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::min()))),
		..f.peer.clone()
	};
	let (second, second_messages) =
		mwc_p2p::Peer::connected_for_test(second_info, f.context, f.peers.clone());
	let second = Arc::new(second);
	f.peers.add_connected(second.clone()).unwrap();
	assert!(f
		.peers
		.header_received(parent.header.clone(), &first.info)
		.unwrap());
	f.peers
		.headers_received(&[child.header.clone()], 0, &second.info)
		.unwrap();
	assert!(f
		.manager
		.has_block_request(&first.info.addr, &parent.hash(f.context).unwrap()));
	assert!(f
		.manager
		.has_block_request(&second.info.addr, &child.hash(f.context).unwrap()));
	for messages in [&first_messages, &second_messages] {
		assert_eq!(
			messages.try_recv().unwrap().message_type_for_test(),
			mwc_p2p::msg::Type::GetBlock
		);
		assert_eq!(messages.try_iter().count(), 0);
	}
	// A repeated header must not create another task or resend its request.
	f.peers
		.headers_received(&[child.header.clone()], 0, &second.info)
		.unwrap();
	assert_eq!(second_messages.try_iter().count(), 0);
	assert!(f
		.peers
		.block_received(&mut f.secp, child.clone(), &first.info)
		.unwrap());
	assert!(!f
		.manager
		.has_block_request(&second.info.addr, &child.hash(f.context).unwrap()));
	let mut duplicate = child.clone();
	duplicate.body.outputs[0].proof.proof[0] ^= 1;
	assert!(f
		.peers
		.block_received(&mut f.secp, duplicate, &second.info)
		.unwrap());
	assert_eq!(
		first_messages.try_iter().count() + second_messages.try_iter().count(),
		0
	);
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &first.info)
		.unwrap());
	assert_eq!(f.chain.head().unwrap(), f.chain.header_head().unwrap());
	assert_eq!(
		f.chain.head().unwrap().last_block_h,
		child.hash(f.context).unwrap()
	);
	for messages in [&first_messages, &second_messages] {
		assert_eq!(
			messages.try_recv().unwrap().message_type_for_test(),
			mwc_p2p::msg::Type::CompactBlock
		);
		assert_eq!(messages.try_iter().count(), 0);
	}
	assert!(!f.peers.is_banned(&second.info.addr).unwrap());
}

#[test]
fn reorg_bodies_relay_only_when_the_new_branch_reaches_the_header_tip() {
	// Select a four-block fork while the body head stays on the old three-block
	// branch. Applying the first three fork bodies must preserve that head and
	// send nothing. The fourth wins by work and relays a compact block.
	let mut f = Fixture::new(1_934_036);
	let old_head = f.chain.head().unwrap();
	let source_dir = TempDir::new().unwrap();
	let source = init_chain(f.context, &f.secp, &source_dir, Arc::new(NoopAdapter {}));
	let keychain = ExtKeychain::from_seed(&f.secp, &[44; 32], false).unwrap();
	let mut fork = Vec::new();
	for _ in 0..4 {
		let block = next_block(&source, &mut f.secp, &keychain, &[]);
		source
			.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
			.unwrap();
		f.chain
			.process_block_header(&block.header, Options::NONE)
			.unwrap();
		fork.push(block);
	}
	let target = f.chain.header_head().unwrap();
	f.peer.update(target.height, target.total_difficulty);
	let messages = f.request_missing_bodies();
	assert_eq!(messages.try_iter().count(), 4);
	for block in &fork[..3] {
		assert!(f
			.peers
			.block_received(&mut f.secp, block.clone(), &f.peer)
			.unwrap());
		assert_eq!(f.chain.head().unwrap(), old_head);
		assert_eq!(messages.try_iter().count(), 0);
	}
	assert!(f
		.peers
		.block_received(&mut f.secp, fork[3].clone(), &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap(), target);
	assert_eq!(
		messages.try_recv().unwrap().message_type_for_test(),
		mwc_p2p::msg::Type::CompactBlock
	);
	assert_eq!(messages.try_iter().count(), 0);
}

#[test]
fn unsolicited_headers_and_blocks_wait_for_snapshot_validation() {
	// Deliver both header message formats and a full/compact body while snapshot
	// validation is active. None may move either head or send a body request.
	// After validation, the same header must schedule its body normally.
	let mut f = Fixture::new(1_934_037);
	let block = f.block(&[]);
	let old_head = f.chain.header_head().unwrap();
	let (peer, messages) =
		mwc_p2p::Peer::connected_for_test(f.peer.clone(), f.context, f.peers.clone());
	let peer = Arc::new(peer);
	f.peers.add_connected(peer.clone()).unwrap();
	f.adapter
		.sync_state
		.update(SyncStatus::ValidatingKernelsHistory {
			headers: 0,
			headers_total: old_head.height,
		});
	assert!(f
		.peers
		.header_received(block.header.clone(), &peer.info)
		.unwrap());
	f.peers
		.headers_received(&[block.header.clone()], 0, &peer.info)
		.unwrap();
	assert!(f
		.peers
		.block_received(&mut f.secp, block.clone(), &peer.info)
		.unwrap());
	assert!(f
		.peers
		.compact_block_received(
			&mut f.secp,
			CompactBlock::from(block.clone()).unwrap(),
			&peer.info
		)
		.unwrap());
	assert_eq!(f.chain.head().unwrap(), old_head);
	assert_eq!(f.chain.header_head().unwrap(), old_head);
	assert_eq!(messages.try_iter().count(), 0);
	f.adapter.sync_state.reset();
	assert!(f
		.peers
		.header_received(block.header.clone(), &peer.info)
		.unwrap());
	assert!(f
		.manager
		.has_block_request(&peer.info.addr, &block.hash(f.context).unwrap()));
	assert_eq!(
		messages.try_recv().unwrap().message_type_for_test(),
		mwc_p2p::msg::Type::GetBlock
	);
}

#[test]
fn accepted_fork_does_not_relay_while_existing_heads_match() {
	// Mine two competing children of the same parent. Relay the winning child,
	// then accept the equal-work fork: unchanged matching heads must not cause
	// that unrelated fork block to be announced.
	let mut f = Fixture::new(1_934_034);
	let block = f.block(&[]);
	let fork_keychain = ExtKeychain::from_seed(&f.secp, &[43; 32], false).unwrap();
	let fork = next_block(&f.chain, &mut f.secp, &fork_keychain, &[]);
	assert_eq!(
		block.header.total_difficulty(),
		fork.header.total_difficulty()
	);
	assert_ne!(
		block.hash(f.context).unwrap(),
		fork.hash(f.context).unwrap()
	);
	let (observer, messages) =
		mwc_p2p::Peer::connected_for_test(f.peer.clone(), f.context, f.peers.clone());
	f.peers.add_connected(Arc::new(observer)).unwrap();
	f.chain
		.process_block(&mut f.secp, block.clone(), Options::MINE, HashSet::new())
		.unwrap();
	assert_eq!(
		messages.try_recv().unwrap().message_type_for_test(),
		mwc_p2p::msg::Type::CompactBlock
	);
	assert!(f
		.peers
		.block_received(&mut f.secp, fork.clone(), &f.peer)
		.unwrap());
	assert!(!f
		.chain
		.block_exists(&fork.hash(f.context).unwrap())
		.unwrap());
	assert_eq!(messages.try_iter().count(), 0);
	// Exercise the chain callback directly: unsolicited fork bodies are now
	// ignored by network admission when they do not extend the current head.
	f.chain
		.process_block(&mut f.secp, fork.clone(), Options::NONE, HashSet::new())
		.unwrap();
	assert!(f
		.chain
		.block_exists(&fork.hash(f.context).unwrap())
		.unwrap());
	assert_eq!(
		f.chain.head().unwrap().last_block_h,
		block.hash(f.context).unwrap()
	);
	assert_eq!(f.chain.head().unwrap(), f.chain.header_head().unwrap());
	assert_eq!(messages.try_iter().count(), 0);
}

// Workflow: a second chain shares blocks 1..3 and produces parent 4 and child 5.
// The receiver knows only parent 4's header and holds the alternate proof for
// child 5. Deliver compact child 5, full child 5, then full parent 4, in that order.
// Expected: discard the guessed child and request its full body without banning
// the sender. BodySync buffers that response until the parent arrives, then
// applies both blocks in order.
#[test]
fn compact_missing_parent_fetches_full_body_into_body_sync_queue() {
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
	// withholding the parent body makes the reconstructed child fail with missing
	// ancestry. This isolates deferred body validation from missing-header handling.
	f.chain
		.process_block_header(&parent.header, Options::NONE)
		.unwrap();
	f.add_transaction(local);
	assert!(f
		.peers
		.compact_block_received(&mut f.secp, compact, &f.peer)
		.unwrap());
	assert!(!f.chain.block_exists(&hash).unwrap());
	let requests = f.request_missing_bodies();
	assert!(requests.try_iter().count() > 0);
	assert!(f.manager.has_block_request(&f.peer.addr, &hash));
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());

	// The requested full response stays in its task until the parent arrives.
	// It must not be applied early or inherit the failed local reconstruction.
	assert!(f.peers.block_received(&mut f.secp, child, &f.peer).unwrap());
	assert!(!f.chain.block_exists(&hash).unwrap());
	assert_eq!(f.chain.head().unwrap().height, 3);
	// Parent arrival applies the ready prefix, preserving the child's supplier
	// identity through deferred validation.
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 5);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

#[test]
fn a_full_response_replaces_a_buffered_reconstruction_without_blame() {
	// Request the parent, then reconstruct its child with a different local
	// rangeproof. A later full child must replace that guess while both wait
	// for the parent, and applying them must not ban the compact-block supplier.
	let mut f = Fixture::new(1_934_038);
	let (mined, local) = f.proof_variants();
	let source_dir = TempDir::new().unwrap();
	let source = init_chain(f.context, &f.secp, &source_dir, Arc::new(NoopAdapter {}));
	for block in &f.history {
		source
			.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
			.unwrap();
	}
	let parent = next_block(&source, &mut f.secp, &f.keychain, &[]);
	source
		.process_block(&mut f.secp, parent.clone(), Options::NONE, HashSet::new())
		.unwrap();
	let child = next_block(&source, &mut f.secp, &f.keychain, &[mined]);
	f.chain
		.process_block_header(&parent.header, Options::NONE)
		.unwrap();
	f.peer
		.update(parent.header.height, parent.header.total_difficulty());
	let messages = f.request_missing_bodies();
	assert_eq!(messages.try_iter().count(), 1);
	f.add_transaction(local);
	assert!(f
		.peers
		.compact_block_received(
			&mut f.secp,
			CompactBlock::from(child.clone()).unwrap(),
			&f.peer
		)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 3);
	let full_supplier = PeerInfo {
		addr: PeerAddr::Ip("127.0.0.2:3438".parse().unwrap()),
		live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::min()))),
		..f.peer.clone()
	};
	assert!(f
		.peers
		.block_received(&mut f.secp, child.clone(), &full_supplier)
		.unwrap());
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &f.peer)
		.unwrap());
	assert_eq!(
		f.chain.head().unwrap().last_block_h,
		child.hash(f.context).unwrap()
	);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
	assert!(!f.peers.is_banned(&full_supplier.addr).unwrap());
	assert_eq!(
		messages.try_recv().unwrap().message_type_for_test(),
		mwc_p2p::msg::Type::CompactBlock
	);
	assert_eq!(messages.try_iter().count(), 0);
}

// Buffer an invalid child from one peer, then deliver its valid parent from
// another. Delayed validation must ban only the child's supplier, keep the
// parent, and retry the child through BodySync.
#[test]
fn body_sync_bans_buffered_child_supplier_without_banning_parent_supplier() {
	let mut f = Fixture::new(1_934_031);
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
	let child = next_block(&producer, &mut f.secp, &f.keychain, &[]);
	for block in [&parent, &child] {
		f.chain
			.process_block_header(&block.header, Options::NONE)
			.unwrap();
	}
	f.peer
		.update(child.header.height, child.header.total_difficulty());
	let requests = f.request_missing_bodies();
	assert_eq!(requests.try_iter().count(), 2);
	let bad_peer = PeerInfo {
		addr: PeerAddr::Ip("127.0.0.2:3431".parse().unwrap()),
		live_info: Arc::new(RwLock::new(PeerLiveInfo::new(
			child.header.total_difficulty(),
		))),
		..f.peer.clone()
	};
	let mut invalid_child = child.clone();
	invalid_child.body.outputs[0].proof.proof[0] ^= 1;
	assert!(f
		.peers
		.block_received(&mut f.secp, invalid_child, &bad_peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 3);
	assert!(!f.peers.is_banned(&bad_peer.addr).unwrap());
	assert!(f
		.peers
		.block_received(&mut f.secp, parent, &f.peer)
		.unwrap());
	assert_eq!(f.chain.head().unwrap().height, 4);
	assert!(f.peers.is_banned(&bad_peer.addr).unwrap());
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
	f.manager.sync_request(&f.peers).unwrap();
	assert_eq!(requests.try_iter().count(), 1);
	assert!(f
		.manager
		.has_block_request(&f.peer.addr, &child.hash(f.context).unwrap()));
	assert!(f.peers.block_received(&mut f.secp, child, &f.peer).unwrap());
	assert_eq!(f.chain.head().unwrap().height, 5);
	assert!(!f.peers.is_banned(&f.peer.addr).unwrap());
}

// Receive an already-stored body, then a new body, then an older body. Both known
// and newly accepted blocks must raise the peer's best tip, while the old replay
// must leave the stronger tip intact.
#[test]
fn full_blocks_preserve_best_peer_tip() {
	let mut f = Fixture::new(1_934_030);
	let known = f.history.last().unwrap().clone();
	assert!(f
		.peers
		.block_received(&mut f.secp, known.clone(), &f.peer)
		.unwrap());
	assert_eq!(
		f.peer.get_height_and_difficulty(),
		(known.header.height, known.header.total_difficulty())
	);

	let block = f.block(&[]);
	assert!(f
		.peers
		.block_received(&mut f.secp, block.clone(), &f.peer)
		.unwrap());
	assert_eq!(
		f.peer.get_height_and_difficulty(),
		(block.header.height, block.header.total_difficulty())
	);
	assert!(f
		.peers
		.block_received(&mut f.secp, f.history[0].clone(), &f.peer)
		.unwrap());
	assert_eq!(
		f.peer.get_height_and_difficulty(),
		(block.header.height, block.header.total_difficulty())
	);
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
	assert_eq!(f.peer.get_height_and_difficulty(), (0, Difficulty::min()));
}

#[test]
fn peer_cleanup_counts_incompatible_and_lagging_tips_independently() {
	// Exercise matching, lagging, incompatible and recovering peer advertisements.
	// Cleanup must count the two policies independently and preserve useful peers.
	let mut f = Fixture::new(943_810);
	let blocks = f.history.clone();
	let header_only = f.block(&[]).header;
	f.chain
		.process_block_header(&header_only, Options::NONE)
		.unwrap();
	let mut receivers = Vec::new();
	let mut peer = |port: u16, inbound: bool, height: u64, work: Difficulty| {
		let info = PeerInfo {
			addr: PeerAddr::Ip(([127, 0, 0, 1], port).into()),
			direction: if inbound {
				Direction::Inbound
			} else {
				Direction::Outbound
			},
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(work))),
			..f.peer.clone()
		};
		info.update(height, work);
		let (peer, receiver) =
			mwc_p2p::Peer::connected_for_test(info, f.context, Arc::new(mwc_p2p::DummyAdapter {}));
		receivers.push(receiver);
		let peer = Arc::new(peer);
		f.peers.add_connected(peer.clone()).unwrap();
		peer
	};
	let work = blocks[0].header.total_difficulty();
	let matching = peer(3491, false, 1, work);
	let wrong = peer(3492, false, 2, work);
	let inbound = peer(3493, true, 2, work);
	let progressing = peer(3494, false, 2, work);
	progressing
		.info
		.update(3, blocks[1].header.total_difficulty());
	let better = peer(
		3495,
		false,
		4,
		(blocks[2].header.total_difficulty() + Difficulty::from_num(1)).unwrap(),
	);
	let equal = peer(3496, false, 1, blocks[2].header.total_difficulty());
	let one_behind = peer(3497, false, 2, blocks[1].header.total_difficulty());
	let lagging_inbound = peer(3498, true, 1, work);
	let lagging_outbound = peer(3499, false, 1, work);
	// The header-only lead must not change the cleanup baseline.
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 0);
	for peer in [&wrong, &progressing, &matching, &inbound, &better, &equal] {
		assert!(f.peers.get_connected_peer(&peer.info.addr).is_some());
	}

	// Inject the tip changes directly to isolate cleanup counters: normal peer updates
	// now retain the best work/height pair rather than allowing these regressions.
	// Adapting to our branch resets this peer's first incompatible result.
	wrong.info.live_info.write().height = 1;
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 1);
	assert!(f.peers.get_connected_peer(&wrong.info.addr).is_some());
	assert!(f.peers.get_connected_peer(&progressing.info.addr).is_none());
	assert!(!f.peers.is_banned(&progressing.info.addr).unwrap());

	// A later mismatch needs two new consecutive cleanup results.
	wrong.info.live_info.write().height = 2;
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 0);
	assert!(f.peers.get_connected_peer(&wrong.info.addr).is_some());
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 1);
	assert!(f.peers.get_connected_peer(&wrong.info.addr).is_none());
	assert!(!f.peers.is_banned(&wrong.info.addr).unwrap());
	for peer in [&matching, &inbound, &better, &equal] {
		assert!(f.peers.get_connected_peer(&peer.info.addr).is_some());
	}

	// Four cleanup checks have elapsed. Moving within one block of our
	// body tip resets the outbound peer's lag count, despite the header lead.
	matching.info.update(2, blocks[1].header.total_difficulty());
	for _ in 0..5 {
		let summary = f
			.peers
			.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
		assert_eq!(summary.removed_peers, 0);
		assert!(f
			.peers
			.get_connected_peer(&lagging_inbound.info.addr)
			.is_some());
	}
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 1);
	// The ten-check lag policy applies to outbound suppliers. Keep lagging
	// inbound peers connected so they can catch up from us.
	assert!(f
		.peers
		.get_connected_peer(&lagging_outbound.info.addr)
		.is_none());
	assert!(!f.peers.is_banned(&lagging_outbound.info.addr).unwrap());
	assert!(f
		.peers
		.get_connected_peer(&lagging_inbound.info.addr)
		.is_some());

	// Falling behind again needs ten new consecutive checks, even on our branch.
	{
		let mut info = matching.info.live_info.write();
		info.height = 1;
		info.total_difficulty = work;
	}
	for _ in 0..9 {
		let summary = f
			.peers
			.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
		assert_eq!(summary.removed_peers, 0);
		assert!(f.peers.get_connected_peer(&matching.info.addr).is_some());
	}
	let summary = f
		.peers
		.clean_peers(10, 10, Capabilities::UNKNOWN, P2PConfig::default());
	assert_eq!(summary.removed_peers, 1);
	assert!(f.peers.get_connected_peer(&matching.info.addr).is_none());
	assert!(!f.peers.is_banned(&matching.info.addr).unwrap());
	for peer in [&inbound, &better, &equal, &one_behind, &lagging_inbound] {
		assert!(f.peers.get_connected_peer(&peer.info.addr).is_some());
	}
}
