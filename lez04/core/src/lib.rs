//! Types and SSZ helpers shared by the Lantern spike guest and its runner.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use risc0_zkvm::sha::{Impl, Sha256 as _};

pub const COMMITTEE_SIZE: usize = 512;
pub const HALF: usize = 256;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SLOTS_PER_PERIOD: u64 = 8192;
pub const SECONDS_PER_SLOT: u64 = 12;
/// Two thirds of 512, rounded up.
pub const FLOOR: u32 = 342;
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

// Electra and Fulu generalized indices.
pub const FINALIZED_ROOT_GINDEX: u64 = 169;
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 86;
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 87;
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;

/// Exit codes of refusals: a non-zero exit is charged only its cycles, a panic the whole budget.
pub mod refusal {
    pub const ROOT_MISMATCH: u8 = 10;
    pub const BAD_SIGNATURE: u8 = 11;
    pub const STALE: u8 = 12;
    pub const NO_COMMITTEE_FOR_PERIOD: u8 = 13;
    pub const BELOW_TWO_THIRDS: u8 = 14;
    pub const WRONG_STATE: u8 = 15;
    pub const MALFORMED: u8 = 16;
    pub const SENDER_NOT_ALLOWED: u8 = 17;
    pub const CONFLICTING_COMMITTEE: u8 = 18;
    pub const PAST_WS_WINDOW: u8 = 19;
}

pub type Root = [u8; 32];
/// A G1 point as the guest stores it: blst's in-memory affine form.
pub type RawG1 = [u8; 96];

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionHeader {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: [u8; 256],
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    /// Little-endian uint256.
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct LcHeader {
    pub beacon: BeaconHeader,
    pub execution: ExecutionHeader,
    pub execution_branch: Vec<Root>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub slot: u64,
    pub beacon_root: Root,
    pub execution_state_root: Root,
    pub receipts_root: Root,
    pub block_number: u64,
    pub block_hash: Root,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub attested: BeaconHeader,
    pub finalized: LcHeader,
    pub finality_branch: Vec<Root>,
    pub next_committee: Option<(Root, Vec<Root>)>,
    pub bits: [u8; 64],
    /// Compressed G2.
    pub signature: [u8; 96],
    pub signature_slot: u64,
}

/// Written once at Init.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub checkpoint_root: Root,
    pub genesis_validators_root: Root,
    pub genesis_time: u64,
    /// (activation epoch, fork version), strictly ascending.
    pub forks: Vec<(u64, [u8; 4])>,
    pub ws_period_secs: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub config: Config,
    pub head: Head,
    /// (period, committee root).
    pub current: (u64, Root),
    pub next: Option<(u64, Root)>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Staging {
    pub root: Root,
    pub second_root: Root,
    pub aggregate: RawG1,
    pub keys: Vec<RawG1>,
}

/// Its keys and aggregate match its root, so any instance holding that root may use it.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Committee {
    pub root: Root,
    pub aggregate: RawG1,
    pub keys: Vec<RawG1>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub instance: AccountId,
    pub committee: (u64, Root),
    pub stage: u8,
    pub pk: RawG1,
    /// blst affine G2, 192 bytes each.
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    /// blst fp12, 576 bytes, after the Miller loop.
    pub fp12: Vec<u8>,
    pub head: Head,
    pub next: Option<(u64, Root)>,
    pub record: Option<AccountId>,
}

/// Tagged so no handler decodes another kind's state.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum LightState {
    Instance(Instance),
    Staging(Staging),
    Committee(Committee),
    Job(Job),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AggregateRequest {
    pub job: AccountId,
    pub record: Option<AccountId>,
    pub committee: (u64, Root),
    pub bits: [u8; 64],
    pub signature: [u8; 96],
    pub signing_root: Root,
    pub head: Head,
    pub next: Option<(u64, Root)>,
}

/// A verified head, written once to its own actor so a reader's view of it never changes.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub instance: AccountId,
    pub head: Head,
}

/// An Ethereum account and one storage slot, proven under a recorded head.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Consume {
    pub instance: AccountId,
    pub record: AccountId,
    pub address: [u8; 20],
    pub nonce: u64,
    /// Big-endian uint256.
    pub balance: [u8; 32],
    pub storage_root: Root,
    pub code_hash: Root,
    pub account_proof: Vec<Vec<u8>>,
    pub slot: Root,
    /// Big-endian uint256.
    pub value: [u8; 32],
    pub storage_proof: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub instance: AccountId,
    pub slot: u64,
    pub block_number: u64,
    pub address: [u8; 20],
    pub storage_slot: Root,
    pub value: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Consumer {
    Pending(Box<Consume>),
    Done(Statement),
}

// Record, Consume, Read and RecordReply keep their run-3 indices, so the consumption's wire bytes
// match the guest the private proofs ran on.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Message {
    Init {
        config: Config,
        header: LcHeader,
        committee_root: Root,
        committee_branch: Vec<Root>,
    },
    InstallFirst {
        root: Root,
        second_root: Root,
        aggregate: [u8; 48],
        keys: Vec<[u8; 96]>,
    },
    Prepare {
        committee: AccountId,
        job: AccountId,
        record: Option<AccountId>,
        update: Box<Update>,
    },
    Begin(Box<Job>),
    Miller,
    Finish,
    Advance {
        committee: (u64, Root),
        head: Head,
        next: Option<(u64, Root)>,
        /// The job's Miller loop output, exponentiated only after the instance's checks pass.
        fp12: Vec<u8>,
    },
    Record(Record),
    Consume(Box<Consume>),
    Read,
    RecordReply(Record),
    InstallSecond {
        keys: Vec<[u8; 96]>,
    },
    Aggregate(Box<AggregateRequest>),
}

#[must_use]
pub fn sha(bytes: &[u8]) -> Root {
    Impl::hash_bytes(bytes).as_bytes().try_into().expect("32 bytes")
}

#[must_use]
pub fn h2(a: &Root, b: &Root) -> Root {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    sha(&buf)
}

#[must_use]
pub fn merkleize(chunks: &[Root], limit: usize) -> Root {
    let width = limit.max(chunks.len()).max(1).next_power_of_two();
    let mut layer: Vec<Root> = chunks.to_vec();
    layer.resize(width, [0u8; 32]);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|pair| h2(&pair[0], &pair[1])).collect();
    }
    layer[0]
}

#[must_use]
pub fn u64_chunk(x: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&x.to_le_bytes());
    c
}

#[must_use]
pub fn htr_beacon(h: &BeaconHeader) -> Root {
    merkleize(
        &[
            u64_chunk(h.slot),
            u64_chunk(h.proposer_index),
            h.parent_root,
            h.state_root,
            h.body_root,
        ],
        8,
    )
}

/// `None` when `extra_data` is longer than its 32-byte limit.
#[must_use]
pub fn htr_execution(e: &ExecutionHeader) -> Option<Root> {
    if e.extra_data.len() > 32 {
        return None;
    }
    let mut fee_recipient = [0u8; 32];
    fee_recipient[..20].copy_from_slice(&e.fee_recipient);
    let bloom: Vec<Root> = e
        .logs_bloom
        .chunks(32)
        .map(|c| c.try_into().expect("32"))
        .collect();
    let mut extra = [0u8; 32];
    extra[..e.extra_data.len()].copy_from_slice(&e.extra_data);
    let extra_root = h2(
        &merkleize(&[extra], 1),
        &u64_chunk(e.extra_data.len() as u64),
    );
    Some(merkleize(
        &[
            e.parent_hash,
            fee_recipient,
            e.state_root,
            e.receipts_root,
            merkleize(&bloom, 8),
            e.prev_randao,
            u64_chunk(e.block_number),
            u64_chunk(e.gas_limit),
            u64_chunk(e.gas_used),
            u64_chunk(e.timestamp),
            extra_root,
            e.base_fee_per_gas,
            e.block_hash,
            e.transactions_root,
            e.withdrawals_root,
            u64_chunk(e.blob_gas_used),
            u64_chunk(e.excess_blob_gas),
        ],
        32,
    ))
}

#[must_use]
pub fn verify_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> bool {
    let depth = 63 - gindex.leading_zeros();
    if branch.len() != depth as usize {
        return false;
    }
    let index = gindex - (1u64 << depth);
    let mut value = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        value = if (index >> i) & 1 == 1 {
            h2(sibling, &value)
        } else {
            h2(&value, sibling)
        };
    }
    value == *root
}

/// The head a light-client header proves, or `None` if its execution payload does not check.
#[must_use]
pub fn verified_head(header: &LcHeader) -> Option<Head> {
    let execution_root = htr_execution(&header.execution)?;
    verify_branch(
        &execution_root,
        &header.execution_branch,
        EXECUTION_PAYLOAD_GINDEX,
        &header.beacon.body_root,
    )
    .then(|| Head {
        slot: header.beacon.slot,
        beacon_root: htr_beacon(&header.beacon),
        execution_state_root: header.execution.state_root,
        receipts_root: header.execution.receipts_root,
        block_number: header.execution.block_number,
        block_hash: header.execution.block_hash,
    })
}

/// SSZ root of a `Bytes48` key.
#[must_use]
pub fn key_leaf(compressed: &[u8; 48]) -> Root {
    let mut buf = [0u8; 64];
    buf[..48].copy_from_slice(compressed);
    sha(&buf)
}

/// `None` when no fork in `forks` covers the signature's epoch.
#[must_use]
pub fn signing_root(
    attested: &BeaconHeader,
    signature_slot: u64,
    forks: &[(u64, [u8; 4])],
    genesis_validators_root: &Root,
) -> Option<Root> {
    let epoch = signature_slot.max(1).saturating_sub(1) / SLOTS_PER_EPOCH;
    let version = forks.iter().rev().find(|(start, _)| *start <= epoch)?.1;
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&version);
    let fork_data_root = h2(&version_chunk, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    Some(h2(&htr_beacon(attested), &domain))
}

#[must_use]
pub fn forks_ascending(forks: &[(u64, [u8; 4])]) -> bool {
    !forks.is_empty() && forks.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

#[must_use]
pub const fn period(slot: u64) -> u64 {
    slot / SLOTS_PER_PERIOD
}

/// Start of `slot` in milliseconds, LEZ's block timestamp unit.
#[must_use]
pub const fn slot_time_ms(genesis_time: u64, slot: u64) -> u64 {
    genesis_time
        .saturating_add(slot.saturating_mul(SECONDS_PER_SLOT))
        .saturating_mul(1000)
}
