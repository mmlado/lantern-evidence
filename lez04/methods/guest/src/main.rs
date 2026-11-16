//! Lantern spike on LEZ v0.4.0-rc3: the sync-committee check split into public transactions.
//!
//! An instance holds its configuration, head and committee roots. Committees live in actors of
//! their own, checked against their root, so installing one never touches an instance. Steps two
//! and three run on a job actor, whose state carries the prepared pairing between transactions.

use blst::{
    BLST_ERROR, blst_final_exp, blst_fp12, blst_fp12_is_one, blst_hash_to_g2, blst_miller_loop_n,
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress,
    blst_p1_affine_generator, blst_p1_affine_on_curve, blst_p1_cneg, blst_p1_deserialize,
    blst_p1_from_affine, blst_p1_is_inf, blst_p1_to_affine, blst_p1_uncompress, blst_p2,
    blst_p2_affine, blst_p2_affine_in_g2, blst_p2_affine_is_inf, blst_p2_to_affine,
    blst_p2_uncompress,
};
use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_trie::{Nibbles, proof::verify_proof};
use lantern_spike_core::{
    AggregateRequest, COMMITTEE_SIZE, CURRENT_SYNC_COMMITTEE_GINDEX, Committee, Config, Consume,
    Consumer, FINALIZED_ROOT_GINDEX, FLOOR, HALF, Head, Instance, Job, LcHeader, LightState,
    Message, NEXT_SYNC_COMMITTEE_GINDEX, RawG1, Record, Root, Staging, Statement, Update,
    forks_ascending, h2, htr_beacon, key_leaf, merkleize, period, refusal, signing_root,
    slot_time_ms, verified_head, verify_branch,
};
use lee_core::{
    account::{AccountId, Actor},
    program::{ReceiveInput, Response},
};

#[derive(alloy_rlp::RlpEncodable)]
struct TrieAccount {
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// A panic is charged the whole gas limit, a non-zero exit only the cycles used.
fn refuse(code: u8, why: &str) -> ! {
    risc0_zkvm::guest::env::log(why);
    risc0_zkvm::guest::env::exit(code)
}

const _: () = assert!(core::mem::size_of::<blst_p1_affine>() == 96);
const _: () = assert!(core::mem::size_of::<blst_p2_affine>() == 192);
const _: () = assert!(core::mem::size_of::<blst_fp12>() == 576);

lee_core::actor_entrypoint!(handle);

fn handle(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Init {
            config,
            header,
            committee_root,
            committee_branch,
        } => init(input, config, &header, committee_root, &committee_branch),
        Message::InstallFirst {
            root,
            second_root,
            aggregate,
            keys,
        } => install_first(input, root, second_root, &aggregate, &keys),
        Message::InstallSecond { keys } => install_second(input, &keys),
        Message::Prepare {
            committee,
            job,
            record,
            update,
        } => prepare(input, committee, job, record, &update),
        Message::Aggregate(request) => aggregate(input, &request),
        Message::Begin(job) => begin(input, *job),
        Message::Miller => miller(input),
        Message::Finish => finish(input),
        Message::Advance {
            committee,
            head,
            next,
            fp12,
        } => advance(input, committee, head, next, &fp12),
        Message::Record(record) => {
            if !input.from_own_program() {
                refuse(refusal::SENDER_NOT_ALLOWED, "only a job writes a record");
            }
            claim(input);
            Response::set_state(borsh::to_vec(&record).expect("encodes"))
        }
        Message::Consume(consume) => {
            // Unsigned, a Consume could occupy an empty actor that a pending update names.
            if !input.is_authorized {
                refuse(refusal::SENDER_NOT_ALLOWED, "a consumer acts only with its own signature");
            }
            let idle = input.pre_state.is_empty()
                || matches!(borsh::from_slice(&input.pre_state), Ok(Consumer::Done(_)));
            assert!(idle, "consumer busy");
            let record_actor = Actor::new(consume.record, input.receiver.program_account_id);
            Response::set_state(borsh::to_vec(&Consumer::Pending(consume)).expect("encodes"))
                .send_sync(record_actor, &Message::Read)
        }
        Message::Read => {
            let reader = input.from.expect("a reader");
            let record: Record = borsh::from_slice(&input.pre_state).expect("a record");
            Response::keep_state().send_sync(reader, &Message::RecordReply(record))
        }
        Message::RecordReply(record) => {
            let Consumer::Pending(consume) =
                borsh::from_slice(&input.pre_state).expect("a pending consumption")
            else {
                panic!("no pending consumption");
            };
            assert!(
                input.from == Some(Actor::new(consume.record, input.receiver.program_account_id)),
                "the reply must come from the named record"
            );
            assert!(record.instance == consume.instance, "record of another instance");
            Response::set_state(
                borsh::to_vec(&Consumer::Done(attest(&consume, &record))).expect("encodes"),
            )
        }
    }
}

fn init(
    input: &ReceiveInput,
    config: Config,
    header: &LcHeader,
    committee_root: Root,
    committee_branch: &[Root],
) -> Response {
    claim(input);
    if htr_beacon(&header.beacon) != config.checkpoint_root {
        refuse(refusal::MALFORMED, "header is not the checkpoint");
    }
    if !forks_ascending(&config.forks) {
        refuse(refusal::MALFORMED, "forks not strictly ascending");
    }
    if !verify_branch(
        &committee_root,
        committee_branch,
        CURRENT_SYNC_COMMITTEE_GINDEX,
        &header.beacon.state_root,
    ) {
        refuse(refusal::MALFORMED, "current committee branch");
    }
    let Some(head) = verified_head(header) else {
        refuse(refusal::MALFORMED, "execution payload branch");
    };
    store(&LightState::Instance(Instance {
        config,
        current: (period(head.slot), committee_root),
        next: None,
        head,
    }))
}

fn install_first(
    input: &ReceiveInput,
    root: Root,
    second_root: Root,
    aggregate: &[u8; 48],
    keys: &[[u8; 96]],
) -> Response {
    claim(input);
    let (raw, first_root) = half(keys);
    if h2(&h2(&first_root, &second_root), &key_leaf(aggregate)) != root {
        refuse(refusal::ROOT_MISMATCH, "first half does not match the committee root");
    }
    let mut point = blst_p1_affine::default();
    if unsafe { blst_p1_uncompress(&mut point, aggregate.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        refuse(refusal::MALFORMED, "aggregate encoding");
    }
    store(&LightState::Staging(Staging {
        root,
        second_root,
        aggregate: raw_g1(&point),
        keys: raw,
    }))
}

fn install_second(input: &ReceiveInput, keys: &[[u8; 96]]) -> Response {
    let Some(LightState::Staging(staging)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "no first half staged");
    };
    let (raw, second_root) = half(keys);
    if second_root != staging.second_root {
        refuse(refusal::ROOT_MISMATCH, "second half does not match the staged root");
    }
    let mut keys = staging.keys;
    keys.extend(raw);
    store(&LightState::Committee(Committee {
        root: staging.root,
        aggregate: staging.aggregate,
        keys,
    }))
}

fn prepare(
    input: &ReceiveInput,
    committee: AccountId,
    job: AccountId,
    record: Option<AccountId>,
    update: &Update,
) -> Response {
    let Some(LightState::Instance(instance)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "not an instance");
    };
    let me = input.receiver.account_id;
    if job == me
        || job == committee
        || record.is_some_and(|record| record == me || record == committee || record == job)
    {
        refuse(refusal::WRONG_STATE, "job and record must be actors of their own");
    }
    let Some(signer) = committee_for(&instance, period(update.signature_slot)) else {
        refuse(refusal::NO_COMMITTEE_FOR_PERIOD, "no committee for the signature period");
    };
    if !(update.signature_slot > update.attested.slot
        && update.attested.slot >= update.finalized.beacon.slot)
    {
        refuse(refusal::MALFORMED, "slot order");
    }
    let participants: u32 = update.bits.iter().map(|b| b.count_ones()).sum();
    if participants < FLOOR {
        refuse(refusal::BELOW_TWO_THIRDS, "below two thirds of the committee");
    }
    if !verify_branch(
        &htr_beacon(&update.finalized.beacon),
        &update.finality_branch,
        FINALIZED_ROOT_GINDEX,
        &update.attested.state_root,
    ) {
        refuse(refusal::MALFORMED, "finality branch");
    }
    let Some(head) = verified_head(&update.finalized) else {
        refuse(refusal::MALFORMED, "execution payload branch");
    };
    let next = update.next_committee.as_ref().and_then(|(root, branch)| {
        if !verify_branch(root, branch, NEXT_SYNC_COMMITTEE_GINDEX, &update.attested.state_root) {
            refuse(refusal::MALFORMED, "next committee branch");
        }
        // Committees from a not yet final period could still be reorganised away.
        (period(update.finalized.beacon.slot) == period(update.attested.slot))
            .then(|| (period(update.attested.slot) + 1, *root))
    });
    if !newer(&instance, &head, next.as_ref()) {
        refuse(refusal::STALE, "stale or duplicate update");
    }
    let config = &instance.config;
    let Some(signing_root) = signing_root(
        &update.attested,
        update.signature_slot,
        &config.forks,
        &config.genesis_validators_root,
    ) else {
        refuse(refusal::MALFORMED, "no fork for the signature slot");
    };
    let valid_from = slot_time_ms(config.genesis_time, update.signature_slot);
    let valid_to = slot_time_ms(config.genesis_time, instance.head.slot)
        .saturating_add(config.ws_period_secs.saturating_mul(1000));
    let request = AggregateRequest {
        job,
        record,
        committee: signer,
        bits: update.bits,
        signature: update.signature,
        signing_root,
        head,
        next,
    };
    let program = input.receiver.program_account_id;
    let Ok(response) = Response::keep_state()
        .send_sync(
            Actor::new(committee, program),
            &Message::Aggregate(Box::new(request)),
        )
        .try_timestamp_window(valid_from..valid_to)
    else {
        refuse(refusal::PAST_WS_WINDOW, "signed past the weak-subjectivity window");
    };
    response
}

fn aggregate(input: &ReceiveInput, request: &AggregateRequest) -> Response {
    let Some(from) = input.from else {
        refuse(refusal::SENDER_NOT_ALLOWED, "only an instance asks for an aggregate");
    };
    if !input.from_own_program() {
        refuse(refusal::SENDER_NOT_ALLOWED, "only an instance asks for an aggregate");
    }
    let Some(LightState::Committee(committee)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "not an installed committee");
    };
    if committee.root != request.committee.1 {
        refuse(refusal::NO_COMMITTEE_FOR_PERIOD, "this actor holds another committee");
    }
    let bit = |i: usize| (request.bits[i / 8] >> (i % 8)) & 1 == 1;
    // Two thirds sign, so taking the absent keys off the aggregate is the shorter sum.
    let mut acc = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut acc, &from_raw::<blst_p1_affine>(&committee.aggregate)) };
    for i in (0..COMMITTEE_SIZE).filter(|&i| !bit(i)) {
        let mut q = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut q, &from_raw::<blst_p1_affine>(&committee.keys[i]));
            blst_p1_cneg(&mut q, true);
            let p: *mut blst_p1 = &mut acc;
            blst_p1_add_or_double(p, p, &q);
        }
    }
    if unsafe { blst_p1_is_inf(&acc) } {
        refuse(refusal::MALFORMED, "participants aggregate to the identity");
    }
    let mut pk = blst_p1_affine::default();
    let mut sig = blst_p2_affine::default();
    let mut msg = blst_p2::default();
    let mut msg_aff = blst_p2_affine::default();
    unsafe {
        blst_p1_to_affine(&mut pk, &acc);
        if blst_p2_uncompress(&mut sig, request.signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            refuse(refusal::MALFORMED, "signature encoding");
        }
        if !blst_p2_affine_in_g2(&sig) || blst_p2_affine_is_inf(&sig) {
            refuse(refusal::MALFORMED, "signature outside G2");
        }
        blst_hash_to_g2(
            &mut msg,
            request.signing_root.as_ptr(),
            request.signing_root.len(),
            DST.as_ptr(),
            DST.len(),
            core::ptr::null(),
            0,
        );
        blst_p2_to_affine(&mut msg_aff, &msg);
    }
    let job = Job {
        instance: from.account_id,
        committee: request.committee,
        stage: 1,
        pk: raw_g1(&pk),
        msg: raw_bytes(&msg_aff),
        sig: raw_bytes(&sig),
        fp12: Vec::new(),
        head: request.head.clone(),
        next: request.next,
        record: request.record,
    };
    Response::keep_state().send_sync(
        Actor::new(request.job, input.receiver.program_account_id),
        &Message::Begin(Box::new(job)),
    )
}

fn begin(input: &ReceiveInput, job: Job) -> Response {
    if !input.from_own_program() {
        refuse(refusal::SENDER_NOT_ALLOWED, "only a committee starts a job");
    }
    claim(input);
    store(&LightState::Job(job))
}

fn miller(input: &ReceiveInput) -> Response {
    let Some(LightState::Job(mut job)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "not a job");
    };
    if job.stage != 1 {
        refuse(refusal::WRONG_STATE, "Miller loop already run");
    }
    let pk: blst_p1_affine = from_raw(&job.pk);
    let msg: blst_p2_affine = from_raw(&job.msg);
    let sig: blst_p2_affine = from_raw(&job.sig);
    let mut neg_g1 = blst_p1::default();
    let mut neg_g1_aff = blst_p1_affine::default();
    let mut fp12 = blst_fp12::default();
    unsafe {
        blst_p1_from_affine(&mut neg_g1, blst_p1_affine_generator());
        blst_p1_cneg(&mut neg_g1, true);
        blst_p1_to_affine(&mut neg_g1_aff, &neg_g1);
        let qs: [*const blst_p2_affine; 2] = [&msg, &sig];
        let ps: [*const blst_p1_affine; 2] = [&pk, &neg_g1_aff];
        blst_miller_loop_n(&mut fp12, qs.as_ptr(), ps.as_ptr(), 2);
    }
    job.fp12 = raw_bytes(&fp12);
    job.stage = 2;
    store(&LightState::Job(job))
}

fn finish(input: &ReceiveInput) -> Response {
    let Some(LightState::Job(job)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "not a job");
    };
    if job.stage != 2 {
        refuse(refusal::WRONG_STATE, "Miller loop not run");
    }
    let program = input.receiver.program_account_id;
    let response = Response::set_state(Vec::new()).send_sync(
        Actor::new(job.instance, program),
        &Message::Advance {
            committee: job.committee,
            head: job.head.clone(),
            next: job.next,
            fp12: job.fp12,
        },
    );
    match job.record {
        Some(record) => response.send_sync(
            Actor::new(record, program),
            &Message::Record(Record {
                instance: job.instance,
                head: job.head,
            }),
        ),
        None => response,
    }
}

fn advance(
    input: &ReceiveInput,
    committee: (u64, Root),
    head: Head,
    next: Option<(u64, Root)>,
    fp12: &[u8],
) -> Response {
    if !input.from_own_program() {
        refuse(refusal::SENDER_NOT_ALLOWED, "only a job advances an instance");
    }
    let Some(LightState::Instance(mut instance)) = decode(&input.pre_state) else {
        refuse(refusal::WRONG_STATE, "not an instance");
    };
    if committee_for(&instance, committee.0) != Some(committee) {
        refuse(refusal::NO_COMMITTEE_FOR_PERIOD, "signed by a committee the instance no longer holds");
    }
    if !newer(&instance, &head, next.as_ref()) {
        refuse(refusal::STALE, "stale update");
    }
    // After the checks, so a raced or stale update is refused before the costliest step.
    let fp12: blst_fp12 = from_raw(fp12);
    let mut gt = blst_fp12::default();
    let ok = unsafe {
        blst_final_exp(&mut gt, &fp12);
        blst_fp12_is_one(&gt)
    };
    if !ok {
        refuse(refusal::BAD_SIGNATURE, "sync committee signature does not verify");
    }
    // A job prepared in time must not refresh an instance whose window has since closed.
    let config = &instance.config;
    let valid_to = slot_time_ms(config.genesis_time, instance.head.slot)
        .saturating_add(config.ws_period_secs.saturating_mul(1000));
    if head.slot > instance.head.slot {
        instance.head = head;
    }
    if let Some(known) = instance.next {
        if period(instance.head.slot) >= known.0 {
            instance.current = known;
            instance.next = None;
        }
    }
    if let Some(offered) = next {
        match instance.next {
            None if offered.0 == instance.current.0 + 1 => instance.next = Some(offered),
            Some(known) if known.0 == offered.0 && known.1 != offered.1 => refuse(
                refusal::CONFLICTING_COMMITTEE,
                "a different next committee for a known period",
            ),
            _ => {}
        }
    }
    store(&LightState::Instance(instance)).timestamp_window(..valid_to)
}

fn committee_for(instance: &Instance, signature_period: u64) -> Option<(u64, Root)> {
    if instance.current.0 == signature_period {
        return Some(instance.current);
    }
    instance.next.filter(|next| next.0 == signature_period)
}

// The spec takes a next committee from an update finalized before the head, which then stays.
fn newer(instance: &Instance, head: &Head, next: Option<&(u64, Root)>) -> bool {
    head.slot > instance.head.slot
        || (instance.next.is_none() && next.is_some_and(|next| next.0 == instance.current.0 + 1))
}

// Unsigned, anyone could occupy an empty actor that a pending update names.
fn claim(input: &ReceiveInput) {
    if !input.is_authorized {
        refuse(refusal::SENDER_NOT_ALLOWED, "an empty actor is written only with its signature");
    }
    if !input.pre_state.is_empty() {
        refuse(refusal::WRONG_STATE, "actor already holds state");
    }
}

fn attest(consume: &Consume, record: &Record) -> Statement {
    let account = TrieAccount {
        nonce: consume.nonce,
        balance: U256::from_be_bytes(consume.balance),
        storage_root: B256::from(consume.storage_root),
        code_hash: B256::from(consume.code_hash),
    };
    let nodes: Vec<Bytes> = consume.account_proof.iter().cloned().map(Bytes::from).collect();
    assert!(
        verify_proof(
            B256::from(record.head.execution_state_root),
            Nibbles::unpack(keccak256(consume.address)),
            Some(alloy_rlp::encode(&account)),
            nodes.iter()
        )
        .is_ok(),
        "account proof"
    );
    let value = U256::from_be_bytes(consume.value);
    let nodes: Vec<Bytes> = consume.storage_proof.iter().cloned().map(Bytes::from).collect();
    let expected = (!value.is_zero()).then(|| alloy_rlp::encode(value));
    assert!(
        verify_proof(
            account.storage_root,
            Nibbles::unpack(keccak256(consume.slot)),
            expected,
            nodes.iter()
        )
        .is_ok(),
        "storage proof"
    );
    Statement {
        instance: record.instance,
        slot: record.head.slot,
        block_number: record.head.block_number,
        address: consume.address,
        storage_slot: consume.slot,
        value: consume.value,
    }
}

fn half(keys: &[[u8; 96]]) -> (Vec<RawG1>, Root) {
    if keys.len() != HALF {
        refuse(refusal::MALFORMED, "a half is 256 keys");
    }
    let mut raw = Vec::with_capacity(HALF);
    let mut leaves = Vec::with_capacity(HALF);
    for key in keys {
        let point = witnessed(key);
        let mut compressed = [0u8; 48];
        unsafe { blst_p1_affine_compress(compressed.as_mut_ptr(), &point) };
        leaves.push(key_leaf(&compressed));
        raw.push(raw_g1(&point));
    }
    (raw, merkleize(&leaves, HALF))
}

// Uncompressed key checked on the curve; its compression is what the committee root commits to.
fn witnessed(uncompressed: &[u8; 96]) -> blst_p1_affine {
    let mut point = blst_p1_affine::default();
    let ok = unsafe {
        blst_p1_deserialize(&mut point, uncompressed.as_ptr()) == BLST_ERROR::BLST_SUCCESS
            && blst_p1_affine_on_curve(&point)
    };
    if !ok {
        refuse(refusal::MALFORMED, "key encoding");
    }
    point
}

fn decode(state: &[u8]) -> Option<LightState> {
    borsh::from_slice(state).ok()
}

fn store(state: &LightState) -> Response {
    Response::set_state(borsh::to_vec(state).expect("encodes"))
}

fn raw_g1(point: &blst_p1_affine) -> RawG1 {
    raw_bytes(point).try_into().expect("96 bytes")
}

fn raw_bytes<T>(value: &T) -> Vec<u8> {
    let ptr = (value as *const T).cast::<u8>();
    unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<T>()) }.to_vec()
}

fn from_raw<T: Default>(bytes: &[u8]) -> T {
    assert!(bytes.len() == core::mem::size_of::<T>(), "raw size");
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}
