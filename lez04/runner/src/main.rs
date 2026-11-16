//! Drives the Lantern spike on a standalone LEZ v0.4.0-rc3 sequencer with real mainnet data.
//!
//! Usage: lantern-spike-runner <lantern_spike.bin> <payer account id> <data dir>

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use lantern_spike_core::{
    BeaconHeader, COMMITTEE_SIZE, CURRENT_SYNC_COMMITTEE_GINDEX, Config, ExecutionHeader, FLOOR,
    HALF, LcHeader, LightState, Message, NEXT_SYNC_COMMITTEE_GINDEX, Root, Update, h2, htr_beacon,
    key_leaf, merkleize, period, signing_root, slot_time_ms, verified_head, verify_branch,
};
use lee_core::account::{AccountId, Actor};
use serde_json::Value;
use wallet::{
    AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    program_facades::program_loader::ProgramLoader,
};

type Wallet = WalletCore<sequencer_service_rpc::SequencerClient>;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// Month-old mainnet data stays inside this window, and the 14-day instance's has passed.
const WS_MAIN_SECS: u64 = 90 * 86_400;
const WS_SHORT_SECS: u64 = 14 * 86_400;
// Long enough for the closing instance's Prepare and Miller, short of its Finish.
const CLOSING_WINDOW_MS: u64 = 240_000;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("setup-private") => {
            args.remove(0);
            return setup_private(args).await;
        }
        Some("consume") => {
            args.remove(0);
            return consume(args).await;
        }
        Some("cross") => {
            args.remove(0);
            return cross(args).await;
        }
        _ => {}
    }
    let usage = "usage: lantern-spike-runner <lantern_spike.bin> <payer> <data dir>";
    let mut args = args.into_iter();
    let bin = args.next().context(usage)?;
    let payer: AccountId = args
        .next()
        .context(usage)?
        .parse()
        .map_err(|error| anyhow!("payer: {error:?}"))?;
    let data = std::path::PathBuf::from(args.next().context(usage)?);

    // Inputs, checked natively before anything is sent.
    let chain = chain(&data)?;
    let bootstrap = load(&data, "bootstrap_p1885.json")?["data"].clone();
    let checkpoint_root: Root = arr(&Value::String(
        std::fs::read_to_string(data.join("bootstrap_root.txt"))?.trim().to_owned(),
    ));
    let updates = load(&data, "updates_p1884_p1885.json")?;
    let u1885_json = updates[1]["data"].clone();
    let u1886_json = load(&data, "updates_p1886.json")?[0]["data"].clone();

    let bootstrap_header = lc_header(&bootstrap["header"]);
    let (c1885, a1885) = committee(&bootstrap["current_sync_committee"]);
    let root1885 = committee_root(&c1885, &a1885);
    ensure!(htr_beacon(&bootstrap_header.beacon) == checkpoint_root, "bootstrap root");
    let branch1885 = roots(&bootstrap["current_sync_committee_branch"]);
    ensure!(
        verify_branch(&root1885, &branch1885, CURRENT_SYNC_COMMITTEE_GINDEX, &bootstrap_header.beacon.state_root),
        "bootstrap committee branch"
    );
    verified_head(&bootstrap_header).context("bootstrap execution branch")?;

    let (c1886, a1886) = committee(&u1885_json["next_sync_committee"]);
    let root1886 = committee_root(&c1886, &a1886);
    let u1885 = update(&u1885_json, root1886);
    preflight(&u1885, &c1885, &chain, "1885")?;
    let (c1887, a1887) = committee(&u1886_json["next_sync_committee"]);
    let u1886 = update(&u1886_json, committee_root(&c1887, &a1887));
    preflight(&u1886, &c1886, &chain, "1886")?;
    let mut floor = u1885.clone();
    let mut set: u32 = floor.bits.iter().map(|b| b.count_ones()).sum();
    for i in 0..COMMITTEE_SIZE {
        if set == FLOOR {
            break;
        }
        if (floor.bits[i / 8] >> (i % 8)) & 1 == 1 {
            floor.bits[i / 8] &= !(1 << (i % 8));
            set -= 1;
        }
    }
    println!("preflight ok: checkpoint, both committee roots, both updates verify natively; floor update has {set} signers");

    let mut wallet = Wallet::from_env()?;
    let program = deploy(&mut wallet, &bin, payer).await?;
    let mut fresh = || wallet.create_new_account_public(None).0;
    let (instance, instance_ws, instance_closing) = (fresh(), fresh(), fresh());
    let (cache1885, cache1886, cache_forged) = (fresh(), fresh(), fresh());
    let (job_floor, job_1885, job_dup, job_1886) = (fresh(), fresh(), fresh(), fresh());
    let (job_second, job_ws, job_closing, record_1886) = (fresh(), fresh(), fresh(), fresh());
    wallet.store_persistent_data()?;
    println!("instance {instance:?}, 14-day instance {instance_ws:?}, closing instance {instance_closing:?}");
    println!("committees 1885 {cache1885:?}, 1886 {cache1886:?}, forged {cache_forged:?}");
    println!("jobs floor {job_floor:?}, 1885 {job_1885:?}, duplicate {job_dup:?}, 1886 {job_1886:?}, second {job_second:?}, 14-day {job_ws:?}, closing {job_closing:?}, 1886 record {record_1886:?}");

    let actor = |account| unsigned(program, account);
    let signer = |account| signed(program, account);
    let init = |ws_period_secs| Message::Init {
        config: chain.config(checkpoint_root, ws_period_secs),
        header: bootstrap_header.clone(),
        committee_root: root1885,
        committee_branch: branch1885.clone(),
    };
    let prepare = |committee, job, record, u: &Update| Message::Prepare {
        committee,
        job,
        record,
        update: Box::new(u.clone()),
    };
    step(&mut wallet, payer, || vec![signer(instance)], &init(WS_MAIN_SECS), "init").await?;
    step(&mut wallet, payer, || vec![signer(instance_ws)], &init(WS_SHORT_SECS), "init, 14-day window").await?;
    let head_ms = slot_time_ms(chain.genesis_time, bootstrap_header.beacon.slot);
    let closing_secs = (now_ms() + CLOSING_WINDOW_MS - head_ms).div_ceil(1000);
    let closes_at = head_ms + closing_secs * 1000;
    step(&mut wallet, payer, || vec![signer(instance_closing)], &init(closing_secs), "init, window closing in 4 minutes").await?;
    show(&wallet, program, instance, "after init").await?;

    let half1885 = halves(&c1885, &a1885, root1885)?;
    step(&mut wallet, payer, || vec![signer(cache1885)], &half1885.0, "1885 install half 1").await?;
    step(&mut wallet, payer, || vec![actor(cache1885)], &half1885.1, "1885 install half 2").await?;
    show(&wallet, program, cache1885, "1885 committee").await?;

    // Prepared while the closing instance's window is open, finished at the end after it closes.
    step(&mut wallet, payer, || vec![actor(instance_closing), actor(cache1885), signer(job_closing)], &prepare(cache1885, job_closing, None, &u1885), "1885 prepare on the closing instance").await?;
    step(&mut wallet, payer, || vec![actor(job_closing)], &Message::Miller, "1885 miller on the closing instance").await?;

    // The real 1886 root and second subtree with 1885 keys must not install.
    let forged = Message::InstallFirst {
        root: root1886,
        second_root: second_root(&c1886),
        aggregate: a1886,
        keys: uncompressed(&c1885)?[..HALF].to_vec(),
    };
    step(&mut wallet, payer, || vec![signer(cache_forged)], &forged, "forged 1886 half 1 (must revert)").await?;
    let (half1_1886, half2_1886) = halves(&c1886, &a1886, root1886)?;
    step(&mut wallet, payer, || vec![signer(cache1886)], &half1_1886, "1886 install half 1").await?;
    show(&wallet, program, cache1886, "1886 committee, half staged").await?;

    // The floor: 170 absent keys come off the aggregate, then the signature must fail.
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1885), signer(job_floor)], &prepare(cache1885, job_floor, None, &floor), "floor prepare (342 signers)").await?;
    step(&mut wallet, payer, || vec![actor(job_floor)], &Message::Miller, "floor miller").await?;
    step(&mut wallet, payer, || vec![actor(job_floor), actor(instance)], &Message::Finish, "floor finish (must revert)").await?;

    // A job naming another instance would overwrite it.
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1885), signer(instance_ws)], &prepare(cache1885, instance_ws, None, &u1885), "prepare naming another instance as its job (must revert)").await?;

    // A third party writing first to the job an honest update names.
    step(&mut wallet, payer, || vec![actor(job_1885)], &init(WS_MAIN_SECS), "unsigned init to the 1885 job (must revert)").await?;
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1885), actor(job_1885)], &prepare(cache1885, job_1885, None, &u1885), "1885 prepare without the job's signature (must revert)").await?;
    show(&wallet, program, job_1885, "1885 job after both").await?;

    update_steps(&mut wallet, payer, program, instance, cache1885, job_1885, None, &u1885, "1885").await?;
    show(&wallet, program, instance, "after the 1885 update").await?;

    step(&mut wallet, payer, || vec![actor(cache1886)], &half2_1886, "1886 install half 2").await?;
    show(&wallet, program, cache1886, "1886 committee").await?;
    show(&wallet, program, instance, "after the 1886 install, which leaves the instance alone").await?;
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1885), signer(job_dup)], &prepare(cache1885, job_dup, None, &u1885), "duplicate 1885 prepare (must revert)").await?;
    step(&mut wallet, payer, || vec![actor(job_1885)], &Message::Miller, "miller on a finished job (must revert)").await?;

    // Two jobs prepared for the 1886 update, so the second loses at its Finish.
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1886), signer(job_1886)], &prepare(cache1886, job_1886, Some(record_1886), &u1886), "1886 prepare, with a record").await?;
    step(&mut wallet, payer, || vec![actor(instance), actor(cache1886), signer(job_second)], &prepare(cache1886, job_second, None, &u1886), "1886 prepare, second job").await?;
    step(&mut wallet, payer, || vec![actor(record_1886)], &init(WS_MAIN_SECS), "unsigned init to the 1886 record (must revert)").await?;
    step(&mut wallet, payer, || vec![actor(job_1886)], &Message::Miller, "1886 miller").await?;
    step(&mut wallet, payer, || vec![actor(job_second)], &Message::Miller, "1886 miller, second job").await?;
    step(&mut wallet, payer, || vec![actor(job_1886), actor(instance), signer(record_1886)], &Message::Finish, "1886 finish, with a record").await?;
    show(&wallet, program, instance, "after the 1886 update").await?;
    show_record(&wallet, program, record_1886, "1886 record").await?;
    step(&mut wallet, payer, || vec![actor(job_second), actor(instance)], &Message::Finish, "1886 finish, second job (must revert)").await?;
    show(&wallet, program, job_second, "second job").await?;

    step(&mut wallet, payer, || vec![actor(instance_ws), actor(cache1885), signer(job_ws)], &prepare(cache1885, job_ws, None, &u1885), "1885 prepare past the 14-day window (must revert)").await?;
    show(&wallet, program, instance_ws, "14-day instance").await?;
    show(&wallet, program, job_ws, "14-day job").await?;

    let wait = (closes_at + 20_000).saturating_sub(now_ms());
    println!("waiting {} s for the closing instance's window to pass", wait / 1000);
    tokio::time::sleep(Duration::from_millis(wait)).await;
    step(&mut wallet, payer, || vec![actor(job_closing), actor(instance_closing)], &Message::Finish, "1885 finish after the closing instance's window (must revert)").await?;
    show(&wallet, program, instance_closing, "closing instance").await?;
    show(&wallet, program, job_closing, "closing instance's job").await?;
    Ok(())
}

fn unsigned(program: AccountId, account: AccountId) -> AccountMention {
    AccountIdentity::PublicNoSign(account).select_program_actor_state(program)
}

fn signed(program: AccountId, account: AccountId) -> AccountMention {
    AccountIdentity::Public(account).select_program_actor_state(program)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// The three transactions of one update. The job signs its Prepare and the record its Finish.
#[allow(clippy::too_many_arguments)]
async fn update_steps(
    wallet: &mut Wallet,
    payer: AccountId,
    program: AccountId,
    instance: AccountId,
    committee: AccountId,
    job: AccountId,
    record: Option<AccountId>,
    u: &Update,
    name: &str,
) -> Result<()> {
    let prepare = Message::Prepare { committee, job, record, update: Box::new(u.clone()) };
    let prepared = || vec![unsigned(program, instance), unsigned(program, committee), signed(program, job)];
    step(wallet, payer, prepared, &prepare, &format!("{name} prepare")).await?;
    step(wallet, payer, || vec![unsigned(program, job)], &Message::Miller, &format!("{name} miller")).await?;
    let finished = || {
        let mut accounts = vec![unsigned(program, job), unsigned(program, instance)];
        accounts.extend(record.map(|record| signed(program, record)));
        accounts
    };
    step(wallet, payer, finished, &Message::Finish, &format!("{name} finish")).await
}

fn halves(keys: &[[u8; 48]], aggregate: &[u8; 48], root: Root) -> Result<(Message, Message)> {
    let raw = uncompressed(keys)?;
    Ok((
        Message::InstallFirst { root, second_root: second_root(keys), aggregate: *aggregate, keys: raw[..HALF].to_vec() },
        Message::InstallSecond { keys: raw[HALF..].to_vec() },
    ))
}

fn uncompressed(keys: &[[u8; 48]]) -> Result<Vec<[u8; 96]>> {
    keys.iter()
        .map(|k| {
            blst::min_pk::PublicKey::uncompress(k)
                .map(|pk| pk.serialize())
                .map_err(|e| anyhow!("key: {e:?}"))
        })
        .collect()
}

fn second_root(keys: &[[u8; 48]]) -> Root {
    merkleize(&keys[HALF..].iter().map(key_leaf).collect::<Vec<_>>(), HALF)
}

/// Dry run for the metered cycles, then the real send and the fee the payer was charged.
async fn step(
    wallet: &mut Wallet,
    payer: AccountId,
    accounts: impl Fn() -> Vec<AccountMention>,
    message: &Message,
    name: &str,
) -> Result<()> {
    let bytes = borsh::to_vec(message)?;
    println!("== STEP {name}: message {} bytes", bytes.len());
    wallet.set_dry_run(true);
    let dry = wallet.send_pub_tx_paid_by(accounts(), 0, bytes.clone(), Some(payer)).await;
    wallet.set_dry_run(false);
    match &dry {
        Err(ExecutionFailureKind::DryRun(report)) => println!("{report}"),
        Err(error) => println!("   dry run error: {error:?}"),
        Ok(_) => {}
    }
    let before = wallet.get_account_balance(payer).await?;
    wallet.set_allow_revert(name.ends_with("(must revert)"));
    let sent = wallet.send_pub_tx_paid_by(accounts(), 0, bytes, Some(payer)).await;
    wallet.set_allow_revert(false);
    let hash = sent.map_err(|error| anyhow!("{name}: {error:?}"))?;
    let (_tx, block) = wallet.poll_transaction(hash).await?;
    let after = wallet.get_account_balance(payer).await?;
    println!("   included in block {block:?}, payer charged {}", before - after);
    Ok(())
}

async fn actor_state(wallet: &Wallet, program: AccountId, account: AccountId) -> Result<Vec<u8>> {
    Ok(wallet
        .get_account_view(Actor::new(account, program))
        .await?
        .map(|view| view.data.actor_state(program).to_vec())
        .unwrap_or_default())
}

async fn show(wallet: &Wallet, program: AccountId, account: AccountId, when: &str) -> Result<()> {
    let state = actor_state(wallet, program, account).await?;
    if state.is_empty() {
        println!("-- {when}: empty");
        return Ok(());
    }
    let short = |r: &Root| hex::encode(&r[..8]);
    match borsh::from_slice::<LightState>(&state).context("light-client state")? {
        LightState::Instance(i) => println!(
            "-- {when}: instance, state {} bytes, head slot {} block {} beacon root {}, current {:?}, next {:?}, window {} s",
            state.len(),
            i.head.slot,
            i.head.block_number,
            hex::encode(i.head.beacon_root),
            (i.current.0, short(&i.current.1)),
            i.next.map(|(p, r)| (p, short(&r))),
            i.config.ws_period_secs,
        ),
        LightState::Staging(s) => println!("-- {when}: staging, state {} bytes, root {}, {} keys", state.len(), short(&s.root), s.keys.len()),
        LightState::Committee(c) => println!("-- {when}: committee, state {} bytes, root {}, {} keys", state.len(), short(&c.root), c.keys.len()),
        LightState::Job(j) => println!("-- {when}: job, state {} bytes, stage {}", state.len(), j.stage),
    }
    Ok(())
}

async fn show_record(wallet: &Wallet, program: AccountId, record: AccountId, when: &str) -> Result<()> {
    let state = actor_state(wallet, program, record).await?;
    let written: lantern_spike_core::Record = borsh::from_slice(&state).context("record state")?;
    println!(
        "-- {when} {record:?}: {} bytes, instance {:?}, slot {}, block {}, execution state root {}",
        state.len(),
        written.instance,
        written.head.slot,
        written.head.block_number,
        hex::encode(written.head.execution_state_root)
    );
    Ok(())
}

struct Chain {
    genesis_validators_root: Root,
    genesis_time: u64,
    forks: Vec<(u64, [u8; 4])>,
}

impl Chain {
    fn config(&self, checkpoint_root: Root, ws_period_secs: u64) -> Config {
        Config {
            checkpoint_root,
            genesis_validators_root: self.genesis_validators_root,
            genesis_time: self.genesis_time,
            forks: self.forks.clone(),
            ws_period_secs,
        }
    }
}

fn chain(data: &Path) -> Result<Chain> {
    let genesis = load(data, "genesis.json")?["data"].clone();
    Ok(Chain {
        genesis_validators_root: arr(&genesis["genesis_validators_root"]),
        genesis_time: num(&genesis["genesis_time"]),
        forks: forks(&load(data, "spec.json")?["data"]),
    })
}

fn preflight(u: &Update, committee: &[[u8; 48]], chain: &Chain, name: &str) -> Result<()> {
    ensure!(
        verify_branch(&htr_beacon(&u.finalized.beacon), &u.finality_branch, lantern_spike_core::FINALIZED_ROOT_GINDEX, &u.attested.state_root),
        "{name}: finality branch"
    );
    verified_head(&u.finalized).with_context(|| format!("{name}: execution branch"))?;
    if let Some((root, branch)) = u.next_committee.as_ref() {
        ensure!(verify_branch(root, branch, NEXT_SYNC_COMMITTEE_GINDEX, &u.attested.state_root), "{name}: next branch");
    }
    let message = signing_root(&u.attested, u.signature_slot, &chain.forks, &chain.genesis_validators_root)
        .with_context(|| format!("{name}: no fork"))?;
    let keys: Vec<blst::min_pk::PublicKey> = committee
        .iter()
        .enumerate()
        .filter(|(i, _)| (u.bits[i / 8] >> (i % 8)) & 1 == 1)
        .map(|(_, k)| blst::min_pk::PublicKey::uncompress(k).map_err(|e| anyhow!("{e:?}")))
        .collect::<Result<_>>()?;
    let refs: Vec<&blst::min_pk::PublicKey> = keys.iter().collect();
    let sig = blst::min_pk::Signature::uncompress(&u.signature).map_err(|e| anyhow!("{e:?}"))?;
    ensure!(
        sig.fast_aggregate_verify(true, &message, DST, &refs) == blst::BLST_ERROR::BLST_SUCCESS,
        "{name}: signature"
    );
    println!("preflight {name}: {} signers, signing root {}", keys.len(), hex::encode(&message[..8]));
    Ok(())
}

fn committee_root(keys: &[[u8; 48]], aggregate: &[u8; 48]) -> Root {
    let leaves: Vec<Root> = keys.iter().map(key_leaf).collect();
    h2(&merkleize(&leaves, COMMITTEE_SIZE), &key_leaf(aggregate))
}

fn load(dir: &Path, name: &str) -> Result<Value> {
    let text = std::fs::read_to_string(dir.join(name)).with_context(|| format!("reading {name}"))?;
    Ok(serde_json::from_str(&text)?)
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string").trim_start_matches("0x")).expect("hex")
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().expect("length")
}

fn num(v: &Value) -> u64 {
    v.as_str().expect("decimal string").parse().expect("u64")
}

fn roots(v: &Value) -> Vec<Root> {
    v.as_array().expect("array").iter().map(arr).collect()
}

fn beacon(v: &Value) -> BeaconHeader {
    BeaconHeader {
        slot: num(&v["slot"]),
        proposer_index: num(&v["proposer_index"]),
        parent_root: arr(&v["parent_root"]),
        state_root: arr(&v["state_root"]),
        body_root: arr(&v["body_root"]),
    }
}

fn lc_header(v: &Value) -> LcHeader {
    let e = &v["execution"];
    let base_fee: u128 = e["base_fee_per_gas"].as_str().expect("fee").parse().expect("u128");
    let mut base_fee_per_gas = [0u8; 32];
    base_fee_per_gas[..16].copy_from_slice(&base_fee.to_le_bytes());
    LcHeader {
        beacon: beacon(&v["beacon"]),
        execution: ExecutionHeader {
            parent_hash: arr(&e["parent_hash"]),
            fee_recipient: arr(&e["fee_recipient"]),
            state_root: arr(&e["state_root"]),
            receipts_root: arr(&e["receipts_root"]),
            logs_bloom: arr(&e["logs_bloom"]),
            prev_randao: arr(&e["prev_randao"]),
            block_number: num(&e["block_number"]),
            gas_limit: num(&e["gas_limit"]),
            gas_used: num(&e["gas_used"]),
            timestamp: num(&e["timestamp"]),
            extra_data: bytes(&e["extra_data"]),
            base_fee_per_gas,
            block_hash: arr(&e["block_hash"]),
            transactions_root: arr(&e["transactions_root"]),
            withdrawals_root: arr(&e["withdrawals_root"]),
            blob_gas_used: num(&e["blob_gas_used"]),
            excess_blob_gas: num(&e["excess_blob_gas"]),
        },
        execution_branch: roots(&v["execution_branch"]),
    }
}

fn update(v: &Value, next_root: Root) -> Update {
    Update {
        attested: beacon(&v["attested_header"]["beacon"]),
        finalized: lc_header(&v["finalized_header"]),
        finality_branch: roots(&v["finality_branch"]),
        next_committee: v
            .get("next_sync_committee_branch")
            .map(|branch| (next_root, roots(branch))),
        bits: arr(&v["sync_aggregate"]["sync_committee_bits"]),
        signature: arr(&v["sync_aggregate"]["sync_committee_signature"]),
        signature_slot: num(&v["signature_slot"]),
    }
}

fn committee(v: &Value) -> (Vec<[u8; 48]>, [u8; 48]) {
    let keys = v["pubkeys"].as_array().expect("keys").iter().map(arr).collect();
    (keys, arr(&v["aggregate_pubkey"]))
}

fn forks(spec: &Value) -> Vec<(u64, [u8; 4])> {
    let map = spec.as_object().expect("spec object");
    let mut out: Vec<(u64, [u8; 4])> = map
        .iter()
        .filter_map(|(key, value)| {
            let name = key.strip_suffix("_FORK_VERSION")?;
            let epoch = if name == "GENESIS" {
                0
            } else {
                map.get(&format!("{name}_FORK_EPOCH"))?.as_str()?.parse::<u64>().ok()?
            };
            (epoch < 1 << 60).then(|| (epoch, arr(value)))
        })
        .collect();
    out.sort();
    out
}

/// A fresh instance from a recent checkpoint whose finality update writes a record, for the
/// private consumption. Writes the ids to `<fresh>/ids.json`.
async fn setup_private(args: Vec<String>) -> Result<()> {
    let [bin, payer, data, fresh]: [String; 4] = args
        .try_into()
        .map_err(|_| anyhow!("usage: setup-private <bin> <payer> <data dir> <fresh dir>"))?;
    let payer: AccountId = payer.parse().map_err(|error| anyhow!("payer: {error:?}"))?;
    let (data, fresh) = (std::path::PathBuf::from(data), std::path::PathBuf::from(fresh));
    let chain = chain(&data)?;
    let bootstrap = load(&fresh, "bootstrap.json")?["data"].clone();
    let checkpoint_root: Root = arr(&Value::String(
        std::fs::read_to_string(fresh.join("bootstrap_root.txt"))?.trim().to_owned(),
    ));
    let header = lc_header(&bootstrap["header"]);
    let (keys, aggregate) = committee(&bootstrap["current_sync_committee"]);
    let root = committee_root(&keys, &aggregate);
    let branch = roots(&bootstrap["current_sync_committee_branch"]);
    ensure!(htr_beacon(&header.beacon) == checkpoint_root, "bootstrap root");
    ensure!(verify_branch(&root, &branch, CURRENT_SYNC_COMMITTEE_GINDEX, &header.beacon.state_root), "bootstrap branch");
    let mut u = update(&load(&fresh, "finality_update.json")?["data"], [0; 32]);
    u.next_committee = None;
    preflight(&u, &keys, &chain, "fresh")?;

    let mut wallet = Wallet::from_env()?;
    let program = deploy(&mut wallet, &bin, payer).await?;
    let mut fresh_account = || wallet.create_new_account_public(None).0;
    let (instance, cache, job, record) = (fresh_account(), fresh_account(), fresh_account(), fresh_account());
    wallet.store_persistent_data()?;
    println!("instance {instance:?}, committee {cache:?}, job {job:?}, record {record:?}");
    let init = Message::Init {
        config: chain.config(checkpoint_root, WS_SHORT_SECS),
        header,
        committee_root: root,
        committee_branch: branch,
    };
    step(&mut wallet, payer, || vec![signed(program, instance)], &init, "fresh init").await?;
    let (first, second) = halves(&keys, &aggregate, root)?;
    step(&mut wallet, payer, || vec![signed(program, cache)], &first, "fresh install half 1").await?;
    step(&mut wallet, payer, || vec![unsigned(program, cache)], &second, "fresh install half 2").await?;
    update_steps(&mut wallet, payer, program, instance, cache, job, Some(record), &u, "fresh").await?;
    show(&wallet, program, instance, "fresh instance").await?;
    show_record(&wallet, program, record, "record").await?;
    std::fs::write(
        fresh.join("ids.json"),
        serde_json::json!({"program": format!("{program:?}"), "instance": format!("{instance:?}"), "committee": format!("{cache:?}"), "record": format!("{record:?}")}).to_string(),
    )?;
    Ok(())
}

/// The mid-period instance `setup-private` left crosses into the next period. The period's
/// served update teaches the next committee though it finalized before the head, then the latest
/// finality update, signed by that committee, rotates the instance.
async fn cross(args: Vec<String>) -> Result<()> {
    let [payer, data, fresh, served_dir]: [String; 4] = args
        .try_into()
        .map_err(|_| anyhow!("usage: cross <payer> <data dir> <fresh dir> <cross dir>"))?;
    let payer: AccountId = payer.parse().map_err(|error| anyhow!("payer: {error:?}"))?;
    let (data, fresh, served_dir) = (
        std::path::PathBuf::from(data),
        std::path::PathBuf::from(fresh),
        std::path::PathBuf::from(served_dir),
    );
    let chain = chain(&data)?;
    let ids = load(&fresh, "ids.json")?;
    let id = |key: &str| -> Result<AccountId> {
        ids[key].as_str().context("id")?.parse().map_err(|error| anyhow!("{key}: {error:?}"))
    };
    let (program, instance, current_cache, fresh_record) = (id("program")?, id("instance")?, id("committee")?, id("record")?);
    let (keys, _) = committee(&load(&fresh, "bootstrap.json")?["data"]["current_sync_committee"]);
    let served_json = load(&served_dir, "updates.json")?[0]["data"].clone();
    let (next_keys, next_aggregate) = committee(&served_json["next_sync_committee"]);
    let next_root = committee_root(&next_keys, &next_aggregate);
    let served = update(&served_json, next_root);
    preflight(&served, &keys, &chain, "served")?;
    let mut latest = update(&load(&served_dir, "finality_update.json")?["data"], [0; 32]);
    latest.next_committee = None;
    preflight(&latest, &next_keys, &chain, "latest")?;
    let served_period = period(served.attested.slot);
    ensure!(period(served.finalized.beacon.slot) == served_period, "served update finalized in another period");
    ensure!(period(served.signature_slot) == served_period, "served update signed in another period");
    ensure!(period(latest.signature_slot) == served_period + 1, "latest update not signed by the next committee");
    println!(
        "served: attested {}, finalized {}, signature {} (period {served_period}), next committee {}; latest: finalized {} (period {}), signature {} (period {})",
        served.attested.slot,
        served.finalized.beacon.slot,
        served.signature_slot,
        hex::encode(&next_root[..8]),
        latest.finalized.beacon.slot,
        period(latest.finalized.beacon.slot),
        latest.signature_slot,
        period(latest.signature_slot),
    );

    let mut wallet = Wallet::from_env()?;
    let mut fresh_account = || wallet.create_new_account_public(None).0;
    let (job_served, next_cache, job_latest, record_latest) = (fresh_account(), fresh_account(), fresh_account(), fresh_account());
    wallet.store_persistent_data()?;
    println!("served job {job_served:?}, next committee {next_cache:?}, latest job {job_latest:?}, latest record {record_latest:?}");
    // A valid consumption of the record setup-private wrote, sent unsigned into actors it does not own.
    let occupy = Message::Consume(Box::new(consume_request(&fresh, instance, fresh_record)?));
    show(&wallet, program, instance, "mid-period instance").await?;
    update_steps(&mut wallet, payer, program, instance, current_cache, job_served, None, &served, "served").await?;
    show(&wallet, program, instance, "after the served update").await?;
    step(&mut wallet, payer, || vec![unsigned(program, job_served), unsigned(program, fresh_record)], &occupy, "unsigned consume into the finished served job (must revert)").await?;
    show(&wallet, program, job_served, "served job").await?;
    let (first, second) = halves(&next_keys, &next_aggregate, next_root)?;
    step(&mut wallet, payer, || vec![signed(program, next_cache)], &first, "next committee install half 1").await?;
    step(&mut wallet, payer, || vec![unsigned(program, next_cache)], &second, "next committee install half 2").await?;
    show(&wallet, program, next_cache, "next committee").await?;
    let prepare = Message::Prepare { committee: next_cache, job: job_latest, record: Some(record_latest), update: Box::new(latest.clone()) };
    step(&mut wallet, payer, || vec![unsigned(program, instance), unsigned(program, next_cache), signed(program, job_latest)], &prepare, "latest prepare").await?;
    step(&mut wallet, payer, || vec![unsigned(program, job_latest)], &Message::Miller, "latest miller").await?;
    step(&mut wallet, payer, || vec![unsigned(program, record_latest), unsigned(program, fresh_record)], &occupy, "unsigned consume into the latest record before its step three (must revert)").await?;
    step(&mut wallet, payer, || vec![unsigned(program, job_latest), unsigned(program, instance), signed(program, record_latest)], &Message::Finish, "latest finish").await?;
    show(&wallet, program, instance, "after the latest update").await?;
    show_record(&wallet, program, record_latest, "latest record").await?;
    Ok(())
}

/// One private consumption: a private Lantern actor reads the record and proves WETH's slot 0.
/// With `--dry-run` it reports the public cycles and stops before proving.
async fn consume(args: Vec<String>) -> Result<()> {
    let dry_run_only = args.iter().any(|a| a == "--dry-run");
    let args: Vec<String> = args.into_iter().filter(|a| a != "--dry-run").collect();
    let [bin, fresh, consumer]: [String; 3] = args
        .try_into()
        .map_err(|_| anyhow!("usage: consume <bin> <fresh dir> <private consumer id> [--dry-run]"))?;
    let fresh = std::path::PathBuf::from(fresh);
    let consumer: AccountId = consumer.parse().map_err(|error| anyhow!("consumer: {error:?}"))?;
    let ids = load(&fresh, "ids.json")?;
    let id = |key: &str| -> Result<AccountId> {
        ids[key].as_str().context("id")?.parse().map_err(|error| anyhow!("{key}: {error:?}"))
    };
    let (program, instance, record) = (id("program")?, id("instance")?, id("record")?);
    let request = consume_request(&fresh, instance, record)?;
    let (account_nodes, storage_nodes) = (request.account_proof.len(), request.storage_proof.len());
    let message = borsh::to_vec(&Message::Consume(Box::new(request)))?;
    println!("consume: message {} bytes, account proof {account_nodes} nodes, storage proof {storage_nodes} nodes", message.len());

    let mut wallet = Wallet::from_env()?;
    wallet.sync_to_latest_block().await?;
    let bytecode = std::fs::read(&bin).with_context(|| format!("reading {bin}"))?;
    let programs = lee::privacy_preserving_transaction::circuit::ProgramCatalog::from([(
        program,
        lee::program::Program::new(bytecode.into()).map_err(|error| anyhow!("program: {error:?}"))?,
    )]);
    let mentions = || {
        vec![
            AccountIdentity::PrivateOwned(consumer).select_program_actor_state(program),
            AccountIdentity::PublicNoSign(record).select_program_actor_state(program),
        ]
    };
    wallet.set_dry_run(true);
    let dry = wallet.send_privacy_preserving_tx(mentions(), 0, message.clone(), &programs).await;
    wallet.set_dry_run(false);
    match &dry {
        Err(ExecutionFailureKind::DryRun(report)) => println!("{report}"),
        Err(error) => println!("   dry run error: {error:?}"),
        Ok(_) => {}
    }
    if dry_run_only {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let (hash, _) = wallet
        .send_privacy_preserving_tx(mentions(), 0, message, &programs)
        .await
        .map_err(|error| anyhow!("consume: {error:?}"))?;
    println!("consume: proved and sent in {:.1} s", started.elapsed().as_secs_f64());
    let (_tx, block) = wallet.poll_transaction(hash).await?;
    println!("consume: included in block {block:?}");
    wallet.sync_to_latest_block().await?;
    let account = wallet.get_account_private(consumer).context("consumer not tracked")?;
    let state: &[u8] = account.data.actor_state(program);
    let done: lantern_spike_core::Consumer = borsh::from_slice(state).context("consumer state")?;
    println!("consume: consumer state {done:?}");
    wallet.store_persistent_data()?;
    Ok(())
}

async fn deploy(wallet: &mut Wallet, bin: &str, payer: AccountId) -> Result<AccountId> {
    let bytecode = std::fs::read(bin).with_context(|| format!("reading {bin}"))?;
    let user_elf_len = risc0_binfmt::ProgramBinary::decode(&bytecode)
        .map_err(|error| anyhow!("not a program binary: {error:?}"))?
        .user_elf
        .len();
    let segment_count = user_elf_len.div_ceil(program_loader_core::MAX_SEGMENT_DATA_LEN);
    let header = wallet.create_new_account_public(None).0;
    let segments: Vec<AccountId> = std::iter::repeat_with(|| wallet.create_new_account_public(None).0)
        .take(segment_count)
        .collect();
    wallet.store_persistent_data()?;
    let program = ProgramLoader(&*wallet).deploy(header, &segments, bytecode, true, Some(payer)).await?;
    println!("program  {program:?}, {segment_count} segments, binary {} bytes", std::fs::metadata(bin)?.len());
    Ok(program)
}

/// WETH's account and storage slot 0 at the fresh finality update's block, read from `record`.
fn consume_request(fresh: &Path, instance: AccountId, record: AccountId) -> Result<lantern_spike_core::Consume> {
    let p = load(fresh, "proof_weth.json")?["result"].clone();
    let sp = &p["storageProof"][0];
    let proof = |v: &Value| -> Vec<Vec<u8>> { v.as_array().expect("proof").iter().map(bytes).collect() };
    Ok(lantern_spike_core::Consume {
        instance,
        record,
        address: arr(&p["address"]),
        nonce: u64::from_str_radix(p["nonce"].as_str().context("nonce")?.trim_start_matches("0x"), 16)?,
        balance: quantity(&p["balance"]),
        storage_root: arr(&p["storageHash"]),
        code_hash: arr(&p["codeHash"]),
        account_proof: proof(&p["accountProof"]),
        slot: quantity(&sp["key"]),
        value: quantity(&sp["value"]),
        storage_proof: proof(&sp["proof"]),
    })
}

/// A JSON-RPC quantity as a big-endian 32-byte word.
fn quantity(v: &Value) -> [u8; 32] {
    let digits = v.as_str().expect("quantity").trim_start_matches("0x");
    hex::decode(format!("{digits:0>64}")).expect("hex").try_into().expect("32 bytes")
}
