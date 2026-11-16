//! RFP-021 feasibility spike: one sync-committee finality update verified inside a private transaction.

use super::*;

#[test]
fn rfp021_update_private_tx() {
    let path = std::env::var("RFP021_INSTRUCTION").expect("RFP021_INSTRUCTION names the borsh instruction file");
    let instruction_data = std::fs::read(path).unwrap();
    let program = crate::test_methods::rfp021_update_verify();
    let keys = test_private_account_keys_1();
    let instance_account = Account {
        nonce: Nonce(1),
        ..Account::default()
    };
    let mut state = V03State::new()
        .with_private_account(&keys, &instance_account)
        .with_programs([program.clone()]);
    let program_id = AccountId::from_builtin_program(program.id());
    let instance_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO);
    let membership = state
        .get_proof_for_commitment(&Commitment::new(&instance_id, &instance_account))
        .unwrap();
    let deps = ProgramWithDependencies::new(program, program_id, HashMap::new());

    let started = std::time::Instant::now();
    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(instance_id, program_id)],
            private_witnesses: vec![update_witness(&keys, Identifier::ZERO, instance_account, membership)],
            instruction_data,
            dummy_inputs: vec![],
            ciphertext_padding: Some(512),
            ..Default::default()
        },
        &deps,
    )
    .unwrap();
    let elapsed = started.elapsed();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let tx_bytes = borsh::to_vec(&tx).unwrap().len();
    let proof_bytes = tx.witness_set.proof().clone().into_inner().len();
    eprintln!("RFP021 update private tx prove_time={elapsed:?} proof_bytes={proof_bytes} tx_bytes={tx_bytes}");
    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 1_500)
        .unwrap();
    eprintln!("RFP021   settled");
}
