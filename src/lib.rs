use std::fs::{self, File};

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ff::{BigInteger, PrimeField, ToBytes};
use ark_groth16::{create_random_proof, generate_random_parameters, verify_proof, ProvingKey};
use arkworks_native_gadgets::{
    merkle_tree::{Path, SparseMerkleTree},
    poseidon::Poseidon,
};
use arkworks_setups::{
    common::{setup_params, setup_tree_and_create_path},
    r1cs::vanchor::VAnchorR1CSProver,
    utxo::Utxo,
    Curve, VAnchorProver,
};
use ethabi::{encode, Token};
use num_bigint::{BigInt, Sign};

type Bn254Fr = ark_bn254::Fr;

const TREE_DEPTH: usize = 30;
const ANCHOR_CT: usize = 2;
const NUM_UTXOS: usize = 2;
const DEFAULT_LEAF: [u8; 32] = [
    47, 229, 76, 96, 211, 172, 171, 243, 52, 58, 53, 182, 235, 161, 93, 180, 130, 27, 52, 15, 118,
    231, 65, 226, 36, 150, 133, 237, 72, 153, 175, 108,
];

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Element([u8; 32]);

impl Element {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(input: &[u8]) -> Self {
        let mut buf = [0u8; 32];
        buf.iter_mut().zip(input).for_each(|(a, b)| *a = *b);
        Self(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ExtData {
    pub recipient: [u8; 32],
    pub relayer: [u8; 32],
    pub ext_amount: i128,
    pub fee: u128,
    pub refund: u128,
    pub token: u32,
    pub encrypted_output1: Vec<u8>,
    pub encrypted_output2: Vec<u8>,
}

impl ExtData {
    pub fn new(
        recipient: [u8; 32],
        relayer: [u8; 32],
        ext_amount: i128,
        fee: u128,
        refund: u128,
        token: u32,
        encrypted_output1: Vec<u8>,
        encrypted_output2: Vec<u8>,
    ) -> Self {
        Self {
            recipient,
            relayer,
            ext_amount,
            fee,
            refund,
            token,
            encrypted_output1,
            encrypted_output2,
        }
    }

    fn into_abi(&self) -> Token {
        let recipient = Token::Bytes(self.recipient.to_vec());
        let ext_amount = Token::Bytes(self.ext_amount.to_be_bytes().to_vec());
        let relayer = Token::Bytes(self.relayer.to_vec().to_vec());
        let fee = Token::Bytes(self.fee.to_be_bytes().to_vec());
        let refund = Token::Bytes(self.refund.to_be_bytes().to_vec());
        let token = Token::Bytes(self.token.to_be_bytes().to_vec());
        let encrypted_output1 = Token::Bytes(self.encrypted_output1.clone());
        let encrypted_output2 = Token::Bytes(self.encrypted_output2.clone());
        let mut ext_data_args = Vec::new();
        ext_data_args.push(recipient);
        ext_data_args.push(relayer);
        ext_data_args.push(ext_amount);
        ext_data_args.push(fee);
        ext_data_args.push(refund);
        ext_data_args.push(token);
        ext_data_args.push(encrypted_output1);
        ext_data_args.push(encrypted_output2);
        Token::Tuple(ext_data_args)
    }

    fn encode_abi(&self) -> Vec<u8> {
        encode(&[self.into_abi()])
    }
}

fn setup_environment_with_circom() -> (ProvingKey<Bn254>, CircomConfig<Bn254>) {
    let wasm_2_2_path = fs::canonicalize("poseidon_vanchor_2_2.wasm");
    let r1cs_2_2_path = fs::canonicalize("poseidon_vanchor_2_2.r1cs");
    let cfg_2_2 =
        CircomConfig::<Bn254>::new(wasm_2_2_path.unwrap(), r1cs_2_2_path.unwrap()).unwrap();

    let mut file_2_2 = File::open("circuit_final.zkey").unwrap();
    let (params_2_2, _matrices) = ark_circom::read_zkey(&mut file_2_2).unwrap();
    (params_2_2, cfg_2_2)
}

fn insert_utxos_to_merkle_tree(
    utxos: &[Utxo<Bn254Fr>; 2],
    neighbor_roots: [Element; ANCHOR_CT - 1],
    custom_root: Element,
) -> (
    [u64; 2],
    [Vec<u8>; 2],
    SparseMerkleTree<Bn254Fr, Poseidon<Bn254Fr>, TREE_DEPTH>,
    Vec<Path<Bn254Fr, Poseidon<Bn254Fr>, TREE_DEPTH>>,
) {
    let curve = Curve::Bn254;
    let leaf0 = utxos[0].commitment.into_repr().to_bytes_be();
    let leaf1 = utxos[1].commitment.into_repr().to_bytes_be();

    let leaves: Vec<Vec<u8>> = vec![leaf0, leaf1];
    let leaves_f: Vec<Bn254Fr> = leaves
        .iter()
        .map(|x| Bn254Fr::from_be_bytes_mod_order(x))
        .collect();

    let in_indices = [0, 1];

    let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
    let poseidon3 = Poseidon::new(params3);
    let (tree, _) = setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, TREE_DEPTH>(
        &poseidon3,
        &leaves_f,
        0,
        &DEFAULT_LEAF,
    )
    .unwrap();

    let in_paths: Vec<_> = in_indices
        .iter()
        .map(|i| tree.generate_membership_proof(*i))
        .collect();

    let roots_f: [Bn254Fr; ANCHOR_CT] = vec![if custom_root != Element::from_bytes(&[0u8; 32]) {
        Bn254Fr::from_be_bytes_mod_order(custom_root.as_bytes())
    } else {
        tree.root()
    }]
    .iter()
    .chain(
        neighbor_roots
            .iter()
            .map(|r| Bn254Fr::from_be_bytes_mod_order(r.as_bytes()))
            .collect::<Vec<Bn254Fr>>()
            .iter(),
    )
    .cloned()
    .collect::<Vec<Bn254Fr>>()
    .try_into()
    .unwrap();
    let in_root_set = roots_f.map(|x| x.into_repr().to_bytes_be());

    (in_indices, in_root_set, tree, in_paths)
}

pub fn setup_circom_zk_circuit(
    config: CircomConfig<Bn254>,
    public_amount: i128,
    chain_id: u64,
    ext_data_hash: Vec<u8>,
    in_utxos: [Utxo<Bn254Fr>; NUM_UTXOS],
    out_utxos: [Utxo<Bn254Fr>; NUM_UTXOS],
    proving_key: ProvingKey<Bn254>,
    neighbor_roots: [Element; ANCHOR_CT - 1],
    custom_root: Element,
) -> (Vec<u8>, Vec<Bn254Fr>) {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    let (in_indices, _in_root_set, _tree, in_paths) =
        insert_utxos_to_merkle_tree(&in_utxos, neighbor_roots, custom_root);

    let params4 = setup_params::<Bn254Fr>(Curve::Bn254, 5, 4);
    let nullifier_hasher = Poseidon::<Bn254Fr> { params: params4 };
    let input_nullifiers = in_utxos
        .clone()
        .map(|utxo| utxo.calculate_nullifier(&nullifier_hasher).unwrap());

    let mut builder = CircomBuilder::new(config);
    // Public inputs
    // publicAmount, extDataHash, inputNullifier, outputCommitment, chainID, roots
    builder.push_input(
        "publicAmount",
        BigInt::from_bytes_be(Sign::Plus, &public_amount.to_be_bytes()),
    );
    builder.push_input(
        "extDataHash",
        BigInt::from_bytes_be(Sign::Plus, &ext_data_hash),
    );
    for i in 0..NUM_UTXOS {
        builder.push_input(
            "inputNullifier",
            BigInt::from_bytes_be(Sign::Plus, &input_nullifiers[i].into_repr().to_bytes_be()),
        );
        builder.push_input(
            "outputCommitment",
            BigInt::from_bytes_be(
                Sign::Plus,
                &out_utxos[i].commitment.into_repr().to_bytes_be(),
            ),
        );
    }
    builder.push_input(
        "chainID",
        BigInt::from_bytes_be(Sign::Plus, &chain_id.to_be_bytes()),
    );
    builder.push_input("roots", BigInt::from_bytes_be(Sign::Plus, &custom_root.0));
    (0..ANCHOR_CT - 1).for_each(|i| {
        builder.push_input(
            "roots",
            BigInt::from_bytes_be(Sign::Plus, &neighbor_roots[i].0),
        );
    });
    // Private inputs
    // inAmount, inPrivateKey, inBlinding, inPathIndices, inPathElements
    // outChainID, outAmount, outPubkey, outBlinding
    for i in 0..NUM_UTXOS {
        builder.push_input(
            "inAmount",
            BigInt::from_bytes_be(Sign::Plus, &in_utxos[i].amount.into_repr().to_bytes_be()),
        );
        builder.push_input(
            "inPrivateKey",
            BigInt::from_bytes_be(
                Sign::Plus,
                &in_utxos[i]
                    .keypair
                    .secret_key
                    .unwrap()
                    .into_repr()
                    .to_bytes_be(),
            ),
        );
        builder.push_input(
            "inBlinding",
            BigInt::from_bytes_be(Sign::Plus, &in_utxos[i].blinding.into_repr().to_bytes_be()),
        );
        builder.push_input("inPathIndices", BigInt::from(in_indices[i]));
        for j in 0..TREE_DEPTH {
            let neighbor_elt: Bn254Fr = if in_indices[i] == 0 {
                in_paths[i].path[j].1
            } else {
                in_paths[i].path[j].0
            };
            builder.push_input(
                "inPathElements",
                BigInt::from_bytes_be(Sign::Plus, &neighbor_elt.into_repr().to_bytes_be()),
            );
        }

        builder.push_input(
            "outChainID",
            BigInt::from_bytes_be(Sign::Plus, &out_utxos[i].chain_id.into_repr().to_bytes_be()),
        );
        builder.push_input(
            "outAmount",
            BigInt::from_bytes_be(Sign::Plus, &out_utxos[i].amount.into_repr().to_bytes_be()),
        );
        builder.push_input(
            "outPubkey",
            BigInt::from_bytes_be(
                Sign::Plus,
                &out_utxos[i].keypair.public_key.into_repr().to_bytes_be(),
            ),
        );
        builder.push_input(
            "outBlinding",
            BigInt::from_bytes_be(Sign::Plus, &out_utxos[i].blinding.into_repr().to_bytes_be()),
        );
    }

    let mut rng = rand::thread_rng();
    let circom = builder.setup();
    let proving_key = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();
    let circom = builder.build().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let is_satisfied = cs.is_satisfied().unwrap();
    println!("is satisfied: {is_satisfied}");
    if !is_satisfied {
        println!(
            "Unsatisfied constraint: {:?}",
            cs.which_is_unsatisfied().unwrap()
        );
    }

    let inputs = circom.get_public_inputs().unwrap();
    println!("inputs: {:?}", inputs.len());
    // Generate the proof
    let mut proof_bytes = vec![];
    let proof = create_random_proof(circom, &proving_key, &mut rng).unwrap();
    proof.write(&mut proof_bytes).unwrap();
    // let pvk = prepare_verifying_key(&params.vk);
    let pvk = proving_key.vk.into();
    let verified = verify_proof(&pvk, &proof, &inputs).expect("verification should not fail");

    assert!(verified, "Proof is not verified");

    (proof_bytes, inputs)
}

#[allow(non_camel_case_types)]
type VAnchorProver_Bn254_30_2_2_2 =
    VAnchorR1CSProver<Bn254, TREE_DEPTH, ANCHOR_CT, NUM_UTXOS, NUM_UTXOS>;

pub fn setup_utxos(
    // Transaction inputs
    chain_ids: [u64; NUM_UTXOS],
    amounts: [u128; NUM_UTXOS],
    indices: Option<[u64; NUM_UTXOS]>,
) -> [Utxo<Bn254Fr>; NUM_UTXOS] {
    let curve = Curve::Bn254;
    let rng = &mut rand::thread_rng();
    // Input Utxos
    let indices: [Option<u64>; NUM_UTXOS] = if indices.is_some() {
        let ind_unw = indices.unwrap();
        ind_unw.map(Some)
    } else {
        [None; NUM_UTXOS]
    };
    let utxo1 = VAnchorProver_Bn254_30_2_2_2::create_random_utxo(
        curve,
        chain_ids[0],
        amounts[0],
        indices[0],
        rng,
    )
    .unwrap();
    let utxo2 = VAnchorProver_Bn254_30_2_2_2::create_random_utxo(
        curve,
        chain_ids[1],
        amounts[1],
        indices[1],
        rng,
    )
    .unwrap();

    [utxo1, utxo2]
}

#[cfg(test)]
mod tests {
    use arkworks_setups::common::keccak_256;

    use super::*;

    const EDGE_CT: usize = 1;
    #[test]
    fn it_works() {
        let (params_2_2, cfg_2_2) = setup_environment_with_circom();
        let recipient = [1u8; 32];
        let relayer = [2u8; 32];
        let ext_amount = 10_i128;
        let public_amount = 10_i128;
        let fee = 0;

        let chain_id = 0x0000000200000001;
        let in_chain_ids = [chain_id; 2];
        let in_amounts = [0, 0];
        let in_indices = [0, 1];
        let out_chain_ids = [chain_id; 2];
        let out_amounts = [10, 0];

        let in_utxos = setup_utxos(in_chain_ids, in_amounts, Some(in_indices));
        let out_utxos = setup_utxos(out_chain_ids, out_amounts, None);

        let output1 = out_utxos[0].commitment.into_repr().to_bytes_be();
        let output2 = out_utxos[1].commitment.into_repr().to_bytes_be();
        let ext_data = ExtData::new(
            recipient,
            relayer,
            ext_amount,
            fee,
            0,
            0,
            // Mock encryption value, not meant to be used in production
            output1.to_vec(),
            // Mock encryption value, not meant to be used in production
            output2.to_vec(),
        );

        let ext_data_hash = keccak_256(&ext_data.encode_abi());

        let custom_root = Element(DEFAULT_LEAF);
        let neighbor_roots: [Element; EDGE_CT] = [Element(DEFAULT_LEAF); EDGE_CT];
        let (_proof, _public_inputs) = setup_circom_zk_circuit(
            cfg_2_2,
            public_amount,
            chain_id,
            ext_data_hash.to_vec(),
            in_utxos,
            out_utxos,
            params_2_2,
            neighbor_roots,
            custom_root,
        );
    }
}
