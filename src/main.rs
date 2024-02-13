use std::str::FromStr;

// use bincode::serialize;
use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::Keypair;
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use bitcoin::consensus::serialize;

use sign_tx::{get_mnemonic_keypair, segwit_ecdsa_sign, taproot_schnorr_sign};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1,000 sat fee

fn main() {
    // dummy_example();
    testnet_example();
}

fn testnet_example() {
    let network = Network::Testnet;

    let seeds = std::env::var("SEEDS").expect("SEEDS environment not set");
    // let txid = "9a0485d541757b501937e30635ad082339bfbcc774bec8bcfbe73f6bf1f5cf79";
    let txid = "572d9575f26070122a736eb40d6cb1e2dce8b57d88f160f269aee639d0ad5397";

    let prevout = OutPoint {
        txid: Txid::from_str(txid).unwrap(),
        vout: 1,
    };

    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let total_amount = Amount::from_sat(555_168);
    let spend_amount = Amount::from_sat(546);
    let fee = Amount::from_sat(200);
    let change_amount = total_amount - spend_amount - fee;

    let recipient =
        Address::from_str("tb1pzzw7e8ttz24utjyl32tjpulyvarq6jkkthpcy5826kqenx3epa3qetj8zd")
            .unwrap()
            .require_network(network)
            .unwrap();
    let spend = TxOut {
        value: spend_amount,
        script_pubkey: recipient.script_pubkey(),
    };

    let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
    let secp = Secp256k1::new();
    let keypair = get_mnemonic_keypair(seeds.as_str(), "", &path, &network);
    let sk = keypair.secret_key();
    let (pubkey, _) = keypair.x_only_public_key();

    let address = Address::p2tr(&secp, pubkey, None, network);
    assert_eq!(address, recipient);

    let script_pubkey = ScriptBuf::new_p2tr(&secp, pubkey, None);
    let change = TxOut {
        value: change_amount,
        script_pubkey: script_pubkey.clone(),
    };

    let pre_utxo = TxOut {
        value: total_amount,
        script_pubkey,
    };
    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };
    let tx = taproot_schnorr_sign(&[pre_utxo], &mut unsigned_tx, &sk, &secp);
    let raw_tx = serialize(&tx).to_lower_hex_string();
    eprintln!("{raw_tx}");
}

#[allow(unused)]
fn dummy_example() {
    let secp = Secp256k1::new();

    let sk = SecretKey::new(&mut rand::thread_rng());

    // segwit v0
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let wpkh = pk.wpubkey_hash().expect("key is compressed");

    let recipient = Address::from_str("bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf")
        .expect("invalid address")
        .require_network(Network::Bitcoin)
        .expect("invalid address for mainnet");

    let dummy_out_point = OutPoint {
        txid: Txid::all_zeros(),
        vout: 0,
    };

    let input = TxIn {
        previous_output: dummy_out_point,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let spend = TxOut {
        value: SPEND_AMOUNT,
        script_pubkey: recipient.script_pubkey(),
    };

    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2wpkh(&wpkh), // segwit v0
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input.clone()],
        output: vec![spend, change],
    };
    let dummy_utxo = TxOut {
        value: DUMMY_UTXO_AMOUNT,
        script_pubkey: ScriptBuf::new_p2wpkh(&wpkh), // sigwit v0
    };
    let tx = segwit_ecdsa_sign(&dummy_utxo, &mut unsigned_tx, &sk, &secp, &SPEND_AMOUNT);
    // println!("{:#?}", tx);
    let raw_tx: Vec<u8> = serialize(&tx);
    let raw_tx = raw_tx.to_hex_string(bitcoin::hex::Case::Lower);
    println!("{raw_tx}");

    // segwit v1, taproot, p2tr
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = keypair.x_only_public_key();
    let recipient =
        Address::from_str("bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va")
            .expect("a valid address")
            .require_network(Network::Bitcoin)
            .expect("valid address for mainnet");
    let spend = TxOut {
        value: SPEND_AMOUNT,
        script_pubkey: recipient.script_pubkey(),
    };
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None), // taproot, i.e. segwit v1
    };
    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    let dummy_utxo = TxOut {
        value: DUMMY_UTXO_AMOUNT,
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
    };
    let tx = taproot_schnorr_sign(&[dummy_utxo], &mut unsigned_tx, &sk, &secp);

    let raw_tx: Vec<u8> = serialize(&tx);
    let raw_tx = raw_tx.to_hex_string(bitcoin::hex::Case::Lower);
    // println!("{:#?}, {:?}", tx, raw_tx);
    println!("{raw_tx}");
}
