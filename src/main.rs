use std::str::FromStr;

use bincode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::Keypair;
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use sign_tx::{segwit_ecdsa_sign, taproot_schnorr_sign};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1,000 sat fee

fn main() {
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
    let raw_tx: Vec<u8> = serialize(&tx).unwrap();
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

    let raw_tx: Vec<u8> = serialize(&tx).unwrap();
    let raw_tx = raw_tx.to_hex_string(bitcoin::hex::Case::Lower);
    // println!("{:#?}, {:?}", tx, raw_tx);
    println!("{raw_tx}");
}
