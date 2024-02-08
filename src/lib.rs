use bitcoin::bip32::{DerivationPath, Xpriv};
use core::str;
use hex::FromHex;

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    opcodes::all::*, opcodes::OP_0, Amount, Network, ScriptBuf, Transaction, TxOut, Witness,
};

pub fn get_mnemonic_keypair(
    seeds: &str,
    password: &str,
    path: &DerivationPath,
    network: &Network,
) -> Keypair {
    let mnemonic = bip39::Mnemonic::from_str(seeds).expect("Can not convert seeds to mnemonic");
    let seed = mnemonic.to_seed(password);
    let master = Xpriv::new_master(*network, &seed).unwrap();
    let secp = Secp256k1::new();
    let child = master.derive_priv(&secp, path).unwrap();
    child.to_keypair(&secp)
}

pub fn segwit_ecdsa_sign<C: Signing>(
    prevout: &TxOut,
    tx: &mut Transaction,
    sk: &SecretKey,
    secp: &Secp256k1<C>,
    spend_amount: &Amount,
) -> Transaction {
    let sighash_type = EcdsaSighashType::All;
    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .p2wpkh_signature_hash(
            input_index,
            &prevout.script_pubkey,
            *spend_amount,
            sighash_type,
        )
        .expect("failed to create sighash");

    let msg = Message::from(sighash);
    let signature = secp.sign_ecdsa(&msg, sk);

    let signature = bitcoin::ecdsa::Signature {
        sig: signature,
        hash_ty: sighash_type,
    };

    let pk = sk.public_key(secp);
    *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk);

    sighasher.into_transaction().to_owned()
}

pub fn taproot_schnorr_sign<C: Signing + Verification>(
    prevouts: &[TxOut],
    tx: &mut Transaction,
    sk: &SecretKey,
    secp: &Secp256k1<C>,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(prevouts);

    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    let tweaked: TweakedKeypair = keypair.tap_tweak(secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_inner());

    let signature = bitcoin::taproot::Signature {
        sig: signature,
        hash_ty: sighash_type,
    };
    let sig_bytes = signature.to_vec();
    // *sighasher.witness_mut(input_index).unwrap() = Witness::from_slice(&[&sig_bytes]);
    let mut witness = Witness::new();
    witness.push(sig_bytes);

    let script = sats_mint_script();
    let script = script.as_bytes();
    witness.push(script);
    // TODO: another unknown 32-bytes with c0/c1 (OP_RETURN_192/OP_RETURN_193)
    // witness.push(another_script);
    eprintln!("{witness:#?}");
    *sighasher.witness_mut(input_index).unwrap() = witness;

    // eprintln!("{:#?}", Witness::from_slice(&[sig_bytes]));
    sighasher.into_transaction().to_owned()
}

pub fn sats_mint_script() -> ScriptBuf {
    let mut script = ScriptBuf::new();

    script.push_opcode(OP_PUSHBYTES_32);
    // TODO: determine what's the 32 bytes are, maybe the p2tr script pubkey
    script.push_slice([]);
    script.push_opcode(OP_CHECKSIG);

    script.push_opcode(OP_0);
    script.push_opcode(OP_IF);

    script.push_opcode(OP_PUSHBYTES_3);
    script.push_slice(<[u8; 3]>::from_hex("6f7264").unwrap());

    script.push_opcode(OP_PUSHBYTES_1);
    script.push_slice(<[u8; 1]>::from_hex("01").unwrap());

    script.push_opcode(OP_PUSHBYTES_24);
    script.push_slice(
        <[u8; 24]>::from_hex("746578742f706c61696e3b636861727365743d7574662d38").unwrap(),
    );
    script.push_opcode(OP_0);

    script.push_opcode(OP_PUSHBYTES_51);
    script.push_slice(<[u8; 51]>::from_hex("7b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a2273617473222c22616d74223a223130227d").unwrap());
    script.push_opcode(OP_ENDIF);

    script
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, consensus::serialize, hex::DisplayHex, transaction, Address, OutPoint, ScriptBuf,
        Sequence, TxIn, Txid,
    };

    use core::str;
    // use hex::FromHex;

    use super::*;

    // the following two wallet is drained, and not use anymore.
    const SEEDS: &str = "loan join session common coast damp release you pond mystery ripple auction arrange permit negative this mandate honey turn shuffle give amazing catalog extra";
    const SEEDS2: &str =
        "delay ring ice cool purity goat bachelor avoid shine walnut forget impulse";
    #[allow(non_upper_case_globals)]
    const network: Network = Network::Testnet;
    #[test]
    fn mnemonic_test() {
        // let path: DerivationPath = "m/86'/1'/0'/0/0".parse().unwrap();
        let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
        let secp = Secp256k1::new();
        // let keypair = get_mnemonic_keypair(SEEDS, "", &path, &network);
        let keypair = get_mnemonic_keypair(SEEDS2, "", &path, &network);
        let (internal_key, _) = keypair.x_only_public_key();
        let address = Address::p2tr(&secp, internal_key, None, network);

        // eprintln!("{address}");
        // let orig_address = "tb1pgvdtj32j7vyhx3tp33h72qk0cdv0kzjlsske2pludsvf7ex32eksaa8z5p";
        let orig_address = "tb1pm3ygx3jshwssf2wypqy8hqeyd98zv3juwwv0atkwls3artlt5vus6lyj38";
        assert_eq!(&address.to_string(), orig_address);

        // let sk = keypair.secret_key();
        // let prv_key = PrivateKey::new(sk, network);
        // eprintln!("WIF: {}", prv_key.to_wif());
    }

    #[test]
    fn taproot_sign_test() {
        let txid = "6bb7c09c7c19bba0a5bdb4e1eb1f8f34293bfbe103f57a95b459bb8daadc95a8";
        let prevout = OutPoint {
            txid: Txid::from_str(txid).unwrap(),
            vout: 0,
        };

        let input = TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        let total_amount = Amount::from_sat(2100);
        let spend_amount = Amount::from_sat(1000);
        let fee = Amount::from_sat(155);
        let change_amount = total_amount - spend_amount - fee;

        let recipient =
            Address::from_str("tb1pvwx9wckujnk8p47tllef9xlzvlalu329x35h5everqj5gcquda0skwefgm")
                .unwrap()
                .require_network(network)
                .unwrap();
        let spend = TxOut {
            value: spend_amount,
            script_pubkey: recipient.script_pubkey(),
        };

        let path: DerivationPath = "m/86'/1'/0'/0/0".parse().unwrap();
        let secp = Secp256k1::new();
        let keypair = get_mnemonic_keypair(SEEDS, "", &path, &network);
        let sk = keypair.secret_key();
        let (internal_key, _) = keypair.x_only_public_key();

        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
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
        let _raw_tx = serialize(&tx).to_lower_hex_string();
        // eprintln!("{raw_tx}");
        // assert_eq!(raw_tx.as_str(), "02000000000101a895dcaa8dbb59b4957af503e1fb3b29348f1febe1b4bda5a0bb197c9cc0b76b0000000000fdffffff02e803000000000000225120638c5762dc94ec70d7cbfff2929be267fbfe454534697a6599182544601c6f5fb103000000000000225120431ab94552f3097345618c6fe502cfc358fb0a5f842d9507fc6c189f64d1566d0140f626a6233b7f82f5648f66489120e80df2ffa2d6eff46ee4116ae9e255923c912eadf2e5d0a598869c1facaca0a48651ec0b0a0fc9fcd770513ee89d196de6b800000000");
    }

    #[test]
    fn taproot_mint_sats_test() {
        let txid = "5bf4e0c191a952e1e00e07b21c611f4df18520758c8a6bd3a9275495c83287bb";
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

        let total_amount = Amount::from_sat(558_523);
        let spend_amount = Amount::from_sat(546);
        let fee = Amount::from_sat(200);
        let change_amount = total_amount - spend_amount - fee;

        let recipient =
            Address::from_str("tb1pep9ctpc32jf5zsdtnx8v49dghwuxk3dewcndzqa7qflsa97kxtyqnd8ryl")
                .unwrap()
                .require_network(network)
                .unwrap();
        let spend = TxOut {
            value: spend_amount,
            script_pubkey: recipient.script_pubkey(),
        };

        let path: DerivationPath = "m/86'/1'/0'/0/1".parse().unwrap();
        let secp = Secp256k1::new();
        let keypair = get_mnemonic_keypair(SEEDS, "", &path, &network);
        let sk = keypair.secret_key();
        let (internal_key, _) = keypair.x_only_public_key();

        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
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
}
