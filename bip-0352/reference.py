#!/usr/bin/env python3

import hashlib
import json
import bip32
from typing import List, Tuple, Dict, Union
from sys import argv

# local files
from bech32m import convertbits, bech32_encode, decode, Encoding
from secp256k1 import ECKey, ECPubKey


def sha256(s: Union[bytes, bytearray]) -> bytes:
    return hashlib.sha256(s).digest()


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, 'big')


def hash_outpoints(outpoints: List[Tuple[str, int]]) -> bytes:

    outpoints_sorted = sorted([
        bytearray.fromhex(txid)[::-1] + n.to_bytes(4, 'little')
        for txid, n in outpoints
    ])

    s = hashlib.new('sha256')
    for op in outpoints_sorted:
        s.update(op)

    return s.digest()


def derive_silent_payment_key_pair(seed: bytes) -> Tuple[ECKey, ECKey, ECPubKey, ECPubKey]:

    SCAN_KEY="m/352h/0h/0h/1h/0"
    SPEND_KEY="m/352h/0h/0h/0h/0"

    master = bip32.BIP32.from_seed(seed)
    scan = ECKey().set(master.get_privkey_from_path(SCAN_KEY))
    spend = ECKey().set(master.get_privkey_from_path(SPEND_KEY))
    Scan = scan.get_pubkey()
    Spend = spend.get_pubkey()

    return scan, spend, Scan, Spend


def encode_silent_payment_address(B_scan: ECPubKey, B_m: ECPubKey, hrp: str = "tsp", version: int = 0) -> str:

    data = convertbits(B_scan.get_bytes(False) + B_m.get_bytes(False), 8, 5)
    return bech32_encode(hrp, [version] + data, Encoding.BECH32M)


def create_labeled_silent_payment_address(B_scan: ECPubKey, B_spend: ECPubKey, m: bytes, hrp: str = "tsp", version: int = 0) -> str:

    G = ECKey().set(1).get_pubkey()
    B_m = B_spend + m * G
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)

    return labeled_address


def decode_silent_payment_address(address: str, hrp: str = "tsp") -> Tuple[ECPubKey, ECPubKey]:

    version, data = decode(hrp, address)
    B_scan = ECPubKey().set(data[:33])
    B_spend = ECPubKey().set(data[33:])

    return B_scan, B_spend


def create_outputs(input_priv_keys: List[Tuple[ECKey, bool]], outpoints_hash: bytes, recipients: List[Tuple[str, float]], hrp="tsp") -> List[Tuple[str, float]]:

    G = ECKey().set(1).get_pubkey()
    negated_keys = []
    for key, is_xonly in input_priv_keys:
        if is_xonly and key.get_pubkey().get_y()%2 != 0:
            key.negate()
        negated_keys.append(key)

    a_sum = sum(negated_keys)
    silent_payment_groups: Dict[ECPubKey, List[Tuple[ECPubKey, float]]] = {}
    for recipient in recipients:
        addr, amount = recipient
        B_scan, B_m = decode_silent_payment_address(addr, hrp=hrp)
        if B_scan in silent_payment_groups:
            silent_payment_groups[B_scan].append((B_m, amount))
        else:
            silent_payment_groups[B_scan] = [(B_m, amount)]

    outputs = []
    for B_scan, B_m_values in silent_payment_groups.items():
        n = 0
        ecdh_shared_secret = outpoints_hash * a_sum * B_scan

        # Sort B_m_values by amount to ensure determinism in the tests
        # Note: the receiver can find the outputs regardless of the ordering, this
        # sorting step is only for testing
        B_m_values.sort(key=lambda x: x[1])
        for B_m, amount in B_m_values:
            t_n = sha256(ecdh_shared_secret.get_bytes(False) + ser_uint32(n))
            P_nm = B_m + t_n*G
            outputs.append((P_nm.get_bytes().hex(), amount))
            n += 1
    return outputs


def scanning(b_scan: ECKey, B_spend: ECPubKey, A_sum: ECPubKey, outpoints_hash: bytes, outputs_to_check: List[ECPubKey], labels: Dict[str, str] = None) -> List[Dict[str, str]]:

    G = ECKey().set(1).get_pubkey()
    ecdh_shared_secret = outpoints_hash * b_scan * A_sum
    n = 0
    keep_scanning = True
    wallet = []
    while True:
        t_n = sha256(ecdh_shared_secret.get_bytes(False) + ser_uint32(n))
        P_n = B_spend + t_n*G
        for output in outputs_to_check:
            if P_n == output:
                wallet.append({"pub_key": P_n.get_bytes().hex(), "priv_key_tweak": t_n.hex()})
                outputs_to_check.remove(output)
                n += 1
                break
            elif labels:
                m_G_sub = output - P_n
                found = False
                if (m_G_sub.get_bytes(False).hex() in labels):
                    P_nm = P_n + m_G_sub
                    m_G = m_G_sub
                    found = True
                else:
                    output.negate()
                    m_G_sub = output - P_n
                    if (m_G_sub.get_bytes(False).hex() in labels):
                        P_nm = P_n + m_G_sub
                        m_G = m_G_sub
                        found = True
                if found:
                    wallet.append({
                        "pub_key": P_nm.get_bytes().hex(),
                        "priv_key_tweak": (ECKey().set(t_n).add(bytes.fromhex(labels[m_G.get_bytes(False).hex()]))).get_bytes().hex()
                    })
                    outputs_to_check.remove(output)
                    n += 1
                    break
        else:
            break
    return wallet


if __name__ == "__main__":

    with open(argv[1], "r") as f:
        test_data = json.loads(f.read())

    for case in test_data:
        print(case["comment"])
        # Test sending
        for sending_test in case["sending"]:

            given = sending_test["given"]
            expected = sending_test["expected"]
            input_priv_keys = [(ECKey().set(bytes.fromhex(key)), is_xonly) for key, is_xonly in given["input_priv_keys"]]
            outpoints_hash = hash_outpoints(given["outpoints"])
            # Conver the tuples to lists so they can be easily compared to the json list of lists from the given test vectors
            sending_outputs = [list(t) for t in create_outputs(input_priv_keys, outpoints_hash, given["recipients"], hrp="sp")]
            # Check that for a given set of inputs, we were able to generate the expected outputs for the receiver

            sending_outputs.sort(key=lambda x: x[1])
            assert sending_outputs == expected["outputs"], "Sending test failed"

        # Test receiving
        msg = sha256(b'message')
        aux = sha256(b'random auxiliary data')
        for receiving_test in case["receiving"]:
            given = receiving_test["given"]
            expected = receiving_test["expected"]
            outputs_to_check = [ECPubKey().set(bytes.fromhex(p)) for p in given["outputs"]]

            # Check that the given inputs for the receiving test match what was generated during the sending test
            receiving_addresses = []
            b_scan, b_spend, B_scan, B_spend = derive_silent_payment_key_pair(bytes.fromhex(given["bip32_seed"]))
            receiving_addresses.append(encode_silent_payment_address(B_scan, B_spend, hrp="sp"))
            if given["labels"]:
                for _, v in given["labels"].items():
                    receiving_addresses.append(create_labeled_silent_payment_address(B_scan, B_spend, m=bytes.fromhex(v), hrp="sp"))

            # Check that the silent payment addresses match for the given BIP32 seed and labels dictionary
            assert receiving_addresses == expected["addresses"], "Receiving addresses don't match"

            outpoints_hash = hash_outpoints(given["outpoints"])
            input_pub_keys = [ECPubKey().set(bytes.fromhex(key)) for key in given["input_pub_keys"]]
            A_sum = sum(input_pub_keys)
            add_to_wallet = scanning(
                    b_scan=b_scan,
                    B_spend=B_spend,
                    A_sum=A_sum,
                    outpoints_hash=outpoints_hash,
                    outputs_to_check=outputs_to_check,
                    labels=given["labels"],
                    )

            # Check that the private key is correct for the found output public key
            for output in add_to_wallet:
                pub_key = ECPubKey().set(bytes.fromhex(output['pub_key']))
                full_private_key = b_spend.add(bytes.fromhex(output['priv_key_tweak']))
                if full_private_key.get_pubkey().get_y()%2 != 0:
                    full_private_key.negate()

                sig = full_private_key.sign_schnorr(msg, aux)
                assert pub_key.verify_schnorr(sig, msg), f"Invalid signature for {pub_key}"
                output["signature"] = sig.hex()

            # Check if the found output public keys match the expected output public keys
            assert add_to_wallet == expected["outputs"], "Receiving test failed"

    print("All tests passed")
