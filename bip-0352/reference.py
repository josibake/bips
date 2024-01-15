#!/usr/bin/env python3

import hashlib
import json
import bip32  # type: ignore
from typing import List, Tuple, Dict, Union, cast
from sys import argv
from functools import reduce

# local files
from bech32m import convertbits, bech32_encode, decode, Encoding
from secp256k1 import ECKey, ECPubKey


def sha256(s: Union[bytes, bytearray]) -> bytes:
    return hashlib.sha256(s).digest()


def hash160(s: Union[bytes, bytearray]) -> bytes:
    return hashlib.new("ripemd160", sha256(s)).digest()


def is_p2tr(spk: bytes) -> bool:
    if len(spk) != 34:
        return False
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (spk[0] == 0x51) & (spk[1] == 0x20)


def is_p2wpkh(spk: bytes) -> bool:
    if len(spk) != 22:
        return False
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (spk[0] == 0x00) & (spk[1] == 0x14)


def is_p2sh(spk: bytes) -> bool:
    if len(spk) != 23:
        return False
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (spk[0] == 0xA9) & (spk[1] == 0x14) & (spk[-1] == 0x87)


def is_p2pkh(spk: bytes) -> bool:
    if len(spk) != 25:
        return False
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (spk[0] == 0x76) & (spk[1] == 0xA9) & (spk[2] == 0x14) & (spk[-2] == 0x88) & (spk[-1] == 0xAC)


def get_pubkey_from_input(input) -> ECPubKey:
    spk = bytes.fromhex(input["scriptPubKey"])
    if is_p2pkh(spk):
        spk_pkh = spk[3:3 + 20]
        script_sig = bytes.fromhex(input["prevout"][2])
        for i in range(len(script_sig), 0, -1):
            if i - 33 >= 0:
                pk = script_sig[i - 33:i]
                pkh = hash160(pk)
                if pkh == spk_pkh:
                    return ECPubKey().set(pk)
        # should never happen, as this would be an invalid spend
        return ECPubKey()
    if is_p2sh(spk):
        redeem_script = bytes.fromhex(input["prevout"][2])[1:]
        if is_p2wpkh(redeem_script):
            return ECPubKey().set(redeem_script[-33:])
    if is_p2wpkh(spk):
        # the witness must contain two items and the second item is the pubkey
        return ECPubKey().set(bytes.fromhex(input["prevout"][3])[-33:])
    if is_p2tr(spk):
        return ECPubKey().set(spk[2:])
    return ECPubKey()


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, "big")


def get_input_nonce(outpoints: List[Tuple[str, int]], sum_input_pubkeys: ECPubKey) -> bytes:
    lowest_outpoint = sorted([
        bytearray.fromhex(txid)[::-1] + n.to_bytes(4, "little")
        for txid, n in outpoints
    ])[0]

    s = hashlib.new("sha256")
    s.update(lowest_outpoint)
    s.update(sum_input_pubkeys.get_bytes(False))

    return s.digest()


def derive_silent_payment_key_pair(seed: bytes) -> Tuple[ECKey, ECKey, ECPubKey, ECPubKey]:
    SCAN_KEY = "m/352h/0h/0h/1h/0"
    SPEND_KEY = "m/352h/0h/0h/0h/0"

    master = bip32.BIP32.from_seed(seed)
    scan = ECKey().set(master.get_privkey_from_path(SCAN_KEY))
    spend = ECKey().set(master.get_privkey_from_path(SPEND_KEY))
    Scan = scan.get_pubkey()
    Spend = spend.get_pubkey()

    return scan, spend, Scan, Spend


def encode_silent_payment_address(B_scan: ECPubKey, B_m: ECPubKey, hrp: str = "tsp", version: int = 0) -> str:
    data = convertbits(B_scan.get_bytes(False) + B_m.get_bytes(False), 8, 5)
    return bech32_encode(hrp, [version] + data, Encoding.BECH32M)


def generate_label(b_scan: ECKey, m: int) -> bytes:
    return sha256(b_scan.get_bytes() + ser_uint32(m))


def create_labeled_silent_payment_address(b_scan: ECKey, B_spend: ECPubKey, m: int, hrp: str = "tsp", version: int = 0) -> str:
    G = ECKey().set(1).get_pubkey()
    B_scan = b_scan.get_pubkey()
    B_m = B_spend + generate_label(b_scan, m) * G
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)

    return labeled_address


def decode_silent_payment_address(address: str, hrp: str = "tsp") -> Tuple[ECPubKey, ECPubKey]:
    version, data = decode(hrp, address)
    B_scan = ECPubKey().set(data[:33])
    B_spend = ECPubKey().set(data[33:])

    return B_scan, B_spend


def create_outputs(input_priv_keys: List[Tuple[ECKey, bool]], input_nonce: bytes, recipients: List[Tuple[str, float]], hrp="tsp") -> List[Tuple[str, float]]:
    G = ECKey().set(1).get_pubkey()
    negated_keys = []
    for key, is_xonly in input_priv_keys:
        k = ECKey().set(key.get_bytes())
        if is_xonly and k.get_pubkey().get_y() % 2 != 0:
            k.negate()
        negated_keys.append(k)

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
        k = 0
        ecdh_shared_secret = input_nonce * a_sum * B_scan

        # Sort B_m_values by amount to ensure determinism in the tests
        # Note: the receiver can find the outputs regardless of the ordering, this
        # sorting step is only for testing
        B_m_values.sort(key=lambda x: x[1])
        for B_m, amount in B_m_values:
            t_k = sha256(ecdh_shared_secret.get_bytes(False) + ser_uint32(k))
            P_km = B_m + t_k * G
            outputs.append((P_km.get_bytes().hex(), amount))
            k += 1
    return outputs


def scanning(b_scan: ECKey, B_spend: ECPubKey, A_sum: ECPubKey, input_nonce: bytes, outputs_to_check: List[ECPubKey], labels: Dict[str, str] = {}) -> List[Dict[str, str]]:
    G = ECKey().set(1).get_pubkey()
    ecdh_shared_secret = input_nonce * b_scan * A_sum
    k = 0
    wallet = []
    while True:
        t_k = sha256(ecdh_shared_secret.get_bytes(False) + ser_uint32(k))
        P_k = B_spend + t_k * G
        for output in outputs_to_check:
            if P_k == output:
                wallet.append({"pub_key": P_k.get_bytes().hex(), "priv_key_tweak": t_k.hex()})
                outputs_to_check.remove(output)
                k += 1
                break
            elif labels:
                m_G_sub = output - P_k
                if m_G_sub.get_bytes(False).hex() in labels:
                    P_km = P_k + m_G_sub
                    wallet.append({
                        "pub_key": P_km.get_bytes().hex(),
                        "priv_key_tweak": (ECKey().set(t_k).add(
                            bytes.fromhex(labels[m_G_sub.get_bytes(False).hex()])
                        )).get_bytes().hex(),
                    })
                    outputs_to_check.remove(output)
                    k += 1
                else:
                    output.negate()
                    m_G_sub = output - P_k
                    if m_G_sub.get_bytes(False).hex() in labels:
                        P_km = P_k + m_G_sub
                        wallet.append({
                            "pub_key": P_km.get_bytes().hex(),
                            "priv_key_tweak": (ECKey().set(t_k).add(
                                bytes.fromhex(labels[m_G_sub.get_bytes(False).hex()])
                            )).get_bytes().hex(),
                        })
                        outputs_to_check.remove(output)
                        k += 1
                        break
        else:
            break
    return wallet


if __name__ == "__main__":
    with open(argv[1], "r") as f:
        test_data = json.loads(f.read())

    # G , needed for generating the labels "database"
    G = ECKey().set(1).get_pubkey()
    for case in test_data:
        print(case["comment"])
        # Test sending
        for sending_test in case["sending"]:
            given = sending_test["given"]
            expected = sending_test["expected"]

            outpoints = [(input["prevout"][0], input["prevout"][1]) for input in given["inputs"]]
            # Conver the tuples to lists so they can be easily compared to the json list of lists from the given test vectors
            input_priv_keys = []
            input_pub_keys = []
            for input in given["inputs"]:
                pubkey = get_pubkey_from_input(input)
                if not pubkey.valid:
                    continue
                input_priv_keys.append((
                    ECKey().set(bytes.fromhex(input["private_key"])),
                    is_p2tr(bytes.fromhex(input["scriptPubKey"])),
                ))
                input_pub_keys.append(pubkey)
            A_sum = reduce(lambda x, y: x + y, input_pub_keys)
            input_nonce = get_input_nonce(outpoints, A_sum)
            sending_outputs = [
                list(t)
                for t in create_outputs(input_priv_keys, input_nonce, given["recipients"], hrp="sp")
            ]
            # Check that for a given set of inputs, we were able to generate the expected outputs for the receiver
            sending_outputs.sort(key=lambda x: cast(float, x[1]))
            assert sending_outputs == expected["outputs"], "Sending test failed"

        # Test receiving
        msg = sha256(b"message")
        aux = sha256(b"random auxiliary data")
        for receiving_test in case["receiving"]:
            given = receiving_test["given"]
            expected = receiving_test["expected"]
            outputs_to_check = [
                ECPubKey().set(bytes.fromhex(p)) for p in given["outputs"]
            ]
            outpoints = [
                (input["prevout"][0], input["prevout"][1]) for input in given["inputs"]
            ]

            # Check that the given inputs for the receiving test match what was generated during the sending test
            receiving_addresses = []
            b_scan = ECKey().set(bytes.fromhex(given["key_material"]["scan_priv_key"]))
            b_spend = ECKey().set(
                bytes.fromhex(given["key_material"]["spend_priv_key"])
            )
            B_scan = b_scan.get_pubkey()
            B_spend = b_spend.get_pubkey()
            receiving_addresses.append(
                encode_silent_payment_address(B_scan, B_spend, hrp="sp")
            )
            if given["labels"]:
                for label in given["labels"]:
                    receiving_addresses.append(
                        create_labeled_silent_payment_address(
                            b_scan, B_spend, m=label, hrp="sp"
                        )
                    )

            # Check that the silent payment addresses match for the given BIP32 seed and labels dictionary
            assert (receiving_addresses == expected["addresses"]), "Receiving addresses don't match"
            input_pub_keys = []
            for input in given["inputs"]:
                pubkey = get_pubkey_from_input(input)
                if not pubkey.valid:
                    continue
                input_pub_keys.append(pubkey)
            A_sum = reduce(lambda x, y: x + y, input_pub_keys)
            input_nonce = get_input_nonce(outpoints, A_sum)
            pre_computed_labels = {
                (generate_label(b_scan, label) * G).get_bytes(False).hex(): generate_label(b_scan, label).hex()
                for label in given["labels"]
            }
            add_to_wallet = scanning(
                b_scan=b_scan,
                B_spend=B_spend,
                A_sum=A_sum,
                input_nonce=input_nonce,
                outputs_to_check=outputs_to_check,
                labels=pre_computed_labels,
            )

            # Check that the private key is correct for the found output public key
            for output in add_to_wallet:
                pub_key = ECPubKey().set(bytes.fromhex(output["pub_key"]))
                full_private_key = b_spend.add(bytes.fromhex(output["priv_key_tweak"]))
                if full_private_key.get_pubkey().get_y() % 2 != 0:
                    full_private_key.negate()

                sig = full_private_key.sign_schnorr(msg, aux)
                assert pub_key.verify_schnorr(sig, msg), f"Invalid signature for {pub_key}"
                output["signature"] = sig.hex()

            # Check if the found output public keys match the expected output public keys
            assert add_to_wallet == expected["outputs"], "Receiving test failed"

    print("All tests passed")
