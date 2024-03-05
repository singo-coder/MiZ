#!/usr/bin/env python
# Copyright 2021 Mattia Giambirtone & All Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
A simple, decently written and modern Python 3.8+ tool to
ease the altering of balance with MiZip Mifare tags. It can
generate keys for decryption of sectors as well as automate
the generation of block 0/1 of sector 2 to alter a tag's balance. If you
know what you're doing, you can even use this tool to transform any Mifare
1K/4K tag (and probably others using the same scheme) into a "MiZip-compatible"
tag recognizable by vending machines
"""
from re import match
from time import strftime
from random import randint
from sys import exit, stdout
from typing import List, TextIO
from os.path import exists, isfile
from argparse import ArgumentParser, Namespace


__version__ = (0, 0, 1)

# These handy constants, as well as the algorithm, come from https://gist.github.com/y0no/70565a8d09203122181f3b3a08bffcbd#file-mizip_calc-py,
# which in turn got them from https://github.com/iceman1001/proxmark3/blob/master/client/scripts/calc_mizip.lua whose author states that they
# did not find out this algorithm (and probably the constants as well?) on their own. I guess it's stealing all the way down!
# This is a 6-byte big-endian XOR table, if you're wondering
XORTABLE = (
    (0x09125a2589e5, 0xF12C8453D821),
    (0xAB75C937922F, 0x73E799FE3241),
    (0xE27241AF2C09, 0xAA4D137656AE),
    (0x317AB72F4490, 0xB01327272DFD),
)
# These tell calc_sector_key which byte of the UID are
# XORed with which byte of the XOR offset in the
# table above to generate either an A or a B key
KEY_IDX = {
           'A': (0, 1, 2, 3, 0, 1),
           'B': (2, 3, 0, 1, 2, 3)
          }
# Sector 0 uses constant hardcoded keys, and so do we
SECTOR_0_KEYS = ("a0a1a2a3a4a5", "b4c132439eef")
# If you wanna restore any Mifare tag to a blank state
# (as if it was a freshly created MiZip), this is the 
# dump you want
BLANK_DUMP = [
              [
                "D209AB0F7F890400C802002000000018",
                "6200488849884A884B88000000000000",
                "00000000000000000000000000000000",
                "A0A1A2A3A4A5787788C1B4C132439EEF",
              ],
              [
                "01000001000080010001000000008000",
                "01000001000080010001000000008001",
                "55010000000000000000000000000000",
                "DB1BF12A5BEC7877882F5A23565A732E"
              ],
              [
                "00000000000000000000000000000000",
                "00000000000000000000000000000001",
                "55010000000000000000000000000000",
                "797C6238402678778812D8E84BF7994E"
              ],
              [
                "00000000000000000000000000000000",
                "00000000000000000000000000000001",
                "55010000000000000000000000000000",
                "------------787788000142C17FFDA1"
              ],
              [
                "00000000000000000000000000000000",
                "00000000000000000000000000000001",
                "55010000000000000000000000000000",
                "E3731C209699787788001B1CF52E86F2"
              ]
]


def calc_sector_key(uid: bytes, xor: bytes, kind: str) -> str:
    """
    Calculates the encryption key (either A or B),
    for a given entry in the XOR table. Raises a 
    ValueError exception if the given key type is
    not valid
    """

    if (idx := KEY_IDX.get(kind)) is None:
        raise ValueError(f"invalid key type: {kind!r}")
    return "".join([f'{uid[j] ^ xor[i]:02x}' for i, j in enumerate(idx)])


def calc_balance_block(original: str, balance: float) -> str:
    """
    Calculates a replacement block for block 0 or 1 in sector
    2 by using the original block and generates a replacement
    with the desired new balance. Some amount of validation is
    performed on the input, the intermediate results, as well as
    the output: those can be turned off by enabling the highest
    level of optimizations when calling python, but this is
    not recommended.
    
    Note: This function expects that the needed validation to tell
    which block (either 0 or 1) of sector 2 of the tag contains the
    balance has been performed and therefore considers the first
    parameter to be the block containing the balance
    """
    
    # TL;DR: In a MiZip Mifare tag, the balance is encoded in sector 2. 
    # Specifically it's located either in block 1 or 0, depending on the value 
    # of the first byte of block 2 (55 = block 1, AA = block 0). This can be
    # checked by looking at the second byte of block 2, which should mirror
    # the last byte of the block containing the balance (this pattern appears to be
    # a generic checksum applied to all sectors, except for the first block).
    # Once we nail down which block contains what we want, we take the first four bytes
    # which encode the balance (in cents, so 1 euro = 100 cents) in hexadecimal
    # using the little endian byte order and the next byte is a checksum computed by XORing
    # the first half of the preceding 4 bytes with the second half. The rest of the block is unused for balance purposes
    # and contains an operation counter and other things we don't care about
    assert len(original) == 32, "The block size must be 32 characters"
    try:
        balance = int(balance * 100).to_bytes(2, "little")
    except OverflowError:
        raise ValueError("Could not encode balance (value is too high, don't be greedy!)")
    assert len(balance) == 2, f"Expecting the length of encoded balance to be 2, found {len(balance)} instead ({balance.hex()})"
    check = hex(balance[0] ^ balance[1]).strip("0x").zfill(2)  # No need for explicit conversion to bytes (each byte in a bytes object is automatically an integer)
    new_block = f"{balance.hex().zfill(6)}{check}{original[8:]}".upper()
    assert len(new_block) == 32, f"The new block size is != 32 ({len(new_block)}): Balance too high?"
    return new_block


def calc_uid(new_uid: str) -> str:
    """
    Calculates a new UID-BCC pair from
    a given UID (without a BCC, assuming
    this is a made-up user-provided value)
    """
    
    assert len(new_uid) == 8, "The new UID must be 8 characters long and in hexadecimal format!"
    # The uid is in big endian format!
    try:
        new_uid = int(new_uid, base=16).to_bytes(4, "big")
    except OverflowError:
        raise ValueError(f"Could not encode {new_uid} into 4 bytes, maybe dump file is corrupted?")
    # The Block Check is composed of subsequent XORs of the UID's bytes
    bcc = new_uid[0] ^ new_uid[1]
    for i in range(2, 4):
        bcc ^= new_uid[i]
    return (new_uid + bcc.to_bytes(1, "little")).hex().upper()


def parse_dump(file: str, check_blocks: bool = True, check_bcc: bool = True) -> List[List[str]]:
    """
    Parses a given .mct file as produced by Mifare Classic
    Tool. Note that this function makes no assumption about
    the number of sectors or blocks and will happily parse a
    2000-block sector (which is probably not gonna fit anywhere).
    Returns a list of lists where each list is a sector and each
    element in a sublist is a block (in hexadecimal). Raises a
    ValueError exception if the given file does not exist or upon
    a parsing error. The file path is used as-is and is passed directly
    to Python's builtin open()  function. If check_blocks equals True,
    which is the default, this function checks the block checksums for
    each sector starting from 1
    """

    if not exists(file):
        raise ValueError(f"error while reading {file!r}: path does not exist")
    elif not isfile(file):
        raise ValueError(f"error while reading {file!r}: path does not point to a file")
    result = []
    sector = 0
    line = 0
    with open(file) as fp:
        contents = fp.readlines()
        while contents:
            line += 1
            section = contents.pop(0)
            if section.startswith("#"):
                continue  # Comments on their own line
            elif m := match(r"\+Sector: ([0-9]+)", section):
                sector = int(m.group(1))
                if len(result) == sector:
                    # New sector!
                    result.append([])
                else:
                    raise ValueError(f"error while parsing {file!r} at line {line}: expecting sector {len(result)}, got {sector} instead (skipped a sector?)")
            elif m := match(r"^([a-zA-z0-9\-]+)$", section):
                if len(m.group(1)) != 32:
                    raise ValueError(f"error while parsing {file!r} at line {line}: invalid block length (expecting 32, found {len(m.group(1))} instead)")
                result[sector].append(m.group(1))
            else:
                raise ValueError(f"error while parsing {file!r} at line {line}: invalid data in dump file")
    if check_bcc and result[0][0][:10] != calc_uid(result[0][0][:8]):
        raise ValueError(f"BCC mismatch: expected {calc_uid(result[0][0][:8])}, found {result[0][0][:10]} instead")
    if check_blocks:
        # This is where we check the sector checksums
        for i, sector in enumerate(result[1:]):   # Sector 1 is different so we skip it
            if len(sector) < 2:
                raise ValueError(f"Error when validating {file!r} at sector {i + 1}: too few blocks (expecting >= 2, found {len(sector)} instead)")
            if (sector[2][:2] == "55" and sector[1][-2:] == sector[2][2:4]) or (sector[2][:2] == "AA" and sector[0][-2:] == sector[2][2:4]):
                # Checksum is valid!
                continue
            else:
                raise ValueError(f"Error when validating {file!r} at sector {i + 1}: sector check mismatch or invalid block 2")
    return result


def write_dump(dump: List[List[str]], file: TextIO):
    """
    Writes the given dump to the given file
    """

    for i, sector in enumerate(dump):
        print(f"+Sector: {i}", file=file)
        for block in sector:
            print(block, file=file)


def write_keys(uid: str, file: TextIO):
    """
    Writes the keys for a given UID to the given file
    """

    print(f"# Generated with mizip_util by @nocturn9x for tag with UID {uid} on {strftime('%d/%m/%Y %H:%M:%S %p')}", file=file)
    print(f"# A\n{SECTOR_0_KEYS[0]}", file=file)
    try:
        uid = int(uid, base=16).to_bytes(4, "big")
    except OverflowError:
        raise ValueError(f"Could not encode {uid} into 4 bytes, maybe dump file is corrupted?")
    for xorKey, _ in XORTABLE:   # We first print all the A keys, then all the B keys, as this is the format MCT expects
        print(f"{calc_sector_key(uid, xorKey.to_bytes(6, 'big'), 'A')}", file=file)
    print(f"# B\n{SECTOR_0_KEYS[1]}", file=file)
    for _, xorKey in XORTABLE:
        print(f"{calc_sector_key(uid, xorKey.to_bytes(6, 'big'), 'B')}", file=file)


def main(arguments: Namespace):
    """
    Main program entry point
    """

    print(f"MiZip Utility version {'.'.join(map(str, __version__))}, made by @nocturn9x with love and Python 3.8\n")
    if arguments.dump_only and arguments.keys_only:
        print("--dump-only and --keys-only cannot be used together")
        exit(1)
    if arguments.dump_only and arguments.dump_keys:
        print("--dump-keys and --dump-only cannot be used together")
        exit(1)
    if not arguments.uid and not arguments.dump and not arguments.blank:
        print("You must provide either an explicit tag UID, a dump file with --dump, or use --blank!")
        exit(1)
    if arguments.set_uid and arguments.gen_uid:
        print("--set-uid and --gen-uid cannot be used together")
        exit(1)
    try:
        if arguments.blank and not arguments.uid:
            uid = "D209AB0F"
        elif arguments.dump and not arguments.uid:
            uid = parse_dump(arguments.dump, check_blocks=not arguments.skip_checksum, check_bcc=not arguments.skip_bcc)[0][0][:8]
            print(f"Obtained UID {uid} from {arguments.dump!r}")
        elif len(arguments.uid) != 8:
            print("The provided UID is invalid! It must be of the form XXXXXXXX")
            exit(1)
        else:
            try:
                uid = bytes.fromhex(arguments.uid)
            except ValueError:
                print("The provided UID is invalid! Make sure it doesn't contain spurious characters such as ':' or '-'")
                exit(1)
        uid = arguments.uid or uid
        if arguments.set_uid:
            new_uid = uid = arguments.set_uid.upper()
        elif arguments.gen_uid:
            new_uid = uid = randint(0, 4294967295).to_bytes(4, "big").hex().upper()
        else:
            new_uid = uid.upper()
        if arguments.dump_keys:
            print(f"Writing A/B keys for MiZip Mifare tag with UID {uid} to {arguments.dump_keys!r}")
            with open(arguments.dump_keys, "w") as keys:
                write_keys(uid, keys)
        elif not arguments.dump_only:
            write_keys(uid, stdout)
        if not arguments.keys_only or arguments.dump_only and not arguments.blank:
            if not arguments.dump and not arguments.blank:
                print("You must provide the original dump of your MiZip tag to alter the balance!")
                quit(1)
            print(f"Generating new dump with updated balance of {arguments.balance:.2f} euros ({int(arguments.balance) * 100} cents)")
            if not arguments.blank:
                dump = parse_dump(arguments.dump, check_blocks=not arguments.skip_checksum, check_bcc=not arguments.skip_bcc)
            else:
                print("Using blank (aka 'virgin') dump")
                dump = BLANK_DUMP
            if dump[2][2][:2] == "55":
                print(f"Detected balance block is 1")
                balance_block = (2, 1)
            elif dump[2][2][:2] == "AA":
                print("Detected balance block is 0")
                balance_block = (2, 0)
            elif arguments.balance_block == -1:
                print("Could not determine the block containing the balance! Pass it explicitly with --balance-block n")
                quit(1)
            else:
                print(f"Could not detect balance block, defaulting to {arguments.balance_block}")
                balance_block = (2, arguments.balance_block)
            # We replace the block containing the original balance with a new one with a different balance
            dump[balance_block[0]][balance_block[1]] = calc_balance_block(dump[balance_block[0]][balance_block[1]], arguments.balance)
            if arguments.set_uid:
                print(f"Updating UID from {uid} to {arguments.set_uid}")
                oem_info = dump[0][0][10:]
                new_uid = calc_uid(new_uid)
                print(f"Calculated BCC is {new_uid[8:]}")
                dump[0][0] = f"{new_uid}{oem_info}".upper()
            elif arguments.gen_uid:
                print(f"Updating UID from {uid} to a randomly-generated one ({new_uid.upper()})")
                oem_info = dump[0][0][10:]
                new_uid = calc_uid(new_uid)
                print(f"Calculated BCC is {new_uid[8:]}")
                dump[0][0] = f"{new_uid}{oem_info}"
                uid = new_uid
            print("Updating keys")
            # We set the new keys for the updated dump file
            dump[0][3] = f"{SECTOR_0_KEYS[0]}{dump[0][3][12:20]}{SECTOR_0_KEYS[1]}".upper()
            for i, (xorA, xorB) in enumerate(XORTABLE):
                keyA = calc_sector_key(bytes.fromhex(uid), xorA.to_bytes(6, 'big'), 'A')
                keyB = calc_sector_key(bytes.fromhex(uid), xorB.to_bytes(6, 'big'), 'B')
                dump[i + 1][3] = f"{keyA}{dump[i + 1][3][12:20]}{keyB}".upper()
            if arguments.dump_output:
                print(f"Writing new dump to {arguments.dump_output!r}")
                with open(arguments.dump_output, "w") as output:
                    write_dump(dump, output)
            else:
                write_dump(dump, stdout)
    except Exception as error:
        print(f"An error occurred while working -> {type(error).__name__}: {error}")
    else:
        print(f"Done!")


if __name__ == '__main__':
    parser = ArgumentParser(prog="mizip_util", description="A simple tool to ease the altering of balance with MiZip Mifare tags. It can generate keys"
                            " for decryption of sectors using Mifare Classic Tool as well modified dumps to alter a tag's balance")
    parser.add_argument("--uid", "-u", help="The UID of the tag (use any NFC reader app to find that out), for example 1123FD4E. This overrides the one read from the dump file",
                        required=False)
    parser.add_argument("--keys-only", help="Only generate the decryption keys for the tag (use in the Mifare Classic Tool app). Useful if you do not have a dump file yet",
                        action="store_true", default=False)
    parser.add_argument("--dump-keys", "-k", help="Writes the keys to the given file. Note: The file is created if it does not exist and overwritten if it does!")
    parser.add_argument("--balance", "-b", help="Generates a new dump with the balance set to the this value (floating point, in euros), defaults to 0.0",
                        default=0.0, type=float)
    parser.add_argument("--dump", "-d", help="The path to an .mct dump of the sectors of the MiZip tag (create it via the Mifare Classic Tool app)")
    parser.add_argument("--dump-only", help="Only generate an updated dump file and skip key generation. Cannot be used with --keys-only", action="store_true")
    parser.add_argument("--dump-output", "-o", help="Writes the newly generated dump to the given file. Note: The file is created if it does not exist and overwritten if it does!")
    parser.add_argument("--skip-checksum", help="Skip checking the block-wise checksum in each sector starting from 1. Recommended if you're using an old dump from a non-mizip tag",
                        action="store_true")
    parser.add_argument("--set-uid", help="Use the provided UID (in hex) in the new dump file. This will also generate the correct BCC checksum, but note that it will only affect the tag if block 0 in sector 0 is writable", default="")
    parser.add_argument("--gen-uid", help="Similar to --set-uid, but it generates a random UID instead. Cannot be used together with --set-uid", action="store_true")
    parser.add_argument("--skip-bcc", help="Skip checking the BCC derived from the tag's UID (not recommended)", action="store_true")
    parser.add_argument("--blank", help="Instructs mizip_util to use a blank MiZip dump as a starting point for the modified one. Overrides whatever is passed to --dump",
                        action="store_true")
    parser.add_argument("--balance-block", help="Uses this block from sector 2 of the tag to encode the balance (can either be 0 or 1). Only used if the balance block cannot be determinated automatically",
                        type=int, choices=(0, 1), default=-1)
    main(parser.parse_args()) 
