import { fromHex, PrivateKey } from '@rigidity/bls-signatures';
import { formatHex, FullNode } from '@rigidity/chia';
import { mnemonicToSeedSync } from 'bip39';
import dotenv from 'dotenv';
import os from 'os';
import path from 'path';
import { CAT } from './puzzles/CAT';
import { Wallet } from './puzzles/Wallet';

dotenv.config();

const mnemonic = process.env.MNEMONIC_PHRASE;
if (!mnemonic) throw new Error('Missing MNEMONIC_PHRASE in PATH.');

const seed = mnemonicToSeedSync(mnemonic);
const masterPrivateKey = PrivateKey.fromSeed(seed);
const masterPublicKey = masterPrivateKey.getG1();

const assetId = fromHex(
    '1abe38c422fd3325d3f827b5fd9dfea46723d2aa46fd344e0e931f7b76b16ad2'
);

const node = new FullNode(path.join(os.homedir(), '.chia', 'mainnet'));

async function main() {
    for (let i = 0; i < 50; i++) {
        const wallet = new Wallet(Wallet.derivePublicKey(masterPublicKey, i), {
            hardened: false,
            index: i,
        });
        const cat = new CAT(assetId, wallet);
        const puzzleHash = formatHex(cat.hashHex());
        const result = await node.getCoinRecordsByPuzzleHash(
            puzzleHash,
            undefined,
            undefined,
            true
        );
        if (result.success) console.log(result.coin_records.length);
    }
}

main();
