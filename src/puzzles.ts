import { Program } from '@rigidity/clvm';
import fs from 'fs';
import path from 'path';

function puzzle(file: string): Program {
    return Program.deserializeHex(
        fs.readFileSync(path.join(__dirname, '..', 'puzzles', file), 'utf-8')
    );
}

export const puzzles = {
    cat: puzzle('cat.clvm.hex'),
    lockInner: puzzle('lock.inner.puzzle.clvm.hex'),
    wallet: puzzle('p2_delegated_puzzle_or_hidden_puzzle.clvm.hex'),
    syntheticPublicKey: puzzle('calculate_synthetic_public_key.clvm.hex'),
    payToConditions: puzzle('p2_conditions.clvm.hex'),
    genesisById: puzzle('genesis_by_coin_id.clvm.hex'),
    genesisByPuzzleHash: puzzle('genesis_by_puzzle_hash.clvm.hex'),
    everythingWithSignature: puzzle('everything_with_signature.clvm.hex'),
    delegatedTail: puzzle('delegated_tail.clvm.hex'),
    defaultHidden: Program.deserializeHex('ff0980'),
};
