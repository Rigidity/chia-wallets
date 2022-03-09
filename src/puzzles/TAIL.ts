import { JacobianPoint } from '@rigidity/bls-signatures';
import { Program } from '@rigidity/clvm';
import { puzzles } from '../puzzles';

export class TAIL extends Program {}

export class GenesisById extends TAIL {
    constructor(coinId: Uint8Array) {
        super(puzzles.genesisById.curry([Program.fromBytes(coinId)]).value);
    }
}

export class GenesisByPuzzleHash extends TAIL {
    constructor(puzzleHash: Uint8Array) {
        super(
            puzzles.genesisByPuzzleHash.curry([Program.fromBytes(puzzleHash)])
                .value
        );
    }
}

export class EverythingWithSignature extends TAIL {
    constructor(publicKey: JacobianPoint) {
        super(
            puzzles.everythingWithSignature.curry([
                Program.fromBytes(publicKey.toBytes()),
            ]).value
        );
    }
}

export class DelegatedTail extends TAIL {
    constructor(publicKey: JacobianPoint) {
        super(
            puzzles.everythingWithSignature.curry([
                Program.fromBytes(publicKey.toBytes()),
            ]).value
        );
    }
}
