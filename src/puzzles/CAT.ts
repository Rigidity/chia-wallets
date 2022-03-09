import { Program } from '@rigidity/clvm';
import { puzzles } from '../puzzles';

export class CAT extends Program {
    constructor(tailPuzzleHash: Uint8Array, innerPuzzle: Program) {
        super(
            puzzles.cat.curry([
                Program.fromBytes(puzzles.cat.hash()),
                Program.fromBytes(tailPuzzleHash),
                innerPuzzle,
            ]).value
        );
    }
}
