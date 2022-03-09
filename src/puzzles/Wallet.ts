import {
    AugSchemeMPL,
    bigIntToBytes,
    bytesToBigInt,
    concatBytes,
    encodeInt,
    fromHex,
    hash256,
    JacobianPoint,
    PrivateKey,
} from '@rigidity/bls-signatures';
import { CoinSpend, sanitizeHex } from '@rigidity/chia';
import { Program } from '@rigidity/clvm';
import { puzzles } from '../puzzles';

const defaultHiddenPuzzleHash = puzzles.defaultHidden.hash();

const groupOrder =
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

export interface Derivation {
    readonly hardened: boolean;
    readonly index: number;
}

export class Wallet extends Program {
    public readonly publicKey: JacobianPoint;
    public readonly derivation: Derivation;

    constructor(publicKey: JacobianPoint, derivation: Derivation) {
        super(
            puzzles.wallet.curry([
                Program.fromBytes(
                    Wallet.syntheticPublicKey(
                        publicKey,
                        defaultHiddenPuzzleHash
                    ).toBytes()
                ),
            ]).value
        );
        this.publicKey = publicKey;
        this.derivation = derivation;
    }

    public signCoinSpend(
        coinSpend: CoinSpend,
        aggSigMeExtraData: Uint8Array,
        privateKey: PrivateKey,
        keyPairs: Map<JacobianPoint, PrivateKey> = new Map()
    ): JacobianPoint {
        if (!privateKey.getG1().equals(this.publicKey))
            throw new Error('Incorrect private key.');
        const signatures: Array<JacobianPoint> = [];
        const finalKeyPairs = new Map(keyPairs);
        const syntheticPublicKey = Wallet.syntheticPublicKey(
            this.publicKey,
            defaultHiddenPuzzleHash
        );
        const syntheticPrivateKey = Wallet.syntheticPrivateKey(
            privateKey,
            defaultHiddenPuzzleHash
        );
        finalKeyPairs.set(syntheticPublicKey, syntheticPrivateKey);
        const conditions = Program.deserializeHex(
            sanitizeHex(coinSpend.puzzle_reveal)
        )
            .run(Program.deserializeHex(sanitizeHex(coinSpend.solution)))
            .value.toList();
        const pairs: Array<[JacobianPoint, Uint8Array]> = [];
        for (const item of conditions.filter(
            (condition) =>
                condition.first.isAtom &&
                [49, 50].includes(condition.first.toInt())
        )) {
            const condition = item.toList();
            if (condition.length !== 3)
                throw new Error('Invalid condition length.');
            else if (!condition[1].isAtom || condition[1].atom.length !== 48)
                throw new Error('Invalid public key.');
            else if (!condition[2].isAtom || condition[2].atom.length > 1024)
                throw new Error('Invalid message.');
            pairs.push([
                JacobianPoint.fromBytesG1(condition[1].atom),
                concatBytes(
                    condition[2].atom,
                    ...(condition[0].toInt() === 49
                        ? []
                        : [
                              hash256(
                                  concatBytes(
                                      fromHex(
                                          sanitizeHex(
                                              coinSpend.coin.parent_coin_info
                                          )
                                      ),
                                      fromHex(
                                          sanitizeHex(
                                              coinSpend.coin.puzzle_hash
                                          )
                                      ),
                                      encodeInt(coinSpend.coin.amount)
                                  )
                              ),
                              aggSigMeExtraData,
                          ])
                ),
            ]);
        }
        for (const [publicKey, message] of pairs) {
            let privateKey: PrivateKey | null = null;
            for (const keyPair of finalKeyPairs) {
                if (keyPair[0].equals(publicKey)) privateKey = keyPair[1];
            }
            if (!privateKey)
                throw new Error(
                    `Could not find private key for ${publicKey.toHex()}.`
                );
            const signature = AugSchemeMPL.sign(privateKey, message);
            signatures.push(signature);
        }
        return AugSchemeMPL.aggregate(signatures);
    }

    public solutionForConditions(conditions: Program[]): Program {
        const delegatedPuzzle = puzzles.payToConditions.run(
            Program.fromList([Program.fromList(conditions)])
        ).value;
        return Program.fromList([Program.nil, delegatedPuzzle, Program.nil]);
    }

    public static derivePrivateKey(
        masterPrivateKey: PrivateKey,
        index: number,
        hardened: boolean
    ): PrivateKey {
        return Wallet.derivePrivateKeyPath(
            masterPrivateKey,
            [12381, 8444, 2, index],
            hardened
        );
    }

    public static derivePublicKey(
        masterPublicKey: JacobianPoint,
        index: number
    ): JacobianPoint {
        return Wallet.derivePublicKeyPath(masterPublicKey, [
            12381,
            8444,
            2,
            index,
        ]);
    }

    public static syntheticPublicKey(
        publicKey: JacobianPoint,
        hiddenPuzzleHash: Uint8Array
    ): JacobianPoint {
        return JacobianPoint.fromBytes(
            puzzles.syntheticPublicKey.run(
                Program.fromList([
                    Program.fromBytes(publicKey.toBytes()),
                    Program.fromBytes(hiddenPuzzleHash),
                ])
            ).value.atom,
            false
        );
    }

    public static syntheticPrivateKey(
        privateKey: PrivateKey,
        hiddenPuzzleHash: Uint8Array
    ): PrivateKey {
        const privateExponent = bytesToBigInt(privateKey.toBytes(), 'big');
        const publicKey = privateKey.getG1();
        const syntheticOffset = Wallet.syntheticOffset(
            publicKey,
            hiddenPuzzleHash
        );
        const syntheticPrivateExponent =
            (privateExponent + syntheticOffset) % groupOrder;
        const blob = bigIntToBytes(syntheticPrivateExponent, 32, 'big');
        return PrivateKey.fromBytes(blob);
    }

    public static syntheticOffset(
        publicKey: JacobianPoint,
        hiddenPuzzleHash: Uint8Array
    ): bigint {
        const blob = hash256(
            concatBytes(publicKey.toBytes(), hiddenPuzzleHash)
        );
        return bytesToBigInt(blob, 'big') % groupOrder;
    }

    public static derivePrivateKeyPath(
        privateKey: PrivateKey,
        path: number[],
        hardened: boolean
    ): PrivateKey {
        for (const index of path)
            privateKey = (
                hardened
                    ? AugSchemeMPL.deriveChildSk
                    : AugSchemeMPL.deriveChildSkUnhardened
            )(privateKey, index);
        return privateKey;
    }

    public static derivePublicKeyPath(
        publicKey: JacobianPoint,
        path: number[]
    ): JacobianPoint {
        for (const index of path)
            publicKey = AugSchemeMPL.deriveChildPkUnhardened(publicKey, index);
        return publicKey;
    }
}
