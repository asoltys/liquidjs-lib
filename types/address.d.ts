import { Network } from './networks';
export interface Base58CheckResult {
    hash: Buffer;
    version: number;
}
export interface Bech32Result {
    version: number;
    prefix: string;
    data: Buffer;
}
export interface ConfidentialResult {
    blindingKey: Buffer;
    unconfidentialAddress: string;
}
export declare function fromBase58Check(address: string): Base58CheckResult;
export declare function fromBech32(address: string): Bech32Result;
export declare function fromConfidential(address: string): ConfidentialResult;
export declare function toBase58Check(hash: Buffer, version: number): string;
export declare function toBech32(data: Buffer, version: number, prefix: string): string;
export declare function toConfidential(address: string, blindingKey: Buffer): string;
export declare function fromOutputScript(output: Buffer, network?: Network): string;
export declare function toOutputScript(address: string, network?: Network): Buffer;
export declare function getNetwork(address: string): Network;
/**
 * A quick check used to verify if a string could be a valid confidential address.
 * @param address address to check.
 */
export declare function isConfidential(address: string): boolean;
