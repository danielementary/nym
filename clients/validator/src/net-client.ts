import { SigningCosmWasmClient, SigningCosmWasmClientOptions } from '@cosmjs/cosmwasm-stargate';
import { MixNode } from './types'
// import { connect as connectHelper } from "./stargate-helper";
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import { GasPrice } from '@cosmjs/launchpad';
import { Coin } from "@cosmjs/launchpad"
import { BroadcastTxResponse } from "@cosmjs/stargate/types"
import { Options, nymGasLimits, defaultOptions } from "./stargate-helper"
import { ExecuteResult, InstantiateOptions, InstantiateResult, UploadMeta, UploadResult } from '@cosmjs/cosmwasm';


export interface INetClient {
    getMixNodes(contractAddress: string, limit: number, start_after?: string): Promise<PagedResponse>;
    executeContract(senderAddress: string, contractAddress: string, handleMsg: Record<string, unknown>, memo?: string, transferAmount?: readonly Coin[]): Promise<ExecuteResult>;
    instantiate(senderAddress: string, codeId: number, initMsg: Record<string, unknown>, label: string, options?: InstantiateOptions): Promise<InstantiateResult>;
    sendTokens(senderAddress: string, recipientAddress: string, transferAmount: readonly Coin[], memo?: string): Promise<BroadcastTxResponse>;
    upload(senderAddress: string, wasmCode: Uint8Array, meta?: UploadMeta, memo?: string): Promise<UploadResult>;
}

/**
 * Takes care of network communication between this code and the validator. 
 * Depends on `SigningCosmWasClient`, which signs all requests using keypairs 
 * derived from on bech32 mnemonics.
 * 
 * Wraps several methods from CosmWasmSigningClient so we can mock them for
 * unit testing.
 */
export default class NetClient implements INetClient {
    private clientAddress: string;
    private cosmClient: SigningCosmWasmClient;

    private constructor(clientAddress: string, cosmClient: SigningCosmWasmClient) {
        this.clientAddress = clientAddress;
        this.cosmClient = cosmClient;
    }

    public static async connect(contractAddress: string, wallet: DirectSecp256k1HdWallet, url?: string, opts?: Partial<Options>): Promise<INetClient> {
        const options: Options = { ...defaultOptions, ...opts }
        const [{ address }] = await wallet.getAccounts();
        const signerOptions: SigningCosmWasmClientOptions = {
            gasPrice: GasPrice.fromString("0.025unym"),
            gasLimits: nymGasLimits,
        };
        const client = await SigningCosmWasmClient.connectWithSigner(options.httpUrl, wallet, signerOptions);

        let netClient = new NetClient(address, client);
        return netClient;
    }

    public getMixNodes(contractAddress: string, limit: number, start_after?: string): Promise<PagedResponse> {
        if (start_after == undefined) { // TODO: check if we can take this out, I'm not sure what will happen if we send an "undefined" so I'm playing it safe here.
            return this.cosmClient.queryContractSmart(contractAddress, { get_mix_nodes: { limit } });
        } else {
            return this.cosmClient.queryContractSmart(contractAddress, { get_mix_nodes: { limit, start_after } });
        }
    }


    public executeContract(senderAddress: string, contractAddress: string, handleMsg: Record<string, unknown>, memo?: string, transferAmount?: readonly Coin[]): Promise<ExecuteResult> {
        return this.cosmClient.execute(senderAddress, contractAddress, handleMsg, memo, transferAmount);
    }

    public sendTokens(senderAddress: string, recipientAddress: string, transferAmount: readonly Coin[], memo?: string): Promise<BroadcastTxResponse> {
        return this.cosmClient.sendTokens(senderAddress, recipientAddress, transferAmount, memo);
    }

    public upload(senderAddress: string, wasmCode: Uint8Array, meta?: UploadMeta, memo?: string): Promise<UploadResult> {
        return this.cosmClient.upload(senderAddress, wasmCode, meta, memo);
    }

    public instantiate(senderAddress: string, codeId: number, initMsg: Record<string, unknown>, label: string, options?: InstantiateOptions): Promise<InstantiateResult> {
        return this.cosmClient.instantiate(senderAddress, codeId, initMsg, label, options);
    }
}

/// One page of a possible multi-page set of mixnodes. The paging interface is quite
/// inconvenient, as we don't have the two pieces of information we need to know
/// in order to do paging nicely (namely `currentPage` and `totalPages` parameters). 
///
/// Instead, we have only `start_next_page_after`, i.e. the key of the last record
/// on this page. In order to get the *next* page, CosmWasm looks at that value, 
/// finds the next record, and builds the next page starting there. This happens
/// **in series** rather than **in parallel** (!). 
///
/// So we have some consistency problems: 
///
/// * we can't make requests at a given block height, so the result set
///    which we assemble over time may change while requests are being made.
/// * at some point we will make a request for a `start_next_page_after` key 
///   which has just been deleted from the database.
///
/// TODO: more robust error handling on the "deleted key" case.
export interface PagedResponse {
    nodes: MixNode[],
    per_page: number, // TODO: camelCase
    start_next_after: string, // TODO: camelCase
}