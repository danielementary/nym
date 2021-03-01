import ValidatorClient from "nym-validator-client";
import * as fs from "fs";
import { MixNode } from "../../dist/types";

import readlineSync from "readline-sync";
import { Console } from "console";

main(true, false);

async function main(upload: boolean, addNodes: boolean) {
    // get our users set up

    console.log("Setting up users");

    const daveKey = await buildKeyPath("dave");
    console.log("daveKey: " + daveKey);

    const mnemonic = ValidatorClient.loadMnemonic(daveKey);
    console.log("mnemonic: " + mnemonic);

    let contractAddress = "fakeContractAddress";
    let validatorUrl = "http://localhost:26557";

    const coins2000_nym = [{ amount: "2000000000", denom: "unym" }];

    console.log("User dave has been set up.");

    readlineSync.keyIn('Hit any key to continue');



    if (upload) {

        console.log("Starting contract upload");
        readlineSync.keyIn('Hit any key to continue');

        // instantiate a client we can use to upload. We don't have a contract address yet, so let's just fake it.
        let uploadClient = await ValidatorClient.connect(contractAddress, mnemonic, validatorUrl);

        // Upload a new copy of the option contract
        let wasm = fs.readFileSync("../../../../contracts/mixnet/target/wasm32-unknown-unknown/release/mixnet_contracts.wasm");

        // dave can upload (note: nobody else can)
        const uploadResult = await uploadClient.upload(uploadClient.address, wasm, undefined, "mixnet contract");
        console.log("Upload from dave succeeded, codeId is: " + uploadResult.codeId);

        // Instantiate the copy of the option contract
        const { codeId } = uploadResult;
        const initMsg = {};
        let instantiateResult = await uploadClient.instantiate(uploadClient.address, codeId, initMsg, "mixnet contract", { memo: "v0.1.0", transferAmount: [{ denom: "unym", amount: "50000" }] });
        contractAddress = instantiateResult.contractAddress;
        console.log(`mixnet contract ${contractAddress} instantiated successfully`)

        readlineSync.keyIn('Hit any key to continue');


    } else {
        contractAddress = "nym127gs5ej23jd69685a3lyetnhlfe9nwegpjx5a9";
    }

    console.log(`Let's test contract existence. Contract address is: ${contractAddress}`);
    let client = await ValidatorClient.connect(contractAddress, mnemonic, validatorUrl);
    console.log("Connected to the validator. Using client address: " + client.address);

    readlineSync.keyIn('Hit any key to continue');


    console.log("Now the big moment we've all been waiting for. Let's retrieve the mixnodes from the validator.");
    await client.refreshMixNodes().then(response => console.log(response)).catch(err => {
        console.log(err);
    });

    readlineSync.keyIn('Hit any key to continue');


    if (addNodes) {
        console.log("Adding nodes from many different users...");
        for (var i = 1; i < 3; i++) {
            let mnemonic = ValidatorClient.randomMnemonic();
            let newAccount = await ValidatorClient.connect(contractAddress, mnemonic, validatorUrl);

            await client.send(client.address, newAccount.address, coins2000_nym, `Token send to random address`);
            const mixNode: MixNode = {
                host: "1.1.1.1",
                layer: 1,
                location: "London, UK",
                sphinx_key: "sphinx",
                version: "0.10.0",
            };
            await newAccount.announce(mixNode).catch(err => {
                console.log(`Error while adding node: ${err}`);
            });
        }
    }


    console.log("Let's see what is in the topology after we've added nodes:");
    await client.refreshMixNodes().catch(err => {
        console.log(err);
    });
    console.log(client.getMixNodes());
    readlineSync.keyIn('Hit any key to continue');


    console.log("Adding user fred");

    const fredKey = await buildKeyPath("fred");
    const fredMnemonic = ValidatorClient.loadMnemonic(fredKey);
    const fredClient = await ValidatorClient.connect(contractAddress, fredMnemonic, validatorUrl);
    console.log("fred's balance before receiving cash is");
    console.log(await fredClient.getBalance(fredClient.address));


    console.log("let's slide some cash from dave to fred");
    await client.send(client.address, fredClient.address, coins2000_nym, "Sliding some cash to fred!");

    console.log("fred's balance after receiving cash is");
    console.log(await fredClient.getBalance(fredClient.address));

    readlineSync.keyIn('Hit any key to continue');


    console.log("Let's have fred bond a node");

    const fredNode: MixNode = {
        host: "1.1.1.1",
        layer: 1,
        location: "Fred's house",
        sphinx_key: "sphinx",
        version: "0.10.0",
    };

    await fredClient.announce(fredNode);
    console.log("fred's balance after announcing a node is");
    console.log(await fredClient.getBalance(fredClient.address));

    console.log("Let's see how much is currently stored in the mixnet contract itself:");
    console.log(await client.getBalance(contractAddress));

    readlineSync.keyIn('Hit any key to continue');



    log("Nodes in the contract are now", await fredClient.refreshMixNodes());

    readlineSync.keyIn('Hit any key to continue');


    console.log("Let's make sure fred's mixnode is actually in the list of mixnodes");
    let fredPresence = false;
    let fredNodes = await fredClient.refreshMixNodes();
    fredNodes.forEach(node => { if (node.owner == fredClient.address) fredPresence = true })

    console.log(fredPresence);

    readlineSync.keyIn('Hit any key to continue');

    console.log("Alright, so now fred will unbond his mixnode.")
    console.log("We should see money come out of the contract and back to fred");
    console.log("unbonding...");
    let unbondResult = await fredClient.unbond();
    log("unbonding complete", unbondResult);

    log("Nodes in the contract are now", await fredClient.refreshMixNodes());


    console.log("fred should have unbonded. Do we find fred's node in the refreshed list of mixnodes?");
    fredNodes = await fredClient.refreshMixNodes();

    fredPresence = false;
    fredNodes.forEach(node => { if (node.owner == fredClient.address) fredPresence = true })
    console.log(fredPresence);

    readlineSync.keyIn('Hit any key to continue');


    console.log("Let's see how much is currently stored in the mixnet contract:");
    console.log(await client.getBalance(contractAddress));


    console.log("fred's balance after unbonding the node is");
    console.log(await fredClient.getBalance(fredClient.address));

    console.log(`fred's address is ${fredClient.address}`);

    // console.log(fredNodes);

    // await dave.client.execute(dave.address, contractAddress, { un_register_mixnode: {} });
    // console.log("Unbonding succeeded");

    // const after_unbond_balance = await dave.client.getBalance(dave.address, "unym");


    // console.log(`Dave's account now has: ${after_unbond_balance.amount}`);
    // const unbonded_from_dave: number = Number(after_unbond_balance.amount) - Number(before_unbond_balance.amount);
    // console.log(`dave's account had ${unbonded_from_dave} restored to it`);

    // console.log("has the node been removed from the topology?");
    // await getTopology(contractAddress, dave.client);

    // console.log("trying to unbond a node with an account that doesn't own a mixnode bond");
    // await thief.client.execute(thief.address, contractAddress, { un_register_mixnode: {} }).catch(err => {
    //     console.log(`Error unbonding node: ${err}`)
    // });
}

// async function addNode(ip: string, account: Account, contractAddress: string) {
//     let node = {
//         host: ip,
//         layer: 1,
//         location: "the internet",
//         sphinx_key: "mysphinxkey",
//         version: "0.9.2",
//     };

//     const bond = [{ amount: "1000000000", denom: "unym" }];
//     await account.client.execute(account.address, contractAddress, { register_mixnode: { mix_node: node } }, "adding mixnode", bond);
//     console.log(`account ${account.address} added mixnode with ${ip}`);
// }

// async function queryAccount(account: Account) {
//     const balance = await account.client.getBalance(account.address, "unym");
//     console.log(`${account.name} (${account.address}) has: ${balance?.amount}${balance?.denom}`);
// }

// async function getTopology(contractAddress: string, client: SigningCosmWasmClient) {// : Promise<Topology> {
//     let pagedResponse = await client.queryContractSmart(contractAddress, { get_mix_nodes: {} });
//     console.log(pagedResponse);
//     console.log(`length is: ${pagedResponse.nodes.length}.`);
// }

async function buildKeyPath(name: string): Promise<string> {
    return `/home/dave/.nym-test-accounts/${name}.key`;
}

// async function newAccount(mnemonic: string): Promise<Account> {
//     const { client, address } = await connect(mnemonic, {});
//     return new Account(address, client, address);

// }

// class Account {
//     constructor(readonly name: string, readonly client: SigningCosmWasmClient, readonly address: string) { };
// }

// class Topology {
//     constructor(readonly mixNodes: [], readonly validators: []) { };
// }

function log(text: string, thing: any) {
    let msg = JSON.stringify(thing);
    console.log(`${text}: ${msg}`);
}