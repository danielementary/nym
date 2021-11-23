// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0
use crate::error::ContractError;
use crate::queries;
use crate::storage::*;
use config::defaults::DENOM;
use cosmwasm_std::{attr, coins, BankMsg, Coin, DepsMut, Env, MessageInfo, Response, Uint128};
use mixnet_contract::{
    Gateway, GatewayBond, IdentityKey, Layer, MixNode, RawDelegationData, StateParams,
};

pub(crate) mod rewarding;
pub(crate) use rewarding::*;

pub(crate) const OLD_DELEGATIONS_CHUNK_SIZE: usize = 500;

// approximately 1 day (assuming 5s per block)
pub(crate) const MINIMUM_BLOCK_AGE_FOR_REWARDING: u64 = 17280;

// approximately 30min (assuming 5s per block)
pub(crate) const MAX_REWARDING_DURATION_IN_BLOCKS: u64 = 360;

fn validate_mixnode_bond(bond: &[Coin], minimum_bond: Uint128) -> Result<(), ContractError> {
    // check if anything was put as bond
    if bond.is_empty() {
        return Err(ContractError::NoBondFound);
    }

    if bond.len() > 1 {
        return Err(ContractError::MultipleDenoms);
    }

    // check that the denomination is correct
    if bond[0].denom != DENOM {
        return Err(ContractError::WrongDenom {});
    }

    // check that we have at least MIXNODE_BOND coins in our bond
    if bond[0].amount < minimum_bond {
        return Err(ContractError::InsufficientMixNodeBond {
            received: bond[0].amount.into(),
            minimum: minimum_bond.into(),
        });
    }

    Ok(())
}

pub(crate) fn try_add_mixnode(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    mix_node: MixNode,
) -> Result<Response, ContractError> {
    let sender_bytes = info.sender.as_bytes();

    // if the client has an active bonded gateway, don't allow mixnode bonding
    if gateways_owners_read(deps.storage)
        .may_load(sender_bytes)?
        .is_some()
    {
        return Err(ContractError::AlreadyOwnsGateway);
    }

    let mut was_present = false;
    // if the client has an active mixnode with a different identity, don't allow bonding
    if let Some(existing_node) = mixnodes_owners_read(deps.storage).may_load(sender_bytes)? {
        if existing_node != mix_node.identity_key {
            return Err(ContractError::AlreadyOwnsMixnode);
        }
        was_present = true
    }

    // check if somebody else has already bonded a mixnode with this identity
    if let Some(existing_bond) =
        mixnodes_read(deps.storage).may_load(mix_node.identity_key.as_bytes())?
    {
        if existing_bond.owner != info.sender {
            return Err(ContractError::DuplicateMixnode {
                owner: existing_bond.owner,
            });
        }
    }

    let minimum_bond = read_state_params(deps.storage).minimum_mixnode_bond;
    validate_mixnode_bond(&info.funds, minimum_bond)?;

    let layer_distribution = queries::query_layer_distribution(deps.as_ref());
    let layer = layer_distribution.choose_with_fewest();

    let stored_bond = StoredMixnodeBond::new(
        info.funds[0].clone(),
        info.sender.clone(),
        layer,
        env.block.height,
        mix_node,
        None,
    );

    let identity = stored_bond.identity();

    // technically we don't have to set the total_delegation bucket, but it makes things easier
    // in different places that we can guarantee that if node exists, so does the data behind the total delegation
    mixnodes(deps.storage).save(identity.as_bytes(), &stored_bond)?;
    mixnodes_owners(deps.storage).save(sender_bytes, identity)?;
    total_delegation(deps.storage).save(identity.as_bytes(), &Uint128::zero())?;
    increment_layer_count(deps.storage, layer)?;

    let attributes = vec![attr("overwritten", was_present)];
    Ok(Response {
        submessages: Vec::new(),
        messages: Vec::new(),
        attributes,
        data: None,
    })
}

pub(crate) fn try_remove_mixnode(
    deps: DepsMut,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let sender_bytes = info.sender.as_bytes();

    // try to find the identity of the sender's node
    let mix_identity = match mixnodes_owners_read(deps.storage).may_load(sender_bytes)? {
        Some(identity) => identity,
        None => return Err(ContractError::NoAssociatedMixNodeBond { owner: info.sender }),
    };

    // get the bond, since we found associated identity, the node MUST exist
    let mixnode_bond = mixnodes_read(deps.storage).load(mix_identity.as_bytes())?;

    // send bonded funds back to the bond owner
    let messages = vec![BankMsg::Send {
        to_address: info.sender.as_str().to_owned(),
        amount: vec![mixnode_bond.bond_amount()],
    }
    .into()];

    // remove the bond from the list of bonded mixnodes
    mixnodes(deps.storage).remove(mix_identity.as_bytes());
    // remove the node ownership
    mixnodes_owners(deps.storage).remove(sender_bytes);
    // decrement layer count
    decrement_layer_count(deps.storage, mixnode_bond.layer)?;

    // log our actions
    let attributes = vec![attr("action", "unbond"), attr("mixnode_bond", mixnode_bond)];

    Ok(Response {
        submessages: Vec::new(),
        messages,
        attributes,
        data: None,
    })
}

fn validate_gateway_bond(bond: &[Coin], minimum_bond: Uint128) -> Result<(), ContractError> {
    // check if anything was put as bond
    if bond.is_empty() {
        return Err(ContractError::NoBondFound);
    }

    if bond.len() > 1 {
        return Err(ContractError::MultipleDenoms);
    }

    // check that the denomination is correct
    if bond[0].denom != DENOM {
        return Err(ContractError::WrongDenom {});
    }

    // check that we have at least 100 coins in our bond
    if bond[0].amount < minimum_bond {
        return Err(ContractError::InsufficientGatewayBond {
            received: bond[0].amount.into(),
            minimum: minimum_bond.into(),
        });
    }

    Ok(())
}

pub(crate) fn try_add_gateway(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    gateway: Gateway,
) -> Result<Response, ContractError> {
    let sender_bytes = info.sender.as_bytes();

    // if the client has an active bonded mixnode, don't allow gateway bonding
    if mixnodes_owners_read(deps.storage)
        .may_load(sender_bytes)?
        .is_some()
    {
        return Err(ContractError::AlreadyOwnsMixnode);
    }

    let mut was_present = false;
    // if the client has an active gateway with a different identity, don't allow bonding
    if let Some(existing_node) = gateways_owners_read(deps.storage).may_load(sender_bytes)? {
        if existing_node != gateway.identity_key {
            return Err(ContractError::AlreadyOwnsGateway);
        }
        was_present = true
    }

    // check if somebody else has already bonded a gateway with this identity
    if let Some(existing_bond) =
        gateways_read(deps.storage).may_load(gateway.identity_key.as_bytes())?
    {
        if existing_bond.owner != info.sender {
            return Err(ContractError::DuplicateGateway {
                owner: existing_bond.owner,
            });
        }
    }

    let minimum_bond = read_state_params(deps.storage).minimum_gateway_bond;
    validate_gateway_bond(&info.funds, minimum_bond)?;

    let bond = GatewayBond::new(
        info.funds[0].clone(),
        info.sender.clone(),
        env.block.height,
        gateway,
    );

    let identity = bond.identity();
    gateways(deps.storage).save(identity.as_bytes(), &bond)?;
    gateways_owners(deps.storage).save(sender_bytes, identity)?;
    increment_layer_count(deps.storage, Layer::Gateway)?;

    let attributes = vec![attr("overwritten", was_present)];
    Ok(Response {
        submessages: Vec::new(),
        messages: Vec::new(),
        attributes,
        data: None,
    })
}

pub(crate) fn try_remove_gateway(
    deps: DepsMut,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let sender_bytes = info.sender.as_str().as_bytes();

    // try to find the identity of the sender's node
    let gateway_identity = match gateways_owners_read(deps.storage).may_load(sender_bytes)? {
        Some(identity) => identity,
        None => return Err(ContractError::NoAssociatedGatewayBond { owner: info.sender }),
    };

    // get the bond, since we found associated identity, the node MUST exist
    let gateway_bond = gateways_read(deps.storage).load(gateway_identity.as_bytes())?;

    // send bonded funds back to the bond owner
    let messages = vec![BankMsg::Send {
        to_address: info.sender.as_str().to_owned(),
        amount: vec![gateway_bond.bond_amount()],
    }
    .into()];

    // remove the bond from the list of bonded gateways
    gateways(deps.storage).remove(gateway_identity.as_bytes());
    // remove the node ownership
    gateways_owners(deps.storage).remove(sender_bytes);
    // decrement layer count
    decrement_layer_count(deps.storage, Layer::Gateway)?;

    // log our actions
    let attributes = vec![
        attr("action", "unbond"),
        attr("address", info.sender),
        attr("gateway_bond", gateway_bond),
    ];

    Ok(Response {
        submessages: Vec::new(),
        messages,
        attributes,
        data: None,
    })
}

pub(crate) fn try_update_state_params(
    deps: DepsMut,
    info: MessageInfo,
    params: StateParams,
) -> Result<Response, ContractError> {
    // note: In any other case, I wouldn't have attempted to unwrap this result, but in here
    // if we fail to load the stored state we would already be in the undefined behaviour land,
    // so we better just blow up immediately.
    let mut state = config_read(deps.storage).load()?;

    // check if this is executed by the owner, if not reject the transaction
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized);
    }

    if params.mixnode_rewarded_set_size == 0 {
        return Err(ContractError::ZeroRewardedSet);
    }

    if params.mixnode_active_set_size == 0 {
        return Err(ContractError::ZeroActiveSet);
    }

    // note: rewarded_set = active_set + idle_set
    // hence rewarded set must always be bigger than (or equal to) the active set
    if params.mixnode_rewarded_set_size < params.mixnode_active_set_size {
        return Err(ContractError::InvalidActiveSetSize);
    }

    state.params = params;

    config(deps.storage).save(&state)?;

    Ok(Response::default())
}

fn validate_delegation_stake(delegation: &[Coin]) -> Result<(), ContractError> {
    // check if anything was put as delegation
    if delegation.is_empty() {
        return Err(ContractError::EmptyDelegation);
    }

    if delegation.len() > 1 {
        return Err(ContractError::MultipleDenoms);
    }

    // check that the denomination is correct
    if delegation[0].denom != DENOM {
        return Err(ContractError::WrongDenom {});
    }

    // check that we have provided a non-zero amount in the delegation
    if delegation[0].amount.is_zero() {
        return Err(ContractError::EmptyDelegation);
    }

    Ok(())
}

pub(crate) fn try_delegate_to_mixnode(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    mix_identity: IdentityKey,
) -> Result<Response, ContractError> {
    // check if the delegation contains any funds of the appropriate denomination
    validate_delegation_stake(&info.funds)?;

    // check if the target node actually exists
    if mixnodes_read(deps.storage)
        .load(mix_identity.as_bytes())
        .is_err()
    {
        return Err(ContractError::MixNodeBondNotFound {
            identity: mix_identity,
        });
    }

    // update total_delegation of this node
    total_delegation(deps.storage).update::<_, ContractError>(
        mix_identity.as_bytes(),
        |total_delegation| {
            // unwrap is fine as if the mixnode itself exists, so must this entry
            Ok(total_delegation.unwrap() + info.funds[0].amount)
        },
    )?;

    // update delegation of this delegator
    mix_delegations(deps.storage, &mix_identity).update::<_, ContractError>(
        info.sender.as_bytes(),
        |existing_delegation| {
            let existing_delegation_amount = existing_delegation
                .map(|existing_delegation| existing_delegation.amount)
                .unwrap_or_default();

            // the block height is reset, if it existed
            Ok(RawDelegationData::new(
                existing_delegation_amount + info.funds[0].amount,
                env.block.height,
            ))
        },
    )?;

    // save information about delegations of this sender
    reverse_mix_delegations(deps.storage, &info.sender).save(mix_identity.as_bytes(), &())?;

    Ok(Response::default())
}

pub(crate) fn try_remove_delegation_from_mixnode(
    deps: DepsMut,
    info: MessageInfo,
    mix_identity: IdentityKey,
) -> Result<Response, ContractError> {
    let mut delegation_bucket = mix_delegations(deps.storage, &mix_identity);
    let sender_bytes = info.sender.as_bytes();

    if let Some(delegation) = delegation_bucket.may_load(sender_bytes)? {
        // remove all delegation associated with this delegator
        delegation_bucket.remove(sender_bytes);
        reverse_mix_delegations(deps.storage, &info.sender).remove(mix_identity.as_bytes());

        // send delegated funds back to the delegation owner
        let messages = vec![BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: coins(delegation.amount.u128(), DENOM),
        }
        .into()];

        // update total_delegation of this node
        total_delegation(deps.storage).update::<_, ContractError>(
            mix_identity.as_bytes(),
            |total_delegation| {
                // the first unwrap is fine because the delegation information MUST exist, otherwise we would
                // have never gotten here in the first place
                // the second unwrap is also fine because we should NEVER underflow here,
                // if we do, it means we have some serious error in our logic
                Ok(total_delegation
                    .unwrap()
                    .checked_sub(delegation.amount)
                    .unwrap())
            },
        )?;

        Ok(Response {
            submessages: Vec::new(),
            messages,
            attributes: Vec::new(),
            data: None,
        })
    } else {
        Err(ContractError::NoMixnodeDelegationFound {
            identity: mix_identity,
            address: info.sender,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::contract::{execute, query, INITIAL_GATEWAY_BOND, INITIAL_MIXNODE_BOND};
    use crate::helpers::Delegations;
    use crate::storage::layer_distribution_read;
    use crate::support::tests::helpers;
    use crate::support::tests::helpers::{good_gateway_bond, good_mixnode_bond};
    use cosmwasm_std::testing::{mock_env, mock_info};
    use cosmwasm_std::{coin, coins, from_binary, Addr, Uint128};
    use mixnet_contract::{
        ExecuteMsg, LayerDistribution, PagedGatewayResponse, PagedMixnodeResponse, QueryMsg,
        UnpackedDelegation, MIXNODE_DELEGATORS_PAGE_LIMIT,
    };
    use queries::tests::store_n_mix_delegations;

    #[test]
    fn validating_mixnode_bond() {
        // you must send SOME funds
        let result = validate_mixnode_bond(&[], INITIAL_MIXNODE_BOND);
        assert_eq!(result, Err(ContractError::NoBondFound));

        // you must send at least 100 coins...
        let mut bond = good_mixnode_bond();
        bond[0].amount = INITIAL_MIXNODE_BOND.checked_sub(Uint128(1)).unwrap();
        let result = validate_mixnode_bond(&bond, INITIAL_MIXNODE_BOND);
        assert_eq!(
            result,
            Err(ContractError::InsufficientMixNodeBond {
                received: Into::<u128>::into(INITIAL_MIXNODE_BOND) - 1,
                minimum: INITIAL_MIXNODE_BOND.into(),
            })
        );

        // more than that is still fine
        let mut bond = good_mixnode_bond();
        bond[0].amount = INITIAL_MIXNODE_BOND + Uint128(1);
        let result = validate_mixnode_bond(&bond, INITIAL_MIXNODE_BOND);
        assert!(result.is_ok());

        // it must be sent in the defined denom!
        let mut bond = good_mixnode_bond();
        bond[0].denom = "baddenom".to_string();
        let result = validate_mixnode_bond(&bond, INITIAL_MIXNODE_BOND);
        assert_eq!(result, Err(ContractError::WrongDenom {}));

        let mut bond = good_mixnode_bond();
        bond[0].denom = "foomp".to_string();
        let result = validate_mixnode_bond(&bond, INITIAL_MIXNODE_BOND);
        assert_eq!(result, Err(ContractError::WrongDenom {}));
    }

    #[test]
    fn mixnode_add() {
        let mut deps = helpers::init_contract();

        // if we don't send enough funds
        let insufficient_bond = Into::<u128>::into(INITIAL_MIXNODE_BOND) - 1;
        let info = mock_info("anyone", &coins(insufficient_bond, DENOM));
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "anyonesmixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };

        // we are informed that we didn't send enough funds
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            result,
            Err(ContractError::InsufficientMixNodeBond {
                received: insufficient_bond,
                minimum: INITIAL_MIXNODE_BOND.into(),
            })
        );

        // no mixnode was inserted into the topology
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetMixNodes {
                start_after: None,
                limit: Option::from(2),
            },
        )
        .unwrap();
        let page: PagedMixnodeResponse = from_binary(&res).unwrap();
        assert_eq!(0, page.nodes.len());

        // if we send enough funds
        let info = mock_info("anyone", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "anyonesmixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };

        // we get back a message telling us everything was OK
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        // we can query topology and the new node is there
        let query_response = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetMixNodes {
                start_after: None,
                limit: Option::from(2),
            },
        )
        .unwrap();
        let page: PagedMixnodeResponse = from_binary(&query_response).unwrap();
        assert_eq!(1, page.nodes.len());
        assert_eq!(
            &MixNode {
                identity_key: "anyonesmixnode".into(),
                ..helpers::mix_node_fixture()
            },
            page.nodes[0].mix_node()
        );

        // if there was already a mixnode bonded by particular user
        let info = mock_info("foomper", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "foompermixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };

        let execute_response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(execute_response.attributes[0], attr("overwritten", false));

        let info = mock_info("foomper", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "foompermixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };

        // we get a log message about it (TODO: does it get back to the user?)
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(execute_response.attributes[0], attr("overwritten", true));

        // bonding fails if the user already owns a gateway
        let info = mock_info("gateway-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "ownersgateway".into(),
                ..helpers::gateway_fixture()
            },
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("gateway-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "ownersmixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(execute_response, Err(ContractError::AlreadyOwnsGateway));

        // but after he unbonds it, it's all fine again
        let info = mock_info("gateway-owner", &[]);
        let msg = ExecuteMsg::UnbondGateway {};
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("gateway-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "ownersmixnode".into(),
                ..helpers::mix_node_fixture()
            },
        };
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        // adding another node from another account, but with the same IP, should fail (or we would have a weird state). Is that right? Think about this, not sure yet.
        // if we attempt to register a second node from the same address, should we get an error? It would probably be polite.
    }

    #[test]
    fn adding_mixnode_without_existing_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        // before the execution the node had no associated owner
        assert!(mixnodes_owners_read(deps.as_ref().storage)
            .may_load("myAwesomeMixnode".as_bytes())
            .unwrap()
            .is_none());

        // it's all fine, owner is saved
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        assert_eq!(
            "myAwesomeMixnode",
            mixnodes_owners_read(deps.as_ref().storage)
                .load("mix-owner".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn adding_mixnode_with_existing_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // request fails giving the existing owner address in the message
        let info = mock_info("mix-owner-pretender", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            Err(ContractError::DuplicateMixnode {
                owner: Addr::unchecked("mix-owner")
            }),
            execute_response
        );
    }

    #[test]
    fn adding_mixnode_with_existing_unchanged_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                host: "1.1.1.1:1789".into(),
                ..helpers::mix_node_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                host: "2.2.2.2:1789".into(),
                ..helpers::mix_node_fixture()
            },
        };

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());

        // make sure the host information was updated
        assert_eq!(
            "2.2.2.2:1789".to_string(),
            mixnodes_read(deps.as_ref().storage)
                .load("myAwesomeMixnode".as_bytes())
                .unwrap()
                .mix_node
                .host
        );
    }

    #[test]
    fn adding_mixnode_updates_layer_distribution() {
        let mut deps = helpers::init_contract();

        assert_eq!(
            LayerDistribution::default(),
            layer_distribution_read(&deps.storage).load().unwrap(),
        );

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "mix1".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            LayerDistribution {
                layer1: 1,
                ..Default::default()
            },
            layer_distribution_read(&deps.storage).load().unwrap()
        );
    }

    #[test]
    fn mixnode_remove() {
        let mut deps = helpers::init_contract();

        // try un-registering when no nodes exist yet
        let info = mock_info("anyone", &[]);
        let msg = ExecuteMsg::UnbondMixnode {};
        let result = execute(deps.as_mut(), mock_env(), info, msg);

        // we're told that there is no node for our address
        assert_eq!(
            result,
            Err(ContractError::NoAssociatedMixNodeBond {
                owner: Addr::unchecked("anyone")
            })
        );

        // let's add a node owned by bob
        helpers::add_mixnode("bob", good_mixnode_bond(), deps.as_mut());

        // attempt to un-register fred's node, which doesn't exist
        let info = mock_info("fred", &[]);
        let msg = ExecuteMsg::UnbondMixnode {};
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            result,
            Err(ContractError::NoAssociatedMixNodeBond {
                owner: Addr::unchecked("fred")
            })
        );

        // bob's node is still there
        let nodes = helpers::get_mix_nodes(&mut deps);
        assert_eq!(1, nodes.len());
        assert_eq!("bob", nodes[0].owner().clone());

        // add a node owned by fred
        let info = mock_info("fred", &good_mixnode_bond());
        try_add_mixnode(
            deps.as_mut(),
            mock_env(),
            info,
            MixNode {
                identity_key: "fredsmixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        )
        .unwrap();

        // let's make sure we now have 2 nodes:
        assert_eq!(2, helpers::get_mix_nodes(&mut deps).len());

        // un-register fred's node
        let info = mock_info("fred", &[]);
        let msg = ExecuteMsg::UnbondMixnode {};
        let remove_fred = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // we should see log messages come back showing an unbond message
        let expected_attributes = vec![
            attr("action", "unbond"),
            attr(
                "mixnode_bond",
                format!(
                    "amount: {}{}, owner: fred, identity: fredsmixnode",
                    INITIAL_MIXNODE_BOND, DENOM
                ),
            ),
        ];

        // we should see a funds transfer from the contract back to fred
        let expected_messages = vec![BankMsg::Send {
            to_address: String::from(info.sender),
            amount: good_mixnode_bond(),
        }
        .into()];

        // run the executer and check that we got back the correct results
        let expected = Response {
            submessages: Vec::new(),
            messages: expected_messages,
            attributes: expected_attributes,
            data: None,
        };
        assert_eq!(expected, remove_fred);

        // only 1 node now exists, owned by bob:
        let mix_node_bonds = helpers::get_mix_nodes(&mut deps);
        assert_eq!(1, mix_node_bonds.len());
        assert_eq!(&Addr::unchecked("bob"), mix_node_bonds[0].owner());
    }

    #[test]
    fn removing_mixnode_clears_ownership() {
        let mut deps = helpers::init_contract();

        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            "myAwesomeMixnode",
            mixnodes_owners_read(deps.as_ref().storage)
                .load("mix-owner".as_bytes())
                .unwrap()
        );

        let info = mock_info("mix-owner", &[]);
        let msg = ExecuteMsg::UnbondMixnode {};

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());

        assert!(mixnodes_owners_read(deps.as_ref().storage)
            .may_load("mix-owner".as_bytes())
            .unwrap()
            .is_none());

        // and since it's removed, it can be reclaimed
        let info = mock_info("mix-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "myAwesomeMixnode".to_string(),
                ..helpers::mix_node_fixture()
            },
        };

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());
        assert_eq!(
            "myAwesomeMixnode",
            mixnodes_owners_read(deps.as_ref().storage)
                .load("mix-owner".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn validating_gateway_bond() {
        // you must send SOME funds
        let result = validate_gateway_bond(&[], INITIAL_GATEWAY_BOND);
        assert_eq!(result, Err(ContractError::NoBondFound));

        // you must send at least 100 coins...
        let mut bond = good_gateway_bond();
        bond[0].amount = INITIAL_GATEWAY_BOND.checked_sub(Uint128(1)).unwrap();
        let result = validate_gateway_bond(&bond, INITIAL_GATEWAY_BOND);
        assert_eq!(
            result,
            Err(ContractError::InsufficientGatewayBond {
                received: Into::<u128>::into(INITIAL_GATEWAY_BOND) - 1,
                minimum: INITIAL_GATEWAY_BOND.into(),
            })
        );

        // more than that is still fine
        let mut bond = good_gateway_bond();
        bond[0].amount = INITIAL_GATEWAY_BOND + Uint128(1);
        let result = validate_gateway_bond(&bond, INITIAL_GATEWAY_BOND);
        assert!(result.is_ok());

        // it must be sent in the defined denom!
        let mut bond = good_gateway_bond();
        bond[0].denom = "baddenom".to_string();
        let result = validate_gateway_bond(&bond, INITIAL_GATEWAY_BOND);
        assert_eq!(result, Err(ContractError::WrongDenom {}));

        let mut bond = good_gateway_bond();
        bond[0].denom = "foomp".to_string();
        let result = validate_gateway_bond(&bond, INITIAL_GATEWAY_BOND);
        assert_eq!(result, Err(ContractError::WrongDenom {}));
    }

    #[test]
    fn gateway_add() {
        let mut deps = helpers::init_contract();

        // if we fail validation (by say not sending enough funds
        let insufficient_bond = Into::<u128>::into(INITIAL_GATEWAY_BOND) - 1;
        let info = mock_info("anyone", &coins(insufficient_bond, DENOM));
        let msg = ExecuteMsg::BondGateway {
            gateway: helpers::gateway_fixture(),
        };

        // we are informed that we didn't send enough funds
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            result,
            Err(ContractError::InsufficientGatewayBond {
                received: insufficient_bond,
                minimum: INITIAL_GATEWAY_BOND.into(),
            })
        );

        // make sure no gateway was inserted into the topology
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetGateways {
                start_after: None,
                limit: Option::from(2),
            },
        )
        .unwrap();
        let page: PagedGatewayResponse = from_binary(&res).unwrap();
        assert_eq!(0, page.nodes.len());

        // if we send enough funds
        let info = mock_info("anyone", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "anyonesgateway".into(),
                ..helpers::gateway_fixture()
            },
        };

        // we get back a message telling us everything was OK
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        // we can query topology and the new node is there
        let query_response = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetGateways {
                start_after: None,
                limit: Option::from(2),
            },
        )
        .unwrap();
        let page: PagedGatewayResponse = from_binary(&query_response).unwrap();
        assert_eq!(1, page.nodes.len());
        assert_eq!(
            &Gateway {
                identity_key: "anyonesgateway".into(),
                ..helpers::gateway_fixture()
            },
            page.nodes[0].gateway()
        );

        // if there was already a gateway bonded by particular user
        let info = mock_info("foomper", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "foompersgateway".into(),
                ..helpers::gateway_fixture()
            },
        };

        let execute_response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(execute_response.attributes[0], attr("overwritten", false));

        let info = mock_info("foomper", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "foompersgateway".into(),
                ..helpers::gateway_fixture()
            },
        };

        // we get a log message about it (TODO: does it get back to the user?)
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(execute_response.attributes[0], attr("overwritten", true));

        // bonding fails if the user already owns a mixnode
        let info = mock_info("mixnode-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondMixnode {
            mix_node: MixNode {
                identity_key: "ownersmix".into(),
                ..helpers::mix_node_fixture()
            },
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("mixnode-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: helpers::gateway_fixture(),
        };
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(execute_response, Err(ContractError::AlreadyOwnsMixnode));

        // but after he unbonds it, it's all fine again
        let info = mock_info("mixnode-owner", &[]);
        let msg = ExecuteMsg::UnbondMixnode {};
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("mixnode-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: helpers::gateway_fixture(),
        };
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        // adding another node from another account, but with the same IP, should fail (or we would have a weird state).
        // Is that right? Think about this, not sure yet.
    }

    #[test]
    fn adding_gateway_without_existing_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("gateway-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                ..helpers::gateway_fixture()
            },
        };

        // before the execution the node had no associated owner
        assert!(gateways_owners_read(deps.as_ref().storage)
            .may_load("gateway-owner".as_bytes())
            .unwrap()
            .is_none());

        // it's all fine, owner is saved
        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(execute_response.is_ok());

        assert_eq!(
            "myAwesomeGateway",
            gateways_owners_read(deps.as_ref().storage)
                .load("gateway-owner".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn adding_gateway_with_existing_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("gateway-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                ..helpers::gateway_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // request fails giving the existing owner address in the message
        let info = mock_info("gateway-owner-pretender", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                ..helpers::gateway_fixture()
            },
        };

        let execute_response = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            Err(ContractError::DuplicateGateway {
                owner: Addr::unchecked("gateway-owner")
            }),
            execute_response
        );
    }

    #[test]
    fn adding_gateway_with_existing_unchanged_owner() {
        let mut deps = helpers::init_contract();

        let info = mock_info("gateway-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                host: "1.1.1.1".into(),
                ..helpers::gateway_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = mock_info("gateway-owner", &good_gateway_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                host: "2.2.2.2".into(),
                ..helpers::gateway_fixture()
            },
        };

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());

        // make sure the host information was updated
        assert_eq!(
            "2.2.2.2".to_string(),
            gateways_read(deps.as_ref().storage)
                .load("myAwesomeGateway".as_bytes())
                .unwrap()
                .gateway
                .host
        );
    }

    #[test]
    fn gateway_remove() {
        let mut deps = helpers::init_contract();

        // try unbond when no nodes exist yet
        let info = mock_info("anyone", &[]);
        let msg = ExecuteMsg::UnbondGateway {};
        let result = execute(deps.as_mut(), mock_env(), info, msg);

        // we're told that there is no node for our address
        assert_eq!(
            result,
            Err(ContractError::NoAssociatedGatewayBond {
                owner: Addr::unchecked("anyone")
            })
        );

        // let's add a node owned by bob
        helpers::add_gateway("bob", good_gateway_bond(), &mut deps);

        // attempt to unbond fred's node, which doesn't exist
        let info = mock_info("fred", &[]);
        let msg = ExecuteMsg::UnbondGateway {};
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert_eq!(
            result,
            Err(ContractError::NoAssociatedGatewayBond {
                owner: Addr::unchecked("fred")
            })
        );

        // bob's node is still there
        let nodes = helpers::get_gateways(&mut deps);
        assert_eq!(1, nodes.len());

        let first_node = &nodes[0];
        assert_eq!(&Addr::unchecked("bob"), first_node.owner());

        // add a node owned by fred
        let info = mock_info("fred", &good_gateway_bond());
        try_add_gateway(
            deps.as_mut(),
            mock_env(),
            info,
            Gateway {
                identity_key: "fredsgateway".into(),
                ..helpers::gateway_fixture()
            },
        )
        .unwrap();

        // let's make sure we now have 2 nodes:
        assert_eq!(2, helpers::get_gateways(&mut deps).len());

        // unbond fred's node
        let info = mock_info("fred", &[]);
        let msg = ExecuteMsg::UnbondGateway {};
        let remove_fred = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // we should see log messages come back showing an unbond message
        let expected_attributes = vec![
            attr("action", "unbond"),
            attr("address", "fred"),
            attr(
                "gateway_bond",
                format!(
                    "amount: {} {}, owner: fred, identity: fredsgateway",
                    INITIAL_GATEWAY_BOND, DENOM
                ),
            ),
        ];

        // we should see a funds transfer from the contract back to fred
        let expected_messages = vec![BankMsg::Send {
            to_address: String::from(info.sender),
            amount: good_gateway_bond(),
        }
        .into()];

        // run the executer and check that we got back the correct results
        let expected = Response {
            submessages: Vec::new(),
            messages: expected_messages,
            attributes: expected_attributes,
            data: None,
        };
        assert_eq!(remove_fred, expected);

        // only 1 node now exists, owned by bob:
        let gateway_bonds = helpers::get_gateways(&mut deps);
        assert_eq!(1, gateway_bonds.len());
        assert_eq!(&Addr::unchecked("bob"), gateway_bonds[0].owner());
    }

    #[test]
    fn removing_gateway_clears_ownership() {
        let mut deps = helpers::init_contract();

        let info = mock_info("gateway-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                ..helpers::gateway_fixture()
            },
        };

        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            "myAwesomeGateway",
            gateways_owners_read(deps.as_ref().storage)
                .load("gateway-owner".as_bytes())
                .unwrap()
        );

        let info = mock_info("gateway-owner", &[]);
        let msg = ExecuteMsg::UnbondGateway {};

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());

        assert!(gateways_owners_read(deps.as_ref().storage)
            .may_load("gateway-owner".as_bytes())
            .unwrap()
            .is_none());

        // and since it's removed, it can be reclaimed
        let info = mock_info("gateway-owner", &good_mixnode_bond());
        let msg = ExecuteMsg::BondGateway {
            gateway: Gateway {
                identity_key: "myAwesomeGateway".to_string(),
                ..helpers::gateway_fixture()
            },
        };

        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_ok());
        assert_eq!(
            "myAwesomeGateway",
            gateways_owners_read(deps.as_ref().storage)
                .load("gateway-owner".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn updating_state_params() {
        let mut deps = helpers::init_contract();

        let new_params = StateParams {
            minimum_mixnode_bond: INITIAL_MIXNODE_BOND,
            minimum_gateway_bond: INITIAL_GATEWAY_BOND,
            mixnode_rewarded_set_size: 100,
            mixnode_active_set_size: 50,
        };

        // cannot be updated from non-owner account
        let info = mock_info("not-the-creator", &[]);
        let res = try_update_state_params(deps.as_mut(), info, new_params.clone());
        assert_eq!(res, Err(ContractError::Unauthorized));

        // but works fine from the creator account
        let info = mock_info("creator", &[]);
        let res = try_update_state_params(deps.as_mut(), info, new_params.clone());
        assert_eq!(res, Ok(Response::default()));

        // and the state is actually updated
        let current_state = config_read(deps.as_ref().storage).load().unwrap();
        assert_eq!(current_state.params, new_params);

        // error is thrown if rewarded set is smaller than the active set
        let info = mock_info("creator", &[]);
        let mut new_params = current_state.params.clone();
        new_params.mixnode_rewarded_set_size = new_params.mixnode_active_set_size - 1;
        let res = try_update_state_params(deps.as_mut(), info, new_params.clone());
        assert_eq!(Err(ContractError::InvalidActiveSetSize), res);

        // error is thrown for 0 size rewarded set
        let info = mock_info("creator", &[]);
        let mut new_params = current_state.params.clone();
        new_params.mixnode_rewarded_set_size = 0;
        let res = try_update_state_params(deps.as_mut(), info, new_params.clone());
        assert_eq!(Err(ContractError::ZeroRewardedSet), res);

        // error is thrown for 0 size active set
        let info = mock_info("creator", &[]);
        let mut new_params = current_state.params.clone();
        new_params.mixnode_active_set_size = 0;
        let res = try_update_state_params(deps.as_mut(), info, new_params.clone());
        assert_eq!(Err(ContractError::ZeroActiveSet), res);
    }

    #[cfg(test)]
    mod delegation_stake_validation {
        use super::*;
        use cosmwasm_std::coin;

        #[test]
        fn stake_cant_be_empty() {
            assert_eq!(
                Err(ContractError::EmptyDelegation),
                validate_delegation_stake(&[])
            )
        }

        #[test]
        fn stake_must_have_single_coin_type() {
            assert_eq!(
                Err(ContractError::MultipleDenoms),
                validate_delegation_stake(&[coin(123, DENOM), coin(123, "BTC"), coin(123, "DOGE")])
            )
        }

        #[test]
        fn stake_coin_must_be_of_correct_type() {
            assert_eq!(
                Err(ContractError::WrongDenom {}),
                validate_delegation_stake(&[coin(123, "DOGE")])
            )
        }

        #[test]
        fn stake_coin_must_have_value_greater_than_zero() {
            assert_eq!(
                Err(ContractError::EmptyDelegation),
                validate_delegation_stake(&[coin(0, DENOM)])
            )
        }

        #[test]
        fn stake_can_have_any_positive_value() {
            // this might change in the future, but right now an arbitrary (positive) value can be delegated
            assert!(validate_delegation_stake(&[coin(1, DENOM)]).is_ok());
            assert!(validate_delegation_stake(&[coin(123, DENOM)]).is_ok());
            assert!(validate_delegation_stake(&[coin(10000000000, DENOM)]).is_ok());
        }
    }

    #[cfg(test)]
    mod mix_stake_delegation {
        use super::*;
        use crate::storage::mix_delegations_read;
        use crate::support::tests::helpers::add_mixnode;

        #[test]
        fn fails_if_node_doesnt_exist() {
            let mut deps = helpers::init_contract();
            assert_eq!(
                Err(ContractError::MixNodeBondNotFound {
                    identity: "non-existent-mix-identity".into()
                }),
                try_delegate_to_mixnode(
                    deps.as_mut(),
                    mock_env(),
                    mock_info("sender", &coins(123, DENOM)),
                    "non-existent-mix-identity".into(),
                )
            );
        }

        #[test]
        fn succeeds_for_existing_node() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            let delegation = coin(123, DENOM);
            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &vec![delegation.clone()]),
                identity.clone(),
            )
            .is_ok());

            assert_eq!(
                RawDelegationData::new(delegation.amount, mock_env().block.height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity.as_bytes())
                    .is_ok()
            );

            // node's "total_delegation" is increased
            assert_eq!(
                delegation.amount,
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }

        #[test]
        fn fails_if_node_unbonded() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            try_remove_mixnode(deps.as_mut(), mock_info(mixnode_owner, &[])).unwrap();

            assert_eq!(
                Err(ContractError::MixNodeBondNotFound {
                    identity: identity.clone()
                }),
                try_delegate_to_mixnode(
                    deps.as_mut(),
                    mock_env(),
                    mock_info(delegation_owner.as_str(), &coins(123, DENOM)),
                    identity,
                )
            );
        }

        #[test]
        fn succeeds_if_node_rebonded() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            try_remove_mixnode(deps.as_mut(), mock_info(mixnode_owner, &[])).unwrap();
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation = coin(123, DENOM);
            let delegation_owner = Addr::unchecked("sender");

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &vec![delegation.clone()]),
                identity.clone(),
            )
            .is_ok());

            assert_eq!(
                RawDelegationData::new(delegation.amount, mock_env().block.height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity.as_bytes())
                    .is_ok()
            );

            // node's "total_delegation" is increased
            assert_eq!(
                delegation.amount,
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }

        #[test]
        fn is_possible_for_an_already_delegated_node() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            let delegation1 = coin(100, DENOM);
            let delegation2 = coin(50, DENOM);

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &vec![delegation1.clone()]),
                identity.clone(),
            )
            .unwrap();

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &vec![delegation2.clone()]),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                RawDelegationData::new(
                    delegation1.amount + delegation2.amount,
                    mock_env().block.height,
                ),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity.as_bytes())
                    .is_ok()
            );

            // node's "total_delegation" is sum of both
            assert_eq!(
                delegation1.amount + delegation2.amount,
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }

        #[test]
        fn block_height_is_updated_on_new_delegation() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");
            let delegation = coin(100, DENOM);

            let env1 = mock_env();
            let mut env2 = mock_env();
            let initial_height = env1.block.height;
            let updated_height = initial_height + 42;
            // second env has grown in block height
            env2.block.height = updated_height;

            try_delegate_to_mixnode(
                deps.as_mut(),
                env1,
                mock_info(delegation_owner.as_str(), &vec![delegation.clone()]),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                RawDelegationData::new(delegation.amount, initial_height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );

            try_delegate_to_mixnode(
                deps.as_mut(),
                env2,
                mock_info(delegation_owner.as_str(), &vec![delegation.clone()]),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                RawDelegationData::new(delegation.amount + delegation.amount, updated_height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
        }

        #[test]
        fn block_height_is_not_updated_on_different_delegator() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner1 = Addr::unchecked("sender1");
            let delegation_owner2 = Addr::unchecked("sender2");
            let delegation1 = coin(100, DENOM);
            let delegation2 = coin(120, DENOM);

            let env1 = mock_env();
            let mut env2 = mock_env();
            let initial_height = env1.block.height;
            let second_height = initial_height + 42;
            // second env has grown in block height
            env2.block.height = second_height;

            try_delegate_to_mixnode(
                deps.as_mut(),
                env1,
                mock_info(delegation_owner1.as_str(), &vec![delegation1.clone()]),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                RawDelegationData::new(delegation1.amount, initial_height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner1.as_bytes())
                    .unwrap()
            );

            try_delegate_to_mixnode(
                deps.as_mut(),
                env2,
                mock_info(delegation_owner2.as_str(), &vec![delegation2.clone()]),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                RawDelegationData::new(delegation1.amount, initial_height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner1.as_bytes())
                    .unwrap()
            );
            assert_eq!(
                RawDelegationData::new(delegation2.amount, second_height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner2.as_bytes())
                    .unwrap()
            );
        }

        #[test]
        fn is_disallowed_for_already_delegated_node_if_it_unbonded() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(100, DENOM)),
                identity.clone(),
            )
            .unwrap();

            try_remove_mixnode(deps.as_mut(), mock_info(mixnode_owner, &[])).unwrap();

            assert_eq!(
                Err(ContractError::MixNodeBondNotFound {
                    identity: identity.clone()
                }),
                try_delegate_to_mixnode(
                    deps.as_mut(),
                    mock_env(),
                    mock_info(delegation_owner.as_str(), &coins(50, DENOM)),
                    identity,
                )
            );
        }

        #[test]
        fn is_allowed_for_multiple_nodes() {
            let mut deps = helpers::init_contract();
            let mixnode_owner1 = "bob";
            let mixnode_owner2 = "fred";
            let identity1 = add_mixnode(mixnode_owner1, good_mixnode_bond(), deps.as_mut());
            let identity2 = add_mixnode(mixnode_owner2, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(123, DENOM)),
                identity1.clone(),
            )
            .is_ok());

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(42, DENOM)),
                identity2.clone(),
            )
            .is_ok());

            assert_eq!(
                RawDelegationData::new(123u128.into(), mock_env().block.height),
                mix_delegations_read(&deps.storage, &identity1)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity1.as_bytes())
                    .is_ok()
            );

            assert_eq!(
                RawDelegationData::new(42u128.into(), mock_env().block.height),
                mix_delegations_read(&deps.storage, &identity2)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity2.as_bytes())
                    .is_ok()
            );
        }

        #[test]
        fn is_allowed_by_multiple_users() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());

            let delegation1 = coin(123, DENOM);
            let delegation2 = coin(234, DENOM);

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info("sender1", &vec![delegation1.clone()]),
                identity.clone(),
            )
            .is_ok());

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info("sender2", &vec![delegation2.clone()]),
                identity.clone(),
            )
            .is_ok());

            // node's "total_delegation" is sum of both
            assert_eq!(
                delegation1.amount + delegation2.amount,
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }

        #[test]
        fn delegation_is_not_removed_if_node_unbonded() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(100, DENOM)),
                identity.clone(),
            )
            .unwrap();

            try_remove_mixnode(deps.as_mut(), mock_info(mixnode_owner, &[])).unwrap();

            assert_eq!(
                RawDelegationData::new(100u128.into(), mock_env().block.height),
                mix_delegations_read(&deps.storage, &identity)
                    .load(delegation_owner.as_bytes())
                    .unwrap()
            );
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .load(identity.as_bytes())
                    .is_ok()
            );
        }
    }

    #[cfg(test)]
    mod removing_mix_stake_delegation {
        use super::*;
        use crate::storage::mix_delegations_read;
        use crate::support::tests::helpers::add_mixnode;

        #[test]
        fn fails_if_delegation_never_existed() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            assert_eq!(
                Err(ContractError::NoMixnodeDelegationFound {
                    identity: identity.clone(),
                    address: delegation_owner.clone(),
                }),
                try_remove_delegation_from_mixnode(
                    deps.as_mut(),
                    mock_info(delegation_owner.as_str(), &[]),
                    identity,
                )
            );
        }

        #[test]
        fn succeeds_if_delegation_existed() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(100, DENOM)),
                identity.clone(),
            )
            .unwrap();

            assert_eq!(
                Ok(Response {
                    submessages: vec![],
                    messages: vec![BankMsg::Send {
                        to_address: delegation_owner.clone().into(),
                        amount: coins(100, DENOM),
                    }
                    .into()],
                    attributes: Vec::new(),
                    data: None,
                }),
                try_remove_delegation_from_mixnode(
                    deps.as_mut(),
                    mock_info(delegation_owner.as_str(), &[]),
                    identity.clone(),
                )
            );

            assert!(mix_delegations_read(&deps.storage, &identity)
                .may_load(delegation_owner.as_bytes())
                .unwrap()
                .is_none());
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .may_load(identity.as_bytes())
                    .unwrap()
                    .is_none()
            );

            // and total delegation is cleared
            assert_eq!(
                Uint128::zero(),
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }

        #[test]
        fn succeeds_if_delegation_existed_even_if_node_unbonded() {
            let mut deps = helpers::init_contract();

            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner = Addr::unchecked("sender");

            try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner.as_str(), &coins(100, DENOM)),
                identity.clone(),
            )
            .unwrap();

            try_remove_mixnode(deps.as_mut(), mock_info(mixnode_owner, &[])).unwrap();

            assert_eq!(
                Ok(Response {
                    submessages: vec![],
                    messages: vec![BankMsg::Send {
                        to_address: delegation_owner.clone().into(),
                        amount: coins(100, DENOM),
                    }
                    .into()],
                    attributes: Vec::new(),
                    data: None,
                }),
                try_remove_delegation_from_mixnode(
                    deps.as_mut(),
                    mock_info(delegation_owner.as_str(), &[]),
                    identity.clone(),
                )
            );

            assert!(mix_delegations_read(&deps.storage, &identity)
                .may_load(delegation_owner.as_bytes())
                .unwrap()
                .is_none());
            assert!(
                reverse_mix_delegations_read(&deps.storage, &delegation_owner)
                    .may_load(identity.as_bytes())
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn total_delegation_is_preserved_if_only_some_undelegate() {
            let mut deps = helpers::init_contract();
            let mixnode_owner = "bob";
            let identity = add_mixnode(mixnode_owner, good_mixnode_bond(), deps.as_mut());
            let delegation_owner1 = Addr::unchecked("sender1");
            let delegation_owner2 = Addr::unchecked("sender2");

            let delegation1 = coin(123, DENOM);
            let delegation2 = coin(234, DENOM);

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner1.as_str(), &vec![delegation1.clone()]),
                identity.clone(),
            )
            .is_ok());

            assert!(try_delegate_to_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(delegation_owner2.as_str(), &vec![delegation2.clone()]),
                identity.clone(),
            )
            .is_ok());

            // sender1 undelegates
            try_remove_delegation_from_mixnode(
                deps.as_mut(),
                mock_info(delegation_owner1.as_str(), &[]),
                identity.clone(),
            )
            .unwrap();

            // but total delegation should still equal to what sender2 sent
            // node's "total_delegation" is sum of both
            assert_eq!(
                delegation2.amount,
                total_delegation_read(&deps.storage)
                    .load(identity.as_bytes())
                    .unwrap()
            )
        }
    }

    #[test]
    fn multiple_page_delegations() {
        let mut deps = helpers::init_contract();
        let node_identity: IdentityKey = "foo".into();

        store_n_mix_delegations(
            MIXNODE_DELEGATORS_PAGE_LIMIT as u32 * 10,
            &mut deps.storage,
            &node_identity,
        );
        let mix_bucket = all_mix_delegations_read::<RawDelegationData>(&deps.storage);
        let mix_delegations =
            Delegations::new(mix_bucket).collect::<Vec<UnpackedDelegation<RawDelegationData>>>();
        assert_eq!(
            MIXNODE_DELEGATORS_PAGE_LIMIT as u32 * 10,
            mix_delegations.len() as u32
        );
    }

    #[test]
    fn choose_layer_mix_node() {
        let mut deps = helpers::init_contract();
        for owner in ["alice", "bob"] {
            try_add_mixnode(
                deps.as_mut(),
                mock_env(),
                mock_info(owner, &good_mixnode_bond()),
                MixNode {
                    identity_key: owner.to_string(),
                    ..helpers::mix_node_fixture()
                },
            )
            .unwrap();
        }
        let bonded_mix_nodes = helpers::get_mix_nodes(&mut deps);
        let alice_node = bonded_mix_nodes.get(0).unwrap().clone();
        let bob_node = bonded_mix_nodes.get(1).unwrap().clone();
        assert_eq!(alice_node.mix_node.identity_key, "alice");
        assert_eq!(alice_node.layer, Layer::One);
        assert_eq!(bob_node.mix_node.identity_key, "bob");
        assert_eq!(bob_node.layer, Layer::Two);
    }
}