use cosmwasm_std::HumanAddr;
use mixnet_contract::{Gateway, MixNode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    RegisterMixnode { mix_node: MixNode },
    UnRegisterMixnode {},
    BondGateway { gateway: Gateway },
    UnbondGateway {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetMixNodes {
        limit: Option<u32>,
        start_after: Option<HumanAddr>,
    },
    GetGateways {
        start_after: Option<HumanAddr>,
        limit: Option<u32>,
    },
    OwnsMixnode {
        address: HumanAddr,
    },
    OwnsGateway {
        address: HumanAddr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {}
