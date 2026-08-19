// This software is available under the Apache-2.0 license.
// See https://www.apache.org/licenses/LICENSE-2.0.txt for full text.
//
// Copyright (c) 2024, Gluu, Inc.

//! Tests for the policy store format accepted by `CEDARLING_POLICY_STORE_LOCAL`.

use super::utils::test_helpers::create_test_unsigned_request;
use crate::{BootstrapConfig, BootstrapConfigRaw, Cedarling, EntityData, JwtConfig};
use serde::Deserialize;
use serde_json::json;
use tokio::test;

static POLICY_STORE_YAML: &str = include_str!("../../../test_files/policy-store_ok_2.yaml");

async fn cedarling_from_local_policy_store(policy_store: &str) -> Cedarling {
    let raw = BootstrapConfigRaw {
        local_policy_store: Some(policy_store.to_string()),
        ..Default::default()
    };
    let mut config: BootstrapConfig = raw.try_into().expect("bootstrap config should build");
    config.jwt_config = JwtConfig::new_without_validation();

    Cedarling::new(&config)
        .await
        .expect("cedarling should initialize from the inline policy store")
}

async fn assert_authorizes(cedarling: &Cedarling) {
    let resource = EntityData::deserialize(json!({
        "cedar_entity_mapping": {
            "entity_type": "Jans::Issue",
            "id": "random_id"
        },
        "org_id": "some_long_id",
        "country": "US"
    }))
    .expect("resource entity should deserialize");

    let principal = EntityData::deserialize(json!({
        "cedar_entity_mapping": {
            "entity_type": "Jans::TestPrincipal1",
            "id": "1"
        },
        "is_ok": true
    }))
    .expect("principal entity should deserialize");

    let request = create_test_unsigned_request(
        "Jans::Action::\"UpdateForTestPrincipals\"",
        Some(principal),
        resource,
    );

    let result = cedarling
        .authorize_unsigned(request)
        .await
        .expect("request should be parsed without errors");

    assert!(result.decision, "request result should be allowed");
}

#[test]
async fn local_policy_store_accepts_yaml() {
    let cedarling = cedarling_from_local_policy_store(POLICY_STORE_YAML).await;
    assert_authorizes(&cedarling).await;
}

#[test]
async fn local_policy_store_accepts_json() {
    let as_json: serde_json::Value =
        serde_yaml_ng::from_str(POLICY_STORE_YAML).expect("fixture should parse as YAML");
    let as_json = serde_json::to_string(&as_json).expect("fixture should re-encode as JSON");

    let cedarling = cedarling_from_local_policy_store(&as_json).await;
    assert_authorizes(&cedarling).await;
}
