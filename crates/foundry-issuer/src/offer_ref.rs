//! Persistence for Credential Offers delivered **by reference**
//! (OpenID4VCI 1.0 §4.2, L432-L452).
//!
//! A by-reference offer is stored at `create_offer` time and served verbatim to
//! the wallet by `GET /credential-offer/:id`. It is kept as the already-rendered
//! `CredentialOffer` rather than rebuilt on demand, which is the opposite choice
//! from `foundry-verifier`'s `/vp/request/:id` — and deliberately so:
//!
//! - A Request Object **must** be rebuilt, because it is signed and its `exp`
//!   moves. An offer is a fixed document; once created it must not change.
//! - Rebuilding would need `offer_display` persisted on the `IssuanceTransaction`,
//!   which `transaction.rs` deliberately drops ("the offer-stage object is
//!   consumed while building the `CredentialOffer` and never read again"), plus a
//!   second copy of the grant-construction logic. Two drift sources for no gain.
//!
//! **The stored value contains the `pre-authorized_code`.** The key addressing
//! it is therefore a bearer credential — see [`crate::generate_offer_id`] — and
//! neither key nor value may ever be logged (root AGENTS.md §4.5).

use crate::error::IssuanceError;
use crate::offer::CredentialOffer;
use foundry_core::storage::Storage;

/// KV namespace for offers served by reference, keyed by offer id.
///
/// Distinct from `transaction.rs`'s `issuance_tx` and its secondary indices: a
/// row here maps an offer id to an offer *document*, not to a transaction id.
const OFFER_REF_NS: &str = "offer_ref";

/// Persist `offer` under `offer_id` with a TTL relative to `now_unix`.
///
/// `ttl_secs` is the caller's `storage.transaction_ttl_secs`, so the offer stops
/// being *fetchable* exactly when it stops being *redeemable*. A shorter TTL
/// would strand a wallet holding a live link; a longer one would keep serving a
/// `pre-authorized_code` whose transaction has already been purged.
pub async fn save_offer_by_reference(
    storage: &dyn Storage,
    offer_id: &str,
    offer: &CredentialOffer,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let value =
        serde_json::to_string(offer).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(OFFER_REF_NS, offer_id, &value, Some(expires_at))
        .await?;
    Ok(())
}

/// Load the offer stored under `offer_id`, if present and not yet
/// expired/purged.
///
/// Repeatable until the TTL elapses, deliberately: a dropped connection or a
/// wallet retry must not destroy the offer. Single-use-ness belongs to the
/// `pre-authorized_code` inside it (OpenID4VCI L396), which `/token` invalidates
/// on redemption — not to the fetch.
pub async fn load_offer_by_reference(
    storage: &dyn Storage,
    offer_id: &str,
) -> Result<Option<CredentialOffer>, IssuanceError> {
    match storage.get_kv(OFFER_REF_NS, offer_id).await? {
        Some(s) => {
            let offer = serde_json::from_str(&s)
                .map_err(|e| IssuanceError::Deserialization(e.to_string()))?;
            Ok(Some(offer))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offer::{CredentialOfferGrants, PreAuthorizedCodeGrant, TxCodeDefinition};
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        // Leak the tempdir so the file isn't removed before the async test body
        // runs -- same idiom as transaction.rs's tests.
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["com.emvco.dpc.card".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "code-123".to_string(),
                    tx_code: Some(TxCodeDefinition {
                        input_mode: "numeric".to_string(),
                        length: 4,
                    }),
                }),
                authorization_code: None,
            },
            display: Some(vec![serde_json::json!({
                "locale": "en-US",
                "card": { "type": { "code": "CREDIT" } }
            })]),
        }
    }

    #[tokio::test]
    async fn an_offer_round_trips_through_storage() {
        let storage = test_storage().await;
        let offer = sample_offer();
        save_offer_by_reference(&storage, "offer-id-1", &offer, 600, 1_700_000_000)
            .await
            .unwrap();

        let loaded = load_offer_by_reference(&storage, "offer-id-1")
            .await
            .unwrap()
            .expect("the offer must be fetchable");
        assert_eq!(loaded.credential_issuer, offer.credential_issuer);
        assert_eq!(
            loaded
                .grants
                .pre_authorized_code
                .expect("the grant survives the round trip")
                .pre_authorized_code,
            "code-123"
        );
    }

    /// The display metadata is the whole reason by-reference delivery exists, so
    /// it must survive storage verbatim rather than being dropped in transit.
    #[tokio::test]
    async fn display_metadata_survives_the_round_trip() {
        let storage = test_storage().await;
        save_offer_by_reference(&storage, "offer-id-2", &sample_offer(), 600, 1_700_000_000)
            .await
            .unwrap();

        let loaded = load_offer_by_reference(&storage, "offer-id-2")
            .await
            .unwrap()
            .unwrap();
        let display = loaded.display.expect("display metadata is preserved");
        assert_eq!(display[0]["card"]["type"]["code"], "CREDIT");
    }

    #[tokio::test]
    async fn an_unknown_offer_id_is_none_rather_than_an_error() {
        let storage = test_storage().await;
        let loaded = load_offer_by_reference(&storage, "no-such-offer")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    /// The offer must stop being fetchable when its TTL elapses -- otherwise a
    /// `pre-authorized_code` outlives the transaction it belongs to.
    #[tokio::test]
    async fn an_expired_offer_is_no_longer_fetchable() {
        let storage = test_storage().await;
        let now = 1_700_000_000;
        save_offer_by_reference(&storage, "offer-id-3", &sample_offer(), 600, now)
            .await
            .unwrap();

        // One second past expiry.
        foundry_core::storage::Storage::purge_expired(&storage, now + 601)
            .await
            .unwrap();

        let loaded = load_offer_by_reference(&storage, "offer-id-3")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    /// Fetching does not consume: the `pre-authorized_code` inside is the
    /// single-use secret, not the retrieval.
    #[tokio::test]
    async fn fetching_an_offer_twice_succeeds() {
        let storage = test_storage().await;
        save_offer_by_reference(&storage, "offer-id-4", &sample_offer(), 600, 1_700_000_000)
            .await
            .unwrap();

        assert!(
            load_offer_by_reference(&storage, "offer-id-4")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            load_offer_by_reference(&storage, "offer-id-4")
                .await
                .unwrap()
                .is_some()
        );
    }
}
