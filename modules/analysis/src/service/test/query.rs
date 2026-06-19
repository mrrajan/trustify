use crate::{
    config::AnalysisConfig,
    service::{AnalysisService, QueryOptions},
    test::escape_q,
};
use rstest::rstest;
use std::collections::HashSet;
use test_context::test_context;
use trustify_common::db::query::Query;
use trustify_test_context::TrustifyContext;

/// Ensure that the DB logic and the in-memory logic are aligned
#[test_context(TrustifyContext)]
#[rstest]
// Bare name match — exercises node branch (cpe/purl branches return Err)
#[case("A".to_string(), 1)]
// There should be not match for PURLs in default fields
#[case(escape_q("pkg:rpm/redhat/A@0.0.0?arch=src"), 0)]
// When asking for PURL, it must be found
#[case(format!("purl~{}", escape_q("pkg:rpm/redhat/A@0.0.0?arch=src")), 1)]
// When asking for PURL, it must be found, even with a partial match
#[case(format!("purl~{}", escape_q("pkg:rpm/redhat/A")), 1)]
// When searching for the PURL type, one entry must be found
#[case("purl:ty=rpm", 1)]
// Same when using the alias, or remove it
#[case("purl:type=rpm", 1)]
// By PURL name should work as well
#[case("purl:name=A", 1)]
// By CPE components, exact match
#[case("cpe:part=a&cpe:vendor=redhat&cpe:version=0.0.0", 1)]
#[test_log::test(tokio::test)]
async fn alignment(
    ctx: &TrustifyContext,
    #[case] q: String,
    #[case] num_sboms: usize,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q,
        ..Default::default()
    };

    // identify by DB query logic
    //
    // collect all sboms via a DB filter

    let sboms_a: HashSet<_> = service
        .load_graphs_query(&ctx.db, (&q).into())
        .await?
        .into_iter()
        .map(|r| r.0.to_string())
        .collect();

    // identify by in-memory logic
    //
    // Collect all SBOMs first, then process them via the in-memory implementation of the same
    // Should lead to the same number of results

    let all = service
        .load_graphs_query(&ctx.db, (&Query::default()).into())
        .await?;

    let sboms_b: HashSet<_> = service
        .run_graph_query(&q, QueryOptions::default(), &all, &ctx.db)
        .await?
        .into_iter()
        .map(|node| node.base.sbom_id)
        .collect();

    // compare

    assert_eq!(sboms_a, sboms_b, "Resulting SBOMs must be the same");
    assert_eq!(
        sboms_a.len(),
        num_sboms,
        "Number of matching SBOMs not as expected"
    );

    // done

    Ok(())
}

/// Verify that a field-qualified query targeting only node columns works
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn query_node_only_branch(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q: "name~A".to_string(),
        ..Default::default()
    };

    let sboms = service
        .load_graphs_query(&ctx.db, (&q).into())
        .await?;

    assert!(!sboms.is_empty(), "name~A should match at least one SBOM");

    Ok(())
}

/// Verify that an invalid field query produces an error via the fallback path
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn query_no_valid_columns(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q: "nonexistent_field~value".to_string(),
        ..Default::default()
    };

    let result = service
        .load_graphs_query(&ctx.db, (&q).into())
        .await;

    assert!(result.is_err(), "Unknown field should produce an error");

    Ok(())
}

/// Verify that the latest endpoint handles bare queries without panicking
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn query_latest_bare(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q: "A".to_string(),
        ..Default::default()
    };

    let result = service
        .retrieve_latest(
            &q,
            QueryOptions::default(),
            trustify_common::model::Paginated::default(),
            &ctx.db,
        )
        .await;

    assert!(result.is_ok(), "Bare query on latest endpoint should not panic");

    Ok(())
}

/// Verify that a query returning zero results does not panic
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn query_empty_result_no_panic(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q: "nonexistent_component_xyz_12345".to_string(),
        ..Default::default()
    };

    let result = service
        .retrieve_latest(
            &q,
            QueryOptions::default(),
            trustify_common::model::Paginated::default(),
            &ctx.db,
        )
        .await;

    assert!(result.is_ok(), "Empty result set should not panic");
    assert_eq!(result?.total, 0, "Should return zero results");

    Ok(())
}
