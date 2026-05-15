//! Filesystem Scan CTN Contract
//!
//! Runs predefined `find` scans across the filesystem to detect world-writable
//! files, SUID/SGID binaries, unowned files, etc. Uses a built-in scan library
//! keyed by scan_type - arbitrary find arguments are not accepted.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod filesystem_scan;
//  pub use filesystem_scan::create_filesystem_scan_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_filesystem_scan_contract() -> CtnContract {
    let mut contract = CtnContract::new("filesystem_scan".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scan_type".to_string(),
            data_type: DataType::String,
            description: "Predefined scan type from the built-in library".to_string(),
            example_values: vec![
                "world_writable".to_string(),
                "suid_sgid".to_string(),
                "nouser".to_string(),
                "nogroup".to_string(),
                "world_writable_dirs_no_sticky".to_string(),
                "unlabeled_devices".to_string(),
            ],
            validation_notes: Some(
                "Must match a key in the scan library. Arbitrary find arguments are not accepted."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "root_path".to_string(),
            data_type: DataType::String,
            description: "Root directory to start the scan from".to_string(),
            example_values: vec!["/".to_string(), "/etc".to_string(), "/var".to_string()],
            validation_notes: Some("Defaults to / (root filesystem, stays on one device)".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "expected".to_string(),
            data_type: DataType::String,
            description: "Comma-separated list of paths expected to match".to_string(),
            example_values: vec![
                "/usr/bin/sudo,/usr/bin/passwd,/usr/bin/su".to_string(),
            ],
            validation_notes: Some(
                "Matches in this list are excluded from unexpected_count".to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the scan completed successfully".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "match_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Total number of paths matching the scan criteria".to_string(),
            example_values: vec!["0".to_string(), "10".to_string()],
            validation_notes: Some("Use match_count = 0 to assert no findings".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "unexpected_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Matches not present in the expected list".to_string(),
            example_values: vec!["0".to_string()],
            validation_notes: Some(
                "Use unexpected_count = 0 when expected paths are the only allowed matches"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "matches".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Newline-separated list of matching paths".to_string(),
            example_values: vec!["/usr/bin/sudo\n/usr/bin/passwd".to_string()],
            validation_notes: Some("Raw output from find for detailed inspection".to_string()),
        });

    // -- Field mappings -----------------------------------------------

    for field in &["scan_type", "root_path", "expected"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "match_count".to_string(),
        "unexpected_count".to_string(),
        "matches".to_string(),
    ];

    for field in &["found", "match_count", "unexpected_count", "matches"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem_scan".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["find_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(5000),
            memory_usage_mb: Some(10),
            network_intensive: false,
            cpu_intensive: true,
            requires_elevated_privileges: false,
        },
    };

    contract
}
