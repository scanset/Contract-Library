//! Mount Point CTN Contract
//!
//! Validates filesystem mount points and their options via `findmnt -J`.
//! Checks whether a path is a separate mount and whether it has the
//! required hardening options (nosuid, nodev, noexec, etc.).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod mount_point;
//  pub use mount_point::create_mount_point_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_mount_point_contract() -> CtnContract {
    let mut contract = CtnContract::new("mount_point".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "Filesystem mount point to inspect".to_string(),
            example_values: vec![
                "/tmp".to_string(),
                "/var".to_string(),
                "/home".to_string(),
                "/boot".to_string(),
            ],
            validation_notes: Some("Absolute path to a mount point".to_string()),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the path is a separate mount point".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "False if path is not a separate mount (e.g., part of /)".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "source".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Source device for the mount".to_string(),
            example_values: vec!["/dev/mapper/rlm-root".to_string(), "tmpfs".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "fstype".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Filesystem type".to_string(),
            example_values: vec!["xfs".to_string(), "tmpfs".to_string(), "ext4".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "options".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Full mount options string".to_string(),
            example_values: vec!["rw,nosuid,nodev,noexec,relatime".to_string()],
            validation_notes: Some("Comma-separated mount options from findmnt".to_string()),
        });

    // Derived boolean flags for each hardening option
    for (flag, desc) in &[
        ("nosuid", "nosuid flag is set"),
        ("nodev", "nodev flag is set"),
        ("noexec", "noexec flag is set"),
        ("ro", "filesystem mounted read-only"),
        ("relatime", "relatime flag is set"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: flag.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: vec![Operation::Equals, Operation::NotEqual],
                description: desc.to_string(),
                example_values: vec!["true".to_string()],
                validation_notes: Some(
                    "Derived from the options string at collection time".to_string(),
                ),
            });
    }

    // -- Field mappings -----------------------------------------------

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "source".to_string(),
        "fstype".to_string(),
        "options".to_string(),
        "nosuid".to_string(),
        "nodev".to_string(),
        "noexec".to_string(),
        "ro".to_string(),
        "relatime".to_string(),
    ];

    for field in &[
        "found", "source", "fstype", "options", "nosuid", "nodev", "noexec", "ro", "relatime",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "mount_point".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["findmnt_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(20),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
