#![allow(dead_code)]
#![allow(unused_doc_comments)]

extern crate regex;
extern crate indexmap;
extern crate uuid;

extern crate serde;
extern crate serde_json;

use std::fs::File;
use std::path::{Path};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

#[derive(Debug)]
pub enum Error {
    Internal,
    InvalidFormat,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Internal => write!(f, "Internal error"),
            Error::InvalidFormat => write!(f, "Invalid format error"),
        }
    }
}

pub fn parse_operation_string(line: &str) -> Result<(&str, &str, &str), Error> {
    if let (Some(s1), Some(s2)) = (line.find('/'), line.rfind('/')) {
        let provider_namespace = &line[0..s1];
        let resource_type = &line[s1+1..s2];
        let action = &line[s2+1..];
        return Ok((provider_namespace, resource_type, action));
    }
    return Err(Error::InvalidFormat);
}

pub struct Operation {
    provider_namespace: String,
    resource_type: String,
    action: String,
}

impl Operation {
    pub fn from_str(line: &str) -> Option<Self> {
        if let Ok((provider_namespace, resource_type, action)) = parse_operation_string(line) {
            Some(Operation {
                provider_namespace: provider_namespace.to_string(),
                resource_type: resource_type.to_string(),
                action: action.to_string(),
            })
        } else {
            None
        }
    }
}

#[test]
fn test_operation_string() {
    // Operation string: <ProviderNamespace>/<ResourceType>/<Action>
    // The provider namespace is formatted as "Vendor.ProviderName"
    // The resource type can be a full path to a sub-resource ("resource/sub-resource/sub-sub-resource")
    // The action cannot be a path itself, which is why we extract it as the last path element (reverse search on '/')
    // All path elements can be potentially contain the wildcard '*' character for pattern matching

    assert_eq!(parse_operation_string("Microsoft.KeyVault/vaults/read").unwrap(),
        ("Microsoft.KeyVault", "vaults", "read"));

    assert_eq!(parse_operation_string("Microsoft.KeyVault/vaults/secrets/read").unwrap(),
        ("Microsoft.KeyVault", "vaults/secrets", "read"));

    assert_eq!(parse_operation_string("Microsoft.Compute/virtualMachines/*/read").unwrap(),
        ("Microsoft.Compute", "virtualMachines/*", "read"));
}

#[derive(Clone,PartialEq)]
pub enum SecurityPrincipalType {
    User, // individual user
    Group, // user group
    Service, // service principal
    Managed, // managed identity
}

impl SecurityPrincipalType {
    pub fn as_str(&self) -> &str {
        match self {
            &SecurityPrincipalType::User => "User",
            &SecurityPrincipalType::Group => "Group",
            &SecurityPrincipalType::Service => "Service",
            &SecurityPrincipalType::Managed => "Managed",
        }
    }
}

#[derive(Clone,PartialEq)]
pub enum ScopeLevel {
    ManagementGroup,
    Subscription,
    ResourceGroup,
    Resource,
}

impl ScopeLevel {
    pub fn as_str(&self) -> &str {
        match self {
            &ScopeLevel::ManagementGroup => "ManagementGroup",
            &ScopeLevel::Subscription => "Subscription",
            &ScopeLevel::ResourceGroup => "ResourceGroup",
            &ScopeLevel::Resource => "Resource",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RoleDefinition {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Id")]
    id: Uuid,
    #[serde(rename = "IsCustom")]
    is_custom: bool,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Actions")]
    actions: Vec<String>,
    #[serde(rename = "NotActions")]
    not_actions: Vec<String>,
    #[serde(rename = "DataActions")]
    data_actions: Vec<String>,
    #[serde(rename = "NotDataActions")]
    not_data_actions: Vec<String>,
    #[serde(rename = "AssignableScopes")]
    assignable_scopes: Vec<String>,
}

impl RoleDefinition {
    pub fn from_str(json: &str) -> Option<Self> {
        let result = serde_json::from_str(&json);
        if let Err(error) = result {
            eprintln!("failed to parse role definition: {:?}", error);
            return None;
        }
        result.ok()
    }

    pub fn from_file(path: &Path) -> Option<Self> {
        if let Ok(json_file) = File::open(path) {
            serde_json::from_reader(&json_file).ok()
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RoleAssignment {
    #[serde(rename = "RoleAssignmentId")]
    role_assignment_id: String,
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "DisplayName")]
    display_name: String,
    #[serde(rename = "SignInName")]
    sign_in_name: String,
    #[serde(rename = "RoleDefinitionName")]
    role_definition_name: String,
    #[serde(rename = "RoleDefinitionId")]
    role_definition_id: Uuid,
    #[serde(rename = "ObjectId")]
    object_id: Uuid,
    #[serde(rename = "ObjectType")]
    object_type: String,
    #[serde(rename = "CanDelegate")]
    can_delegate: bool,
}

impl RoleAssignment {
    pub fn from_str(json: &str) -> Option<Self> {
        let result = serde_json::from_str(&json);
        if let Err(error) = result {
            eprintln!("failed to parse role assignment: {:?}", error);
            return None;
        }
        result.ok()
    }

    pub fn from_file(path: &Path) -> Option<Self> {
        if let Ok(json_file) = File::open(path) {
            serde_json::from_reader(&json_file).ok()
        } else {
            None
        }
    }
}

#[test]
fn test_role_definition() {
    let role = RoleDefinition::from_str(include_str!("../data/roles/Owner.json")).unwrap();
    assert_eq!(role.name, "Owner");
    assert_eq!(role.id, Uuid::parse_str("8e3af657-a8ff-443c-a75c-2fe8c4bcb635").unwrap());
    assert_eq!(role.is_custom, false);
    assert_eq!(role.description, "Lets you manage everything, including access to resources.");
    assert_eq!(role.actions, vec!["*"]);
    assert_eq!(role.assignable_scopes, vec!["/"]);

    let role = RoleDefinition::from_str(include_str!("../data/roles/Contributor.json")).unwrap();
    assert_eq!(role.name, "Contributor");
    assert_eq!(role.id, Uuid::parse_str("b24988ac-6180-42a0-ab88-20f7382dd24c").unwrap());
    assert_eq!(role.is_custom, false);
    assert_eq!(role.description, "Lets you manage everything except access to resources.");
    assert_eq!(role.actions, vec!["*"]);
    assert_eq!(role.not_actions, vec![
        "Microsoft.Authorization/*/Delete",
        "Microsoft.Authorization/*/Write",
        "Microsoft.Authorization/elevateAccess/Action",
        "Microsoft.Blueprint/blueprintAssignments/write",
        "Microsoft.Blueprint/blueprintAssignments/delete"]);
    assert_eq!(role.assignable_scopes, vec!["/"]);

    let role = RoleDefinition::from_str(include_str!("../data/roles/Reader.json")).unwrap();
    assert_eq!(role.name, "Reader");
    assert_eq!(role.id, Uuid::parse_str("acdd72a7-3385-48ef-bd42-f606fba81ae7").unwrap());
    assert_eq!(role.is_custom, false);
    assert_eq!(role.description, "Lets you view everything, but not make any changes.");
    assert_eq!(role.actions, vec!["*/read"]);
    assert_eq!(role.assignable_scopes, vec!["/"]);

    let role = RoleDefinition::from_str(include_str!("../data/roles/Virtual Machine Administrator Login.json")).unwrap();
    assert_eq!(role.name, "Virtual Machine Administrator Login");
    assert_eq!(role.id, Uuid::parse_str("1c0163c0-47e6-4577-8991-ea5c82e286e4").unwrap());
    assert_eq!(role.is_custom, false);
    assert_eq!(role.description, "View Virtual Machines in the portal and login as administrator");
    assert_eq!(role.actions, vec![
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Network/virtualNetworks/read",
        "Microsoft.Network/loadBalancers/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Compute/virtualMachines/*/read"
    ]);
    assert_eq!(role.data_actions, vec![
        "Microsoft.Compute/virtualMachines/login/action",
        "Microsoft.Compute/virtualMachines/loginAsAdmin/action"
    ]);
    assert_eq!(role.assignable_scopes, vec!["/"]);

    let role = RoleDefinition::from_str(include_str!("../data/roles/Virtual Machine User Login.json")).unwrap();
    assert_eq!(role.name, "Virtual Machine User Login");
    assert_eq!(role.id, Uuid::parse_str("fb879df8-f326-4884-b1cf-06f3ad86be52").unwrap());
    assert_eq!(role.is_custom, false);
    assert_eq!(role.description, "View Virtual Machines in the portal and login as a regular user.");
    assert_eq!(role.actions, vec![
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Network/virtualNetworks/read",
        "Microsoft.Network/loadBalancers/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Compute/virtualMachines/*/read"
    ]);
    assert_eq!(role.data_actions, vec![
        "Microsoft.Compute/virtualMachines/login/action"
    ]);
    assert_eq!(role.assignable_scopes, vec!["/"]);
}

#[test]
fn test_role_assignment() {
    let role_assignment = RoleAssignment::from_str(include_str!("../test/role_assignment_lgriffin.json")).unwrap();
    assert_eq!(role_assignment.role_assignment_id, "/subscriptions/8c978e88-3b6b-42c4-bb42-3cb3357c7870/providers/Microsoft.Authorization/roleAssignments/10d04bc6-feae-486c-9a8a-3a95826334ec");
    assert_eq!(role_assignment.scope, "/subscriptions/8c978e88-3b6b-42c4-bb42-3cb3357c7870");
    assert_eq!(role_assignment.display_name, "Laura Griffin");
    assert_eq!(role_assignment.sign_in_name, "lgriffin@yolo.consulting");
    assert_eq!(role_assignment.role_definition_name, "Owner");
    assert_eq!(role_assignment.role_definition_id, Uuid::parse_str("8e3af657-a8ff-443c-a75c-2fe8c4bcb635").unwrap());
    assert_eq!(role_assignment.object_id, Uuid::parse_str("d5052b6c-3fb4-48de-8d13-16e608076a66").unwrap());
    assert_eq!(role_assignment.object_type, "User");
    assert_eq!(role_assignment.can_delegate, false);
}
