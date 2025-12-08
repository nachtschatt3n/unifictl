// unifictl - CLI for UniFi Site Manager API
// Copyright (C) 2024 Mathias Uhl <mathiasuhl@gmx.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! JSON schema definitions and metadata for UniFi API responses
//!
//! This module provides schema information to help AI agents understand
//! the structure and meaning of API responses.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Metadata about a field in a response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMeta {
    /// Field name
    pub name: String,
    /// Field type (string, number, boolean, array, object)
    pub field_type: String,
    /// Human-readable description
    pub description: String,
    /// Whether this field is always present
    pub required: bool,
    /// AI-relevant importance (high, medium, low)
    pub importance: Importance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Importance {
    High,
    Medium,
    Low,
}

/// Schema definition for an API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSchema {
    /// Endpoint name/identifier
    pub name: String,
    /// Description of what this endpoint returns
    pub description: String,
    /// Expected response structure
    pub fields: Vec<FieldMeta>,
    /// Common use cases for AI agents
    pub use_cases: Vec<String>,
    /// Estimated token count for typical response (useful for AI context management)
    pub typical_tokens: usize,
}

/// Schema registry for all endpoints
pub struct SchemaRegistry {
    schemas: HashMap<String, EndpointSchema>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            schemas: HashMap::new(),
        };
        registry.register_all();
        registry
    }

    pub fn get(&self, endpoint: &str) -> Option<&EndpointSchema> {
        self.schemas.get(endpoint)
    }

    fn register(&mut self, schema: EndpointSchema) {
        self.schemas.insert(schema.name.clone(), schema);
    }

    fn register_all(&mut self) {
        // Device endpoints
        self.register(EndpointSchema {
            name: "device.list".to_string(),
            description: "List all devices (APs, switches, gateways) in the network".to_string(),
            fields: vec![
                FieldMeta {
                    name: "mac".to_string(),
                    field_type: "string".to_string(),
                    description: "Device MAC address (unique identifier)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "name".to_string(),
                    field_type: "string".to_string(),
                    description: "Device name/hostname".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "model".to_string(),
                    field_type: "string".to_string(),
                    description: "Device model (e.g., UAP-AC-LR, USW-24-POE)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "type".to_string(),
                    field_type: "string".to_string(),
                    description: "Device type (uap, usw, ugw)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "state".to_string(),
                    field_type: "number".to_string(),
                    description: "Adoption state (0=offline, 1=connected, etc.)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "ip".to_string(),
                    field_type: "string".to_string(),
                    description: "Current IP address".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
                FieldMeta {
                    name: "version".to_string(),
                    field_type: "string".to_string(),
                    description: "Firmware version".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
                FieldMeta {
                    name: "uptime".to_string(),
                    field_type: "number".to_string(),
                    description: "Uptime in seconds".to_string(),
                    required: false,
                    importance: Importance::Low,
                },
            ],
            use_cases: vec![
                "Inventory management".to_string(),
                "Health monitoring".to_string(),
                "Firmware update planning".to_string(),
                "Troubleshooting connectivity".to_string(),
            ],
            typical_tokens: 500,
        });

        // Client endpoints
        self.register(EndpointSchema {
            name: "client.list".to_string(),
            description: "List all connected clients (wired and wireless)".to_string(),
            fields: vec![
                FieldMeta {
                    name: "mac".to_string(),
                    field_type: "string".to_string(),
                    description: "Client MAC address".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "hostname".to_string(),
                    field_type: "string".to_string(),
                    description: "Client hostname (if available)".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "ip".to_string(),
                    field_type: "string".to_string(),
                    description: "Current IP address".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "is_wired".to_string(),
                    field_type: "boolean".to_string(),
                    description: "Whether client is connected via ethernet".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
                FieldMeta {
                    name: "ap_mac".to_string(),
                    field_type: "string".to_string(),
                    description: "MAC address of connected AP (wireless only)".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "channel".to_string(),
                    field_type: "number".to_string(),
                    description: "WiFi channel (wireless only)".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
                FieldMeta {
                    name: "rssi".to_string(),
                    field_type: "number".to_string(),
                    description: "Signal strength in dBm (wireless only)".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "tx_bytes".to_string(),
                    field_type: "number".to_string(),
                    description: "Bytes transmitted".to_string(),
                    required: false,
                    importance: Importance::Low,
                },
                FieldMeta {
                    name: "rx_bytes".to_string(),
                    field_type: "number".to_string(),
                    description: "Bytes received".to_string(),
                    required: false,
                    importance: Importance::Low,
                },
            ],
            use_cases: vec![
                "Client troubleshooting".to_string(),
                "WiFi performance analysis".to_string(),
                "Network capacity planning".to_string(),
                "Security monitoring".to_string(),
            ],
            typical_tokens: 800,
        });

        // Event endpoints
        self.register(EndpointSchema {
            name: "event.list".to_string(),
            description: "List recent network events (connections, disconnections, alerts)"
                .to_string(),
            fields: vec![
                FieldMeta {
                    name: "_id".to_string(),
                    field_type: "string".to_string(),
                    description: "Event unique identifier".to_string(),
                    required: true,
                    importance: Importance::Low,
                },
                FieldMeta {
                    name: "key".to_string(),
                    field_type: "string".to_string(),
                    description: "Event type key (e.g., EVT_WU_Connected)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "datetime".to_string(),
                    field_type: "string".to_string(),
                    description: "Event timestamp (ISO 8601)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "msg".to_string(),
                    field_type: "string".to_string(),
                    description: "Human-readable event message".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "subsystem".to_string(),
                    field_type: "string".to_string(),
                    description: "Subsystem that generated the event (wlan, lan, etc.)".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
            ],
            use_cases: vec![
                "Troubleshooting connectivity issues".to_string(),
                "Security monitoring".to_string(),
                "Pattern detection".to_string(),
                "Historical analysis".to_string(),
            ],
            typical_tokens: 1200,
        });

        // Health endpoints
        self.register(EndpointSchema {
            name: "health.get".to_string(),
            description: "Get network health status and metrics".to_string(),
            fields: vec![
                FieldMeta {
                    name: "subsystem".to_string(),
                    field_type: "string".to_string(),
                    description: "Subsystem name (wan, lan, wlan, vpn, etc.)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "status".to_string(),
                    field_type: "string".to_string(),
                    description: "Health status (ok, warning, error)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "num_user".to_string(),
                    field_type: "number".to_string(),
                    description: "Number of active users".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
                FieldMeta {
                    name: "num_guest".to_string(),
                    field_type: "number".to_string(),
                    description: "Number of active guests".to_string(),
                    required: false,
                    importance: Importance::Medium,
                },
            ],
            use_cases: vec![
                "Overall network health check".to_string(),
                "Quick diagnostics".to_string(),
                "Monitoring dashboards".to_string(),
            ],
            typical_tokens: 300,
        });

        // Traffic/Flow endpoints
        self.register(EndpointSchema {
            name: "traffic.stats".to_string(),
            description: "Traffic statistics over time period".to_string(),
            fields: vec![
                FieldMeta {
                    name: "time".to_string(),
                    field_type: "number".to_string(),
                    description: "Timestamp (Unix milliseconds)".to_string(),
                    required: true,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "rx_bytes".to_string(),
                    field_type: "number".to_string(),
                    description: "Bytes received in this interval".to_string(),
                    required: false,
                    importance: Importance::High,
                },
                FieldMeta {
                    name: "tx_bytes".to_string(),
                    field_type: "number".to_string(),
                    description: "Bytes transmitted in this interval".to_string(),
                    required: false,
                    importance: Importance::High,
                },
            ],
            use_cases: vec![
                "Bandwidth analysis".to_string(),
                "Capacity planning".to_string(),
                "Trend analysis".to_string(),
                "Anomaly detection".to_string(),
            ],
            typical_tokens: 2000,
        });

        // Add more schemas as needed...
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Estimate token count for JSON data (rough approximation)
/// Uses ~4 characters per token as a heuristic
pub fn estimate_tokens(data: &Value) -> usize {
    let json_str = data.to_string();
    json_str.len() / 4
}

/// Summarize a response for LLM consumption
/// Returns a compact summary with key statistics
pub fn summarize_response(data: &Value, schema: Option<&EndpointSchema>) -> Value {
    let mut summary = serde_json::json!({
        "schema_available": schema.is_some(),
    });

    if let Some(schema) = schema {
        summary["endpoint"] = serde_json::json!(schema.name);
        summary["description"] = serde_json::json!(schema.description);
        summary["use_cases"] = serde_json::json!(schema.use_cases);
    }

    // Extract statistics from data
    if let Some(arr) = data.as_array() {
        summary["count"] = serde_json::json!(arr.len());
        summary["type"] = serde_json::json!("array");

        // Sample first and last item for context
        if !arr.is_empty() {
            summary["sample_first"] = arr[0].clone();
            if arr.len() > 1 {
                summary["sample_last"] = arr[arr.len() - 1].clone();
            }
        }
    } else if let Some(obj) = data.as_object() {
        summary["type"] = serde_json::json!("object");
        summary["fields"] = serde_json::json!(obj.keys().collect::<Vec<_>>());

        // Include data if object is small
        if obj.len() < 10 {
            summary["data"] = data.clone();
        }
    }

    summary["estimated_tokens"] = serde_json::json!(estimate_tokens(data));

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_registry() {
        let registry = SchemaRegistry::new();
        assert!(registry.get("device.list").is_some());
        assert!(registry.get("client.list").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_estimate_tokens() {
        let data = serde_json::json!({"key": "value"});
        let tokens = estimate_tokens(&data);
        assert!(tokens > 0);
        assert!(tokens < 10); // Should be small for this tiny object
    }

    #[test]
    fn test_summarize_array() {
        let data = serde_json::json!([
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "device1"},
            {"mac": "11:22:33:44:55:66", "name": "device2"},
        ]);
        let summary = summarize_response(&data, None);
        assert_eq!(summary["count"], 2);
        assert_eq!(summary["type"], "array");
    }
}
