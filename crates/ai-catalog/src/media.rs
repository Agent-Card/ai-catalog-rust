// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Known catalog-entry media types from the AI Catalog specification
//! (<https://ai-catalog.io/spec/#catalog-entry>).
pub const MEDIA_TYPE_CATALOG: &str = "application/ai-catalog+json";
pub const MEDIA_TYPE_AGENT_CARD: &str = "application/agent-card+json";
pub const MEDIA_TYPE_A2A_AGENT_CARD: &str = "application/a2a-agent-card+json";
pub const MEDIA_TYPE_MCP_SERVER_CARD: &str = "application/mcp-server-card+json";
pub const MEDIA_TYPE_AGENT_SKILLS_JSON: &str = "application/agent-skills+json";
pub const MEDIA_TYPE_AGENT_SKILLS_MARKDOWN: &str = "application/agent-skills+md";
pub const MEDIA_TYPE_AGENT_SKILLS_ZIP: &str = "application/agent-skills+zip";
pub const MEDIA_TYPE_AGENT_SKILLS_GZIP: &str = "application/agent-skills+gzip";
pub const MEDIA_TYPE_AGENT_PLUGINS_ZIP: &str = "application/agent-plugins+zip";
pub const MEDIA_TYPE_AGENT_PLUGINS_GZIP: &str = "application/agent-plugins+gzip";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_media_types_match_spec() {
        assert_eq!(MEDIA_TYPE_CATALOG, "application/ai-catalog+json");
        assert_eq!(MEDIA_TYPE_AGENT_CARD, "application/agent-card+json");
        assert_eq!(MEDIA_TYPE_A2A_AGENT_CARD, "application/a2a-agent-card+json");
        assert_eq!(
            MEDIA_TYPE_MCP_SERVER_CARD,
            "application/mcp-server-card+json"
        );
        assert_eq!(
            MEDIA_TYPE_AGENT_SKILLS_JSON,
            "application/agent-skills+json"
        );
        assert_eq!(
            MEDIA_TYPE_AGENT_SKILLS_MARKDOWN,
            "application/agent-skills+md"
        );
        assert_eq!(MEDIA_TYPE_AGENT_SKILLS_ZIP, "application/agent-skills+zip");
        assert_eq!(
            MEDIA_TYPE_AGENT_SKILLS_GZIP,
            "application/agent-skills+gzip"
        );
        assert_eq!(
            MEDIA_TYPE_AGENT_PLUGINS_ZIP,
            "application/agent-plugins+zip"
        );
        assert_eq!(
            MEDIA_TYPE_AGENT_PLUGINS_GZIP,
            "application/agent-plugins+gzip"
        );
    }
}
