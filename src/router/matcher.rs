//! URL pattern matching for route-based credential detection

use glob::Pattern;
use std::collections::HashMap;

/// URL pattern matcher for auto-detecting credentials
pub struct UrlMatcher {
    /// Patterns mapped to credential aliases
    patterns: Vec<(Pattern, String)>,
}

impl UrlMatcher {
    /// Create a new URL matcher
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add a pattern that maps to a credential alias
    pub fn add_pattern(&mut self, pattern: &str, credential_alias: &str) -> Result<(), String> {
        let glob = Pattern::new(pattern).map_err(|e| e.to_string())?;
        self.patterns.push((glob, credential_alias.to_string()));
        Ok(())
    }

    /// Find a credential alias for a URL
    pub fn match_url(&self, url: &str) -> Option<&str> {
        for (pattern, alias) in &self.patterns {
            if pattern.matches(url) {
                return Some(alias);
            }
        }
        None
    }

    /// Load patterns from a map
    pub fn load_patterns(&mut self, patterns: HashMap<String, String>) {
        for (pattern, alias) in patterns {
            if let Ok(glob) = Pattern::new(&pattern) {
                self.patterns.push((glob, alias));
            }
        }
    }
}

impl Default for UrlMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_matching() {
        let mut matcher = UrlMatcher::new();
        matcher
            .add_pattern("https://api.github.com/*", "github-api")
            .unwrap();
        matcher
            .add_pattern("https://api.openai.com/*", "openai-api")
            .unwrap();

        assert_eq!(
            matcher.match_url("https://api.github.com/user"),
            Some("github-api")
        );
        assert_eq!(
            matcher.match_url("https://api.github.com/repos/foo/bar"),
            Some("github-api")
        );
        assert_eq!(
            matcher.match_url("https://api.openai.com/v1/chat"),
            Some("openai-api")
        );
        assert_eq!(matcher.match_url("https://api.example.com/test"), None);
    }

    #[test]
    fn test_pattern_priority() {
        let mut matcher = UrlMatcher::new();
        // More specific pattern first
        matcher
            .add_pattern("https://api.github.com/repos/*", "github-repos")
            .unwrap();
        matcher
            .add_pattern("https://api.github.com/*", "github-api")
            .unwrap();

        // First matching pattern wins
        assert_eq!(
            matcher.match_url("https://api.github.com/repos/foo"),
            Some("github-repos")
        );
        assert_eq!(
            matcher.match_url("https://api.github.com/user"),
            Some("github-api")
        );
    }
}
