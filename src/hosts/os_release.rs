use std::collections::HashMap;

pub fn parse_os_release(content: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap();
        let v = v.trim().trim_matches('"').trim_matches('\'');
        fields.insert(k.trim().to_string(), v.to_string());
    }
    fields
}

pub fn identify_from_os_release(content: &str, fallback: &str) -> String {
    let fields = parse_os_release(content);
    if let Some(pretty) = fields.get("PRETTY_NAME").filter(|s| !s.is_empty()) {
        return pretty.clone();
    }
    let name = fields
        .get("NAME")
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .unwrap_or(fallback);
    let version = fields
        .get("VERSION")
        .filter(|s| !s.is_empty())
        .or_else(|| fields.get("VERSION_ID").filter(|s| !s.is_empty()))
        .map(String::as_str)
        .unwrap_or("");
    format!("{name} {version}").trim().to_string()
}
