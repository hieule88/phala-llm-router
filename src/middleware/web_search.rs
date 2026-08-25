//! Backend web search for non-streaming clients.
//!
//! A client opts in PER REQUEST with a top-level `"web_search": true` flag in
//! the chat body (the flag is client-signed and receipt-committed like the
//! rest of the request, so the opt-in itself is auditable). The upstream's
//! server-side search tool (`web_context_search`) only runs on streamed chat
//! completions, so for a non-streaming client the gateway:
//!
//!   1. strips the flag, injects the search tool, and forces `stream: true`
//!      on the UPSTREAM request only;
//!   2. buffers the upstream SSE stream to completion;
//!   3. aggregates it back into one ordinary `chat.completion` JSON, adding a
//!      `web_searches` array that lists EVERY query the model sent out of the
//!      enclave to the search service — the user sees exactly what egressed.
//!
//! Receipt semantics stay honest for free: `response.received` commits to the
//! raw upstream SSE bytes, `response.returned` commits to the aggregated JSON
//! (including the disclosure), and the automatic `transparency.response_modified`
//! event records that the gateway reshaped the body.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Top-level request field a client sets to opt into web search.
pub(super) const REQUEST_FLAG: &str = "web_search";

/// The upstream server-side search tool this gateway speaks.
const TOOL_TYPE: &str = "web_context_search";

/// Remove the opt-in flag from the request params and report whether it was
/// set to exactly `true`. Always stripped: the upstream never sees the flag.
pub(super) fn take_request_flag(params: &mut Value) -> bool {
    params
        .as_object_mut()
        .and_then(|obj| obj.remove(REQUEST_FLAG))
        .is_some_and(|v| v == Value::Bool(true))
}

/// Shape the params for a search-capable upstream call: add the server-side
/// search tool (idempotent) and force upstream streaming, which the tool
/// requires on chat completions. Downstream buffering is the caller's job.
pub(super) fn prepare_upstream_params(params: &mut Value) {
    let Some(obj) = params.as_object_mut() else {
        return;
    };
    let tools = obj.entry("tools".to_string()).or_insert_with(|| json!([]));
    if !tools.is_array() {
        *tools = json!([]);
    }
    let arr = tools.as_array_mut().expect("tools coerced to array above");
    let already = arr
        .iter()
        .any(|t| t.get("type").and_then(Value::as_str) == Some(TOOL_TYPE));
    if !already {
        arr.push(json!({ "type": TOOL_TYPE }));
    }
    obj.insert("stream".to_string(), Value::Bool(true));
}

/// System note telling the model the opt-in already happened. Without it,
/// models conditioned by the operator prompt to treat search as usually-absent
/// keep asking the user to "enable web search" even while the tool sits in the
/// request (observed with gpt-oss-120b).
const ENABLED_NOTE: &str = "Web search is ENABLED for this request: the user \
already opted in through their client, so never ask them to enable it. Use the \
web search tool directly whenever the answer needs current or post-cutoff \
information. Treat prices, market data, tickers, news, and questions about \
entities or terms that might postdate your training as needing a search — \
search FIRST instead of answering from possibly stale knowledge. If earlier \
replies in this conversation were written without search (guessing, or saying \
you cannot browse), do not restate them — verify with a fresh search now. The \
search budget is small: run at most two focused searches, then answer from \
whatever they returned — a partial answer with sources beats an empty one. \
Keep queries generic — no confidential details from the conversation — and \
tell the user what you searched.";

/// Roles that may lead a chat as instructions; the note goes right after them.
const LEADING_ROLES: [&str; 2] = ["system", "developer"];

/// Tell the model, in-band, that search is already on. When the chat opens
/// with a system/developer message (the operator default prompt or a
/// client-supplied one), the note is APPENDED to that message's string content
/// rather than added as a second system entry: several serving templates
/// (observed: NEAR's Qwen 3.5/3.6/3.8 — "System message must be at the
/// beginning") reject more than one system message, and merging composes with
/// every template that accepts one. A fresh system message is inserted only
/// when the chat has none, and non-string leading content (block arrays) falls
/// back to inserting AFTER the leading block — imperfect for strict templates,
/// but never corrupts the client's structured content. Upstream-only, like
/// every other transform here: the receipt's `request.received` hash was fixed
/// to the client's exact bytes before this runs.
pub(super) fn inject_enabled_note(params: &mut Value) {
    let Some(messages) = params.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    let leading = messages
        .iter()
        .take_while(|m| {
            m.get("role")
                .and_then(Value::as_str)
                .is_some_and(|r| LEADING_ROLES.contains(&r))
        })
        .count();
    if leading > 0 {
        if let Some(Value::String(content)) = messages[0].get_mut("content") {
            content.push_str("\n\n");
            content.push_str(ENABLED_NOTE);
            return;
        }
        messages.insert(leading, json!({ "role": "system", "content": ENABLED_NOTE }));
        return;
    }
    messages.insert(0, json!({ "role": "system", "content": ENABLED_NOTE }));
}

/// Fold a complete upstream SSE stream back into one `chat.completion` JSON.
///
/// Collected per chunk: `delta.content` / `delta.reasoning_content` are
/// concatenated, `delta.tool_calls[].function.arguments` are accumulated per
/// tool-call index (arguments may arrive split across chunks), the last
/// non-null `finish_reason` wins, and the final `usage` object is kept.
///
/// The result carries a `web_searches` array — one entry per search query the
/// model composed. That text is exactly what left the enclave for the search
/// service, surfaced so the end user can see (and, via the receipt, prove) it.
///
/// Returns `None` when the bytes contain no parseable SSE chunk at all.
pub(super) fn aggregate_stream(sse: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(sse);
    let mut id: Option<Value> = None;
    let mut model: Option<Value> = None;
    let mut created: Option<Value> = None;
    let mut usage: Option<Value> = None;
    let mut finish: Option<String> = None;
    let mut content = String::new();
    let mut reasoning = String::new();
    // One accumulator per tool CALL, in stream order. Sequential server-side
    // search rounds reuse index 0, so the index alone cannot key the map: a
    // chunk carrying an `id` or `function.name` starts a new call, and
    // `current_slot` remembers which accumulator each index is appending to.
    let mut tool_args: Vec<String> = Vec::new();
    let mut current_slot: BTreeMap<u64, usize> = BTreeMap::new();
    let mut saw_chunk = false;

    for line in text.lines() {
        let line = line.trim();
        let Some(payload) = line.strip_prefix("data:") else {
            continue; // SSE comments / keepalives / blank separators
        };
        let payload = payload.trim();
        if payload == "[DONE]" {
            continue;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        saw_chunk = true;
        if id.is_none() {
            id = chunk.get("id").filter(|v| !v.is_null()).cloned();
        }
        if model.is_none() {
            model = chunk.get("model").filter(|v| !v.is_null()).cloned();
        }
        if created.is_none() {
            created = chunk.get("created").filter(|v| !v.is_null()).cloned();
        }
        if let Some(u) = chunk.get("usage").filter(|v| !v.is_null()) {
            usage = Some(u.clone());
        }
        for choice in chunk
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                finish = Some(reason.to_string());
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(piece) = delta.get("content").and_then(Value::as_str) {
                content.push_str(piece);
            }
            if let Some(piece) = delta.get("reasoning_content").and_then(Value::as_str) {
                reasoning.push_str(piece);
            }
            for tc in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let index = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
                let starts_new_call = tc.get("id").and_then(Value::as_str).is_some()
                    || tc
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .is_some();
                if starts_new_call || !current_slot.contains_key(&index) {
                    current_slot.insert(index, tool_args.len());
                    tool_args.push(String::new());
                }
                if let Some(piece) = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                {
                    tool_args[current_slot[&index]].push_str(piece);
                }
            }
        }
    }
    if !saw_chunk {
        return None;
    }

    let web_searches: Vec<Value> = tool_args
        .iter()
        .filter(|args| !args.trim().is_empty())
        .flat_map(|args| parse_query_disclosures(args))
        .collect();

    let mut message = json!({ "role": "assistant", "content": content });
    if !reasoning.is_empty() {
        message["reasoning_content"] = Value::String(reasoning);
    }
    let mut out = json!({
        "id": id.unwrap_or_else(|| json!("chatcmpl-websearch")),
        "object": "chat.completion",
        "created": created.unwrap_or(Value::Null),
        "model": model.unwrap_or(Value::Null),
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish.map(Value::String).unwrap_or(Value::Null),
        }],
        "web_searches": web_searches,
    });
    if let Some(u) = usage {
        out["usage"] = u;
    }
    Some(out)
}

/// Turn one accumulated arguments buffer into disclosure entries. Usually one
/// `{"query": "..."}` object; a buffer holding several concatenated objects
/// (seen when an upstream reuses tool_call ids across rounds) yields one entry
/// per object. Anything unparseable is surfaced verbatim as `{"raw": ...}` —
/// the user must always see exactly what egressed.
fn parse_query_disclosures(args: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for item in serde_json::Deserializer::from_str(args).into_iter::<Value>() {
        match item {
            Ok(v) => out.push(
                v.get("query")
                    .and_then(Value::as_str)
                    .map(|q| json!({ "query": q }))
                    .unwrap_or_else(|| json!({ "raw": v.to_string() })),
            ),
            Err(_) => return vec![json!({ "raw": args })],
        }
    }
    if out.is_empty() {
        out.push(json!({ "raw": args }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_is_taken_and_stripped() {
        let mut on = json!({"model": "m", "web_search": true});
        assert!(take_request_flag(&mut on));
        assert!(on.get("web_search").is_none());

        let mut off = json!({"model": "m", "web_search": false});
        assert!(!take_request_flag(&mut off));
        assert!(off.get("web_search").is_none()); // stripped either way

        let mut absent = json!({"model": "m"});
        assert!(!take_request_flag(&mut absent));

        // Truthy-but-not-true values do not enable a privacy-relevant feature.
        let mut stringy = json!({"web_search": "true"});
        assert!(!take_request_flag(&mut stringy));
    }

    #[test]
    fn prepare_adds_tool_and_stream_idempotently() {
        let mut params = json!({"model": "m", "messages": []});
        prepare_upstream_params(&mut params);
        prepare_upstream_params(&mut params); // idempotent
        assert_eq!(params["stream"], json!(true));
        let tools = params["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], json!("web_context_search"));

        // A client-supplied function tool is preserved alongside.
        let mut with_fn = json!({"tools": [{"type": "function", "function": {"name": "f"}}]});
        prepare_upstream_params(&mut with_fn);
        assert_eq!(with_fn["tools"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn enabled_note_merges_into_the_leading_system_message() {
        // A leading system message absorbs the note — templates like NEAR's
        // Qwen builds reject a SECOND system message outright.
        let mut params = json!({"messages": [
            {"role": "system", "content": "operator prompt"},
            {"role": "user", "content": "hi"},
        ]});
        inject_enabled_note(&mut params);
        let msgs = params["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2, "no extra system message may appear");
        let merged = msgs[0]["content"].as_str().unwrap();
        assert!(merged.starts_with("operator prompt"));
        assert!(merged.contains("Web search is ENABLED"));
        assert_eq!(msgs[1]["role"], json!("user"));

        // No leading instructions → the note becomes the (single) first one.
        let mut bare = json!({"messages": [{"role": "user", "content": "hi"}]});
        inject_enabled_note(&mut bare);
        assert_eq!(bare["messages"][0]["role"], json!("system"));
        assert_eq!(bare["messages"][0]["content"], json!(ENABLED_NOTE));

        // Developer-led chats merge the same way.
        let mut dev = json!({"messages": [
            {"role": "developer", "content": "d"},
            {"role": "user", "content": "hi"},
        ]});
        inject_enabled_note(&mut dev);
        assert_eq!(dev["messages"].as_array().unwrap().len(), 2);
        assert!(dev["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("Web search is ENABLED"));

        // Structured (non-string) leading content is never corrupted: the
        // note falls back to its own message after the leading block.
        let mut blocks = json!({"messages": [
            {"role": "system", "content": [{"type": "text", "text": "op"}]},
            {"role": "user", "content": "hi"},
        ]});
        inject_enabled_note(&mut blocks);
        let msgs = blocks["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert!(msgs[0]["content"].is_array());
        assert_eq!(msgs[1]["content"], json!(ENABLED_NOTE));
    }

    #[test]
    fn aggregates_content_queries_and_usage() {
        // Mirrors the real capture shape: tool_calls (arguments split across
        // two chunks), a nearai_tool_result chunk, reasoning, content, usage.
        let sse = concat!(
            ": keepalive\n\n",
            "data: {\"id\":\"c1\",\"model\":\"gpt-oss-120b\",\"created\":5,\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"web_context_search\",\"arguments\":\"{\\\"query\\\": \\\"lithium \"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"chile 2026\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"nearai_tool_result\":{\"name\":\"web_context_search\",\"output\":\"[1] ...\"}}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"world\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n",
            "data: [DONE]\n\n",
        );
        let out = aggregate_stream(sse.as_bytes()).expect("aggregates");
        assert_eq!(out["id"], json!("c1"));
        assert_eq!(out["model"], json!("gpt-oss-120b"));
        assert_eq!(out["choices"][0]["message"]["content"], json!("Hello world"));
        assert_eq!(
            out["choices"][0]["message"]["reasoning_content"],
            json!("thinking")
        );
        assert_eq!(out["choices"][0]["finish_reason"], json!("stop"));
        assert_eq!(out["usage"]["total_tokens"], json!(12));
        // The disclosure: exactly what the model sent out, reassembled.
        assert_eq!(out["web_searches"][0]["query"], json!("lithium chile 2026"));
    }

    #[test]
    fn sequential_calls_reusing_index_zero_disclose_separately() {
        // NEAR AI streams each server-side search round as a fresh tool call
        // that reuses index 0; function.name marks the start of each round.
        let sse = concat!(
            "data: {\"id\":\"c2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"web_context_search\",\"arguments\":\"{\\\"query\\\": \\\"first \"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"topic\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"function\":{\"name\":\"web_context_search\",\"arguments\":\"{\\\"query\\\": \\\"second topic\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = aggregate_stream(sse.as_bytes()).expect("aggregates");
        let searches = out["web_searches"].as_array().unwrap();
        assert_eq!(searches.len(), 2, "{searches:?}");
        assert_eq!(searches[0]["query"], json!("first topic"));
        assert_eq!(searches[1]["query"], json!("second topic"));
    }

    #[test]
    fn concatenated_argument_objects_split_into_entries() {
        // Belt and braces: even if rounds still land in one buffer, the
        // stream deserializer splits {"query":..}{"query":..} into entries.
        let entries = parse_query_disclosures("{\"query\": \"a\"}\n{\"query\": \"b\"}");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["query"], json!("a"));
        assert_eq!(entries[1]["query"], json!("b"));

        // Unparseable tails fall back to verbatim raw.
        let raw = parse_query_disclosures("{\"query\": \"a\"}{broken");
        assert_eq!(raw.len(), 1);
        assert!(raw[0]["raw"].as_str().unwrap().contains("broken"));

        // Objects without a query field stay visible too.
        let other = parse_query_disclosures("{\"url\": \"x\"}");
        assert_eq!(other[0]["raw"], json!("{\"url\":\"x\"}"));
    }

    #[test]
    fn rejects_streams_with_no_chunks() {
        assert!(aggregate_stream(b"").is_none());
        assert!(aggregate_stream(b"not sse at all").is_none());
        assert!(aggregate_stream(b": keepalive only\n\n").is_none());
    }
}
