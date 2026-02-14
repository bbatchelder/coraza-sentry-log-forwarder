import { describe, it, expect } from "vitest";
import { parseCorazaLog, parseAccessLog, type WafEvent } from "./parser.js";

describe("parseCorazaLog", () => {
  it("returns null for non-WAF log lines", () => {
    expect(parseCorazaLog("[info][main] starting")).toBeNull();
    expect(parseCorazaLog("")).toBeNull();
    expect(parseCorazaLog("[warning][config] listener binding")).toBeNull();
  });

  it("parses a Coraza WAF detection log line", () => {
    const line = `[2026-02-13T10:00:00.000Z][error][wasm] wasm log envoy-gateway-system.my-gateway coraza-waf: [client "1.2.3.4"] Coraza: Warning. Matched "Operator \`Rx' with param \`(?i:(?:select|grant).*(?:from|to|using)|(?:insert\\s+into|update.*set|delete\\s+from))' at ARGS:id. [file "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "60"] [id "942100"] [rev ""] [msg "SQL Injection Attack Detected via libinjection - SQL Tautology"] [data "Matched Data: 1' OR 1=1-- found within ARGS:id"] [severity "critical"] [ver "OWASP_CRS/4.14.0"] [tag "attack-sqli"] [hostname "staging.example.com"] [uri "/test?id=1' OR 1=1--"] [unique_id "abc123"]`;

    const result = parseCorazaLog(line);
    expect(result).not.toBeNull();
    expect(result!.ruleId).toBe("942100");
    expect(result!.message).toBe(
      "SQL Injection Attack Detected via libinjection - SQL Tautology"
    );
    expect(result!.clientIp).toBe("1.2.3.4");
    expect(result!.uri).toBe("/test?id=1' OR 1=1--");
    expect(result!.severity).toBe("critical");
    expect(result!.hostname).toBe("staging.example.com");
    expect(result!.matchedData).toBe(
      "Matched Data: 1' OR 1=1-- found within ARGS:id"
    );
    expect(result!.action).toBe("detect");
    expect(result!.uniqueId).toBe("abc123");
  });

  it("parses a Coraza WAF block (interruption) log line", () => {
    const line = `[2026-02-13T10:00:00.000Z][error][wasm] wasm log envoy-gateway-system.my-gateway coraza-waf: [client "5.6.7.8"] Coraza: Access denied (phase 2). Matched "Operator \`Rx' ..." [id "942100"] [msg "SQL Injection Attack Detected"] [data ""] [severity "critical"] [hostname "staging.example.com"] [uri "/api/foo"]`;

    const result = parseCorazaLog(line);
    expect(result).not.toBeNull();
    expect(result!.action).toBe("block");
    expect(result!.clientIp).toBe("5.6.7.8");
  });

  it("handles missing optional fields gracefully", () => {
    const line = `[error][wasm] wasm log envoy-gateway-system.my-gateway coraza-waf: [client "1.2.3.4"] Coraza: Warning. [id "920420"] [msg "Request content type not allowed"]`;

    const result = parseCorazaLog(line);
    expect(result).not.toBeNull();
    expect(result!.ruleId).toBe("920420");
    expect(result!.message).toBe("Request content type not allowed");
    expect(result!.clientIp).toBe("1.2.3.4");
    expect(result!.uri).toBeUndefined();
    expect(result!.matchedData).toBeUndefined();
    expect(result!.hostname).toBeUndefined();
    expect(result!.severity).toBeUndefined();
    expect(result!.uniqueId).toBeUndefined();
  });

  it("extracts CRS version tag when present", () => {
    const line = `[error][wasm] wasm log envoy-gateway-system.my-gateway coraza-waf: [client "1.2.3.4"] Coraza: Warning. [id "941100"] [msg "XSS Attack Detected"] [ver "OWASP_CRS/4.14.0"] [uri "/q"]`;

    const result = parseCorazaLog(line);
    expect(result).not.toBeNull();
    expect(result!.crsVersion).toBe("OWASP_CRS/4.14.0");
  });
});

describe("parseAccessLog", () => {
  it("returns null for non-JSON lines", () => {
    expect(parseAccessLog("[error][wasm] some log line")).toBeNull();
    expect(parseAccessLog("")).toBeNull();
    expect(parseAccessLog("plain text")).toBeNull();
  });

  it("parses a JSON access log line with :authority", () => {
    const line = JSON.stringify({
      ":authority": "staging.example.com",
      "x-envoy-origin-path": "/?id=1' OR 1=1--",
      response_code: 403,
      method: "GET",
    });

    const result = parseAccessLog(line);
    expect(result).not.toBeNull();
    expect(result!.authority).toBe("staging.example.com");
    expect(result!.path).toBe("/?id=1' OR 1=1--");
    expect(result!.responseCode).toBe(403);
  });

  it("parses production hostname", () => {
    const line = JSON.stringify({
      ":authority": "app.example.com",
      "x-envoy-origin-path": "/api/teams",
      response_code: 200,
    });

    const result = parseAccessLog(line);
    expect(result).not.toBeNull();
    expect(result!.authority).toBe("app.example.com");
    expect(result!.path).toBe("/api/teams");
    expect(result!.responseCode).toBe(200);
  });

  it("handles missing path gracefully", () => {
    const line = JSON.stringify({
      ":authority": "staging.example.com",
      response_code: 200,
    });

    const result = parseAccessLog(line);
    expect(result).not.toBeNull();
    expect(result!.path).toBe("");
  });

  it("returns null for missing authority", () => {
    const line = JSON.stringify({
      response_code: 200,
      "x-envoy-origin-path": "/test",
    });

    const result = parseAccessLog(line);
    expect(result).toBeNull();
  });

  it("returns null for missing response_code", () => {
    const line = JSON.stringify({
      ":authority": "staging.example.com",
      "x-envoy-origin-path": "/test",
    });

    const result = parseAccessLog(line);
    expect(result).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    expect(parseAccessLog("{invalid json")).toBeNull();
  });
});
