export interface WafEvent {
  ruleId: string;
  message: string;
  clientIp: string;
  action: "detect" | "block";
  uri?: string;
  hostname?: string;
  severity?: string;
  matchedData?: string;
  crsVersion?: string;
  uniqueId?: string;
  tags?: string[];
  attackCategory?: string;
}

export interface AccessLogEntry {
  authority: string;
  path: string;
  responseCode: number;
}

const CORAZA_MARKER = "coraza-waf";
const BLOCK_PATTERN = /Access denied/;
const TAG_PATTERN = /\[tag "([^"]+)"\]/g;

// CRS rule ID prefix → attack category fallback (when no attack-* tag is present)
const RULE_ID_CATEGORY: Record<string, string> = {
  "920": "protocol-violation",
  "921": "protocol-attack",
  "930": "lfi",
  "931": "rfi",
  "932": "rce",
  "933": "injection-php",
  "934": "injection-nodejs",
  "941": "xss",
  "942": "sqli",
  "943": "session-fixation",
  "944": "java-attack",
};

const FIELD_PATTERNS: Record<string, RegExp> = {
  ruleId: /\[id "([^"]+)"\]/,
  message: /\[msg "([^"]+)"\]/,
  clientIp: /\[client "([^"]+)"\]/,
  uri: /\[uri "([^"]+)"\]/,
  hostname: /\[hostname "([^"]+)"\]/,
  severity: /\[severity "([^"]+)"\]/,
  matchedData: /\[data "([^"]+)"\]/,
  crsVersion: /\[ver "([^"]+)"\]/,
  uniqueId: /\[unique_id "([^"]+)"\]/,
};

export function parseCorazaLog(line: string): WafEvent | null {
  const lowerLine = line.toLowerCase();
  if (!lowerLine.includes(CORAZA_MARKER)) return null;

  const ruleMatch = line.match(FIELD_PATTERNS.ruleId);
  if (!ruleMatch) return null;

  const msgMatch = line.match(FIELD_PATTERNS.message);
  const clientMatch = line.match(FIELD_PATTERNS.clientIp);
  if (!clientMatch) return null;

  const event: WafEvent = {
    ruleId: ruleMatch[1],
    message: msgMatch?.[1] ?? "Unknown",
    clientIp: clientMatch[1],
    action: BLOCK_PATTERN.test(line) ? "block" : "detect",
  };

  const uriMatch = line.match(FIELD_PATTERNS.uri);
  if (uriMatch) event.uri = uriMatch[1];

  const hostMatch = line.match(FIELD_PATTERNS.hostname);
  if (hostMatch) event.hostname = hostMatch[1];

  const sevMatch = line.match(FIELD_PATTERNS.severity);
  if (sevMatch) event.severity = sevMatch[1];

  const dataMatch = line.match(FIELD_PATTERNS.matchedData);
  if (dataMatch && dataMatch[1]) event.matchedData = dataMatch[1];

  const verMatch = line.match(FIELD_PATTERNS.crsVersion);
  if (verMatch && verMatch[1]) event.crsVersion = verMatch[1];

  const uidMatch = line.match(FIELD_PATTERNS.uniqueId);
  if (uidMatch) event.uniqueId = uidMatch[1];

  // Extract all [tag "..."] values
  const tags: string[] = [];
  for (const m of line.matchAll(TAG_PATTERN)) {
    tags.push(m[1]);
  }
  if (tags.length > 0) {
    event.tags = tags;
    // Derive attack category from the first "attack-*" tag
    const attackTag = tags.find((t) => t.startsWith("attack-"));
    if (attackTag) {
      event.attackCategory = attackTag.slice("attack-".length);
    }
  }

  // Fallback: derive category from rule ID prefix if no attack-* tag was found
  if (!event.attackCategory) {
    const prefix = event.ruleId.slice(0, 3);
    const category = RULE_ID_CATEGORY[prefix];
    if (category) event.attackCategory = category;
  }

  return event;
}

export function parseAccessLog(line: string): AccessLogEntry | null {
  // Access logs are JSON objects starting with {
  if (!line.startsWith("{")) return null;

  try {
    const obj = JSON.parse(line);
    const authority = obj[":authority"];
    const path = obj["x-envoy-origin-path"];
    const responseCode = obj["response_code"];

    if (typeof authority !== "string" || typeof responseCode !== "number") {
      return null;
    }

    return { authority, path: path ?? "", responseCode };
  } catch {
    return null;
  }
}
