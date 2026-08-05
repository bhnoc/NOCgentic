/* Hunt hints for the alert-detail popup.
 *
 * The chips in that popup are clicked and sent as real queries, so the same
 * rule the starter-hint pool lives under applies here: a chip that trips a
 * guardrail renders fine, gets clicked, and answers with a silent cover — which
 * reads as a broken product. The difference is that these are built at runtime
 * from live alert fields, so the check has to run per hint rather than once in
 * a test. The regexes below are copies of the orchestrator's
 * (agents/orchestrator/main.py); if you loosen a guardrail there, loosen it here
 * and in packages/web-server/test/alertHints.test.ts too.
 *
 * Plain classic script on purpose: it loads before app.js and shares its global
 * scope. The IIFE takes the global object as an argument so the test can eval
 * the file against a sandbox instead of the real one.
 */
(function (root) {
  'use strict';

  var MAX_HUNT_HINTS = 5;

  // main.py::_RESTRICTED_OCTETS — an alert whose address sits in one of these
  // subnets is displayed (the feed already carries it) but never turned into a
  // question, because the orchestrator answers those with a cover.
  var RESTRICTED_OCTETS = [12, 13, 14, 15, 150, 152, 153, 154, 199];
  var RESTRICTED_IP_RE = /\b10\.220\.(\d{1,3})\.\d{1,3}\b/;

  // main.py::_ZONE_RE
  var ZONE_RE = /\b(registration|tools)\b/i;

  // main.py::_REFUSAL_PATTERNS
  var REFUSAL_RE = new RegExp([
    'ignore (previous|all|prior)\\s+(instructions|prompts|rules)',
    'show me your (system )?prompt',
    'what (are|is) your (instructions|system prompt|rules)',
    'you are now (dan|an ai|)',
    '(pretend|roleplay|act) (to be|as|as if)',
    'disregard the (rules|instructions)',
    'write (an? )?(exploit|phishing|malware|keylogger|virus|backdoor)',
    'how do i (hack|exploit|compromise|bypass)',
    'craft (malware|an attack|a payload)',
    'generate (phishing|malicious|exploit)',
  ].join('|'), 'i');

  // main.py::_OFFTOPIC_KW
  var OFFTOPIC_KW = [
    'write a poem', 'tell me a joke', 'recipe for', 'translate this', 'weather',
    'homework', 'what is 2+2', 'who won the', 'capital of',
  ];

  // main.py::_VENDOR_RE — the orchestrator strips its own generated hints of
  // vendor names; a hint we build from alert.source would put one straight back.
  var VENDOR_RE = new RegExp('\\b(' + [
    'palo\\s*alto', 'paloalto', 'pan-os',
    'corelight', 'zeek',
    'suricata', 'snort',
    'thousand\\s*eyes', 'thousandeyes',
    'splunk', 'cisco', 'fortinet', 'fortigate',
    'crowdstrike', 'checkpoint', 'check\\s*point',
    'partner',
  ].join('|') + ')\\b', 'i');

  // Description keyword → the phrase used in "other <topic> alerts" hints. The
  // alert text itself is never pasted into a hint: it is operator/vendor prose
  // and may carry a zone name or a product name. Only these labels are.
  var TOPICS = [
    { re: /port\s*scan|\bscanning\b|\bsyn\s+(flood|packets)\b/i, label: 'port scan' },
    { re: /beacon|\bc2\b|command\s*(and|&)\s*control/i,          label: 'C2 beacon' },
    { re: /\bdns\b|tunnel/i,                                     label: 'suspicious DNS' },
    { re: /\btor\b|exit\s*node/i,                                label: 'Tor traffic' },
    { re: /brute\s*force|credential\s*stuff|password\s*spray/i,  label: 'brute-force login' },
    { re: /exfil|data\s*(transfer|upload)/i,                     label: 'data exfiltration' },
    { re: /malware|trojan|ransom|payload|botnet/i,               label: 'malware' },
    { re: /blocklist|block\s*list|threat\s*intel|reputation|\bioc\b/i, label: 'threat-intel match' },
    { re: /lateral\s*movement/i,                                 label: 'lateral movement' },
    { re: /\bssh\b/i,                                            label: 'SSH' },
    { re: /\brdp\b/i,                                            label: 'RDP' },
    { re: /phish/i,                                              label: 'phishing' },
  ];

  var SEVERITY_WORDS = ['critical', 'high', 'medium', 'low'];

  /** True when this text is safe to render as a clickable query. */
  function alertHintIsSafe(hint) {
    var text = String(hint == null ? '' : hint);
    if (!text.trim()) return false;
    if (RESTRICTED_IP_RE.test(text) && ipIsRestricted(text.match(RESTRICTED_IP_RE)[0])) return false;
    if (ZONE_RE.test(text)) return false;
    if (REFUSAL_RE.test(text)) return false;
    if (VENDOR_RE.test(text)) return false;
    var lower = text.toLowerCase();
    for (var i = 0; i < OFFTOPIC_KW.length; i++) {
      if (lower.indexOf(OFFTOPIC_KW[i]) !== -1) return false;
    }
    return true;
  }

  function ipIsRestricted(ip) {
    var m = RESTRICTED_IP_RE.exec(String(ip || ''));
    if (!m) return false;
    var third = parseInt(m[1], 10);
    for (var i = 0; i < RESTRICTED_OCTETS.length; i++) {
      if (RESTRICTED_OCTETS[i] === third) return true;
    }
    return false;
  }

  /** An address we are willing to build a question around, or ''. */
  function huntableIp(value) {
    var ip = String(value == null ? '' : value).trim();
    if (!ip) return '';
    var isV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    var isV6 = ip.indexOf(':') !== -1 && /^[0-9a-fA-F:.]{3,45}$/.test(ip);
    if (!isV4 && !isV6) return '';
    if (isV4 && ip.split('.').some(function (o) { return parseInt(o, 10) > 255; })) return '';
    if (ipIsRestricted(ip)) return '';
    return ip;
  }

  function huntablePort(value) {
    var port = parseInt(value, 10);
    if (!isFinite(port) || port <= 0 || port > 65535) return '';
    return String(port);
  }

  function severityWord(value) {
    var sev = String(value == null ? '' : value).trim().toLowerCase();
    return SEVERITY_WORDS.indexOf(sev) === -1 ? '' : sev;
  }

  function alertTopic(description) {
    var text = String(description == null ? '' : description);
    for (var i = 0; i < TOPICS.length; i++) {
      if (TOPICS[i].re.test(text)) return TOPICS[i].label;
    }
    return '';
  }

  /** UTC minute stamp — an unambiguous anchor for "what else happened then". */
  function huntableTime(timestamp) {
    var d = new Date(timestamp);
    if (isNaN(d.getTime())) return '';
    return d.toISOString().slice(0, 16) + 'Z';
  }

  /**
   * Build up to `max` follow-up questions for one alert, most specific first.
   * Every candidate is filtered through alertHintIsSafe, so a field that would
   * produce a cover-answering chip simply yields fewer chips.
   */
  function buildAlertHuntHints(alert, max) {
    var a = alert || {};
    var limit = typeof max === 'number' && isFinite(max) ? Math.floor(max) : MAX_HUNT_HINTS;
    if (limit <= 0) return [];

    var src = huntableIp(a.srcIp);
    var dst = huntableIp(a.dstIp);
    var port = huntablePort(a.dstPort);
    var sev = severityWord(a.severity);
    var topic = alertTopic(a.description);
    var when = huntableTime(a.timestamp);

    var candidates = [];
    if (src) candidates.push('Show all network activity from ' + src + ' in the last hour');
    if (src && dst) candidates.push('Show every session between ' + src + ' and ' + dst);
    if (dst) candidates.push('What other hosts connected to ' + dst + ' in the last 24 hours?');
    if (src) candidates.push('Has ' + src + ' triggered any other alerts today?');
    if (port) candidates.push('Which hosts are sending traffic on port ' + port + ' right now?');
    if (topic) candidates.push('Are there other ' + topic + ' alerts in the last 24 hours?');
    if (src) candidates.push('Is ' + src + ' talking to any known bad infrastructure?');
    if (sev) candidates.push('Show me every ' + sev + ' severity alert from the last hour');
    if (when) candidates.push('What else was happening on the network around ' + when + '?');
    candidates.push('How serious is this alert and what should we check next?');
    candidates.push('Is this a one-off or part of a larger pattern?');

    var out = [];
    for (var i = 0; i < candidates.length && out.length < limit; i++) {
      var hint = candidates[i];
      if (out.indexOf(hint) === -1 && alertHintIsSafe(hint)) out.push(hint);
    }
    return out;
  }

  /**
   * The query behind the Triage button. Same rules as a hunt chip, because it is
   * the same thing: text assembled from live alert fields and sent as a query.
   *
   * The alert DESCRIPTION never appears in it. That is vendor prose, so it can carry
   * a vendor name or a restricted zone word and trip a guardrail into answering with
   * a silent cover, which reads to the operator as the platform having nothing to
   * say. alertTopic() reduces it to one of our own labels instead. Restricted
   * addresses and out-of-range ports are dropped by the same helpers the chips use,
   * and the finished string is checked once more before it goes out. If it still
   * fails, the caller gets the generic question rather than a covered answer.
   */
  function buildTriageQuery(alert) {
    var a = alert || {};
    var topic = alertTopic(a.description);
    var sev = severityWord(a.severity);
    var src = huntableIp(a.srcIp);
    var dst = huntableIp(a.dstIp);
    var port = huntablePort(a.dstPort);

    var subject = topic
      ? (sev ? 'this ' + sev + ' severity ' + topic + ' alert' : 'this ' + topic + ' alert')
      : (sev ? 'this ' + sev + ' severity alert' : 'this alert');

    var q = 'Triage ' + subject;
    if (src && dst) q += ' involving ' + src + ' and ' + dst;
    else if (src) q += ' from ' + src;
    else if (dst) q += ' targeting ' + dst;
    if (port) q += ' on port ' + port;
    q += '. What is happening and what should we check next?';

    var generic = 'How serious is this alert and what should we check next?';
    return alertHintIsSafe(q) ? q : generic;
  }

  root.buildAlertHuntHints = buildAlertHuntHints;
  root.buildTriageQuery = buildTriageQuery;
  root.alertHintIsSafe = alertHintIsSafe;
  root.MAX_HUNT_HINTS = MAX_HUNT_HINTS;
})(typeof globalThis !== 'undefined' ? globalThis : this);
