/*!
 * sddl-parser.js — Windows SDDL parser
 *
 * Turns an SDDL string into a structured object and keeps the position of
 * every element in the source string so the UI can highlight it.
 *
 * Syntax references:
 *   https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format
 *   https://learn.microsoft.com/windows/win32/secauthz/ace-strings
 *   https://learn.microsoft.com/windows/win32/secauthz/sid-strings
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./sddl-data.js'));
  } else {
    root.SDDL = factory(root.SDDLData);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (D) {
  'use strict';

  /* ------------------------------------------------------------------ *
   * Error type
   * ------------------------------------------------------------------ */
  function SddlError(message, position, length, hint) {
    this.name = 'SddlError';
    this.message = message;
    this.position = position;
    this.length = length || 1;
    this.hint = hint || null;
  }
  SddlError.prototype = Object.create(Error.prototype);
  SddlError.prototype.constructor = SddlError;

  /* ------------------------------------------------------------------ *
   * Helpers
   * ------------------------------------------------------------------ */
  function isSpace(c) {
    return c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f' || c === '\v';
  }

  function hex(n) {
    var s = (n >>> 0).toString(16).toUpperCase();
    return '0x' + ('00000000' + s).slice(-8);
  }

  // Find the ')' that matches the '(' at `start`, skipping quoted strings.
  function matchParen(str, start) {
    var depth = 0;
    var inStr = false;
    var i = start;
    while (i < str.length) {
      var c = str[i];
      if (inStr) {
        if (c === '\\') { i += 2; continue; }
        if (c === '"') inStr = false;
      } else if (c === '"') {
        inStr = true;
      } else if (c === '(') {
        depth++;
      } else if (c === ')') {
        depth--;
        if (depth === 0) return i;
      }
      i++;
    }
    return -1;
  }

  // Split an ACE body on ';' while ignoring quoted strings and nested parentheses.
  function splitFields(inner) {
    var out = [];
    var cur = '';
    var inStr = false;
    var depth = 0;
    for (var i = 0; i < inner.length; i++) {
      var c = inner[i];
      if (inStr) {
        cur += c;
        if (c === '\\') {
          if (i + 1 < inner.length) { cur += inner[i + 1]; i++; }
        } else if (c === '"') {
          inStr = false;
        }
        continue;
      }
      if (c === '"') { inStr = true; cur += c; continue; }
      if (c === '(') { depth++; cur += c; continue; }
      if (c === ')') { depth--; cur += c; continue; }
      if (c === ';' && depth === 0) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    out.push(cur);
    return out;
  }

  /* ------------------------------------------------------------------ *
   * SID parsing
   * ------------------------------------------------------------------ */
  var AUTHORITIES = {
    0: 'Null Authority',
    1: 'World Authority',
    2: 'Local Authority',
    3: 'Creator Authority',
    4: 'Non-unique Authority',
    5: 'NT Authority',
    9: 'Resource Manager Authority',
    15: 'Application Package Authority',
    16: 'Mandatory Label Authority',
    18: 'Authentication Authority',
    19: 'Process Trust Label Authority'
  };

  function parseSid(raw, pos) {
    var text = (raw || '').trim();
    if (!text) {
      return { raw: raw, kind: 'empty', resolved: false, name: 'Not specified', account: null, sid: null };
    }

    // Two-letter alias
    if (/^[A-Za-z]{2}$/.test(text)) {
      var code = text.toUpperCase();
      var alias = D.SID_ALIASES[code];
      if (alias) {
        return {
          raw: raw,
          kind: 'alias',
          code: code,
          sid: alias.sid,
          name: alias.name,
          account: alias.account,
          resolved: true,
          pos: pos,
          desc: 'SDDL alias ' + code + ' resolves to ' + alias.sid
        };
      }
      return {
        raw: raw,
        kind: 'alias',
        code: code,
        sid: null,
        name: 'Unknown alias ' + code,
        account: null,
        resolved: false,
        unknown: true,
        pos: pos,
        desc: 'This two-letter code is not a standard SDDL SID alias.'
      };
    }

    // Full SID string
    var m = /^[Ss]-(\d+)-(\d+|0[xX][0-9a-fA-F]+)((?:-\d+)*)$/.exec(text);
    if (!m) {
      return {
        raw: raw,
        kind: 'invalid',
        sid: null,
        name: 'Unrecognised SID',
        account: null,
        resolved: false,
        unknown: true,
        pos: pos,
        desc: '"' + text + '" is neither a valid SID nor an SDDL alias.'
      };
    }

    var revision = parseInt(m[1], 10);
    var authority = /^0[xX]/.test(m[2]) ? parseInt(m[2], 16) : parseInt(m[2], 10);
    var subAuths = m[3] ? m[3].split('-').filter(function (x) { return x !== ''; }).map(Number) : [];
    var canonical = 'S-' + revision + '-' + authority + (subAuths.length ? '-' + subAuths.join('-') : '');
    var authorityName = AUTHORITIES[authority] || ('Authority ' + authority);

    var info;

    if (D.WELL_KNOWN_SIDS[canonical]) {
      info = D.WELL_KNOWN_SIDS[canonical];
    } else if (D.BUILTIN_ALIASES[canonical]) {
      info = D.BUILTIN_ALIASES[canonical];
    } else if (authority === 5 && subAuths.length === 3 && subAuths[0] === 5) {
      info = {
        name: 'Logon Session',
        account: 'Logon Session ' + subAuths[1] + '-' + subAuths[2],
        desc: 'Unique identifier for a specific logon session (S-1-5-5-X-Y).'
      };
    } else if (authority === 5 && subAuths.length >= 5 && subAuths[0] === 21) {
      var rid = subAuths[subAuths.length - 1];
      var known = D.DOMAIN_RIDS[rid];
      info = {
        name: known || ('Domain-relative RID ' + rid),
        account: known ? null : 'DOMAIN\\RID-' + rid,
        desc: known
          ? 'Domain-relative SID S-1-5-21-<domain>-' + rid + ' (RID ' + rid + ').'
          : 'Domain-relative SID, but RID ' + rid + ' is not a well-known RID and must be resolved against a live domain.'
      };
    } else if (authority === 5 && subAuths.length === 2 && subAuths[0] === 32) {
      info = {
        name: 'Unknown built-in alias (RID ' + subAuths[1] + ')',
        account: 'BUILTIN\\RID-' + subAuths[1],
        desc: 'S-1-5-32 is the built-in domain, but this RID is not in the known list.'
      };
    } else if (authority === 16) {
      info = {
        name: 'Integrity level ' + subAuths[0],
        account: 'Mandatory Label',
        desc: 'Mandatory integrity level SID (S-1-16-<level>).'
      };
    } else if (authority === 15) {
      info = {
        name: 'Application package SID',
        account: 'APPLICATION PACKAGE AUTHORITY',
        desc: 'AppContainer application package SID.'
      };
    } else if (authority === 18) {
      info = {
        name: 'Authentication authority SID',
        account: 'AUTHENTICATION AUTHORITY',
        desc: 'Identity asserted by the authentication authority.'
      };
    } else if (authority === 0) {
      info = { name: 'Null SID', account: 'NULL SID', desc: 'A group with no members.' };
    } else if (authority === 1) {
      info = { name: 'Everyone', account: 'Everyone', desc: 'A group that includes all users.' };
    } else if (authority === 2) {
      info = { name: 'Local', account: 'LOCAL', desc: 'Local logon SID.' };
    } else if (authority === 3) {
      info = { name: 'Creator', account: 'CREATOR', desc: 'Placeholder replaced during inheritance.' };
    } else {
      info = {
        name: 'Unknown SID',
        account: null,
        desc: 'Does not map to a known account. It may belong to another domain or a deleted account.'
      };
    }

    return {
      raw: raw,
      kind: 'sid',
      sid: canonical,
      revision: revision,
      authority: authority,
      authorityName: authorityName,
      subAuthorities: subAuths,
      name: info.name,
      account: info.account,
      desc: info.desc,
      resolved: !!info.name && info.name.indexOf('Unknown') !== 0 && info.name.indexOf('Domain-relative RID') !== 0,
      pos: pos
    };
  }

  /* ------------------------------------------------------------------ *
   * Rights parsing
   * ------------------------------------------------------------------ */
  function parseRights(raw, pos) {
    var text = (raw || '').trim();
    var result = {
      raw: raw,
      mask: 0,
      codes: [],
      items: [],
      isHex: false,
      hex: null,
      unknown: []
    };
    if (!text) return result;

    if (/^0[xX][0-9a-fA-F]+$/.test(text)) {
      result.isHex = true;
      result.mask = parseInt(text, 16) >>> 0;
      result.hex = hex(result.mask);
      return result;
    }

    // Rights are a concatenation of two-letter codes
    if (text.length % 2 !== 0) {
      throw new SddlError(
        'Rights field "' + text + '" has an odd length and cannot be split into two-letter codes.',
        pos,
        text.length,
        'If you meant a raw mask, prefix it with 0x, for example 0x1F01FF.'
      );
    }

    for (var i = 0; i < text.length; i += 2) {
      var code = text.substr(i, 2);
      var item = D.RIGHTS_BY_CODE[code];
      if (item) {
        result.codes.push(code);
        result.items.push(item);
        result.mask = (result.mask | item.mask) >>> 0;
      } else {
        result.unknown.push(code);
      }
    }
    result.hex = hex(result.mask);
    return result;
  }

  // Guess which object types the rights refer to, so the bit decoder
  // can pick the right names (FILE_* vs KEY_* vs ADS_*).
  function inferContexts(rights) {
    var set = {};
    rights.codes.forEach(function (c) { set[c] = true; });
    var ctx = [];
    if (set.FA || set.FR || set.FW || set.FX) ctx.push('file');
    if (set.KA || set.KR || set.KW || set.KX) ctx.push('registry');
    if (set.RP || set.WP || set.CC || set.DC || set.LC || set.SW || set.LO || set.DT || set.CR) ctx.push('ds');
    if (rights.items.some(function (r) { return r.cat === 'mandatory'; })) ctx.push('mandatory');
    return ctx;
  }

  /**
   * Decode an access mask into individual bits.
   * @param {number} mask
   * @param {Array<string>} contexts Object types to show (file / registry / ds / mandatory)
   */
  function decodeMask(mask, contexts) {
    var out = [];
    var seenGeneric = {};
    var wantAll = !contexts || contexts.length === 0;

    D.BITS.forEach(function (b) {
      if ((mask & b.bit) === 0) return;
      if (b.ctx === '*') {
        if (seenGeneric[b.bit]) return;
        seenGeneric[b.bit] = true;
        out.push({ bit: b.bit, name: b.name, desc: b.desc, ctx: 'standard' });
        return;
      }
      if (wantAll || contexts.indexOf(b.ctx) !== -1) {
        out.push({ bit: b.bit, name: b.name, desc: b.desc, ctx: b.ctx });
      }
    });
    return out;
  }

  /* ------------------------------------------------------------------ *
   * ACE parsing
   * ------------------------------------------------------------------ */
  var OBJECT_ACE_TYPES = { OA: 1, OD: 1, OU: 1, OL: 1, ZA: 1, XA: 1, XD: 1, XU: 1 };

  function parseAce(raw, absStart, index) {
    var inner = raw.slice(1, -1);
    var fields = splitFields(inner);
    var ace = {
      index: index,
      raw: raw,
      start: absStart,
      end: absStart + raw.length,
      fields: fields,
      type: null,
      flags: [],
      flagsRaw: '',
      rights: null,
      objectGuid: null,
      inheritObjectGuid: null,
      sid: null,
      condition: null,
      resourceAttribute: null,
      errors: [],
      warnings: []
    };

    if (fields.length < 6) {
      ace.errors.push('ACE has ' + fields.length + ' field' + (fields.length === 1 ? '' : 's') +
        '; a standard ACE needs 6 (type;flags;rights;object_guid;inherit_guid;trustee).');
    }

    var typeCode = (fields[0] || '').trim().toUpperCase();
    ace.type = D.ACE_TYPES[typeCode] || null;
    if (!ace.type) {
      ace.errors.push('Unknown ACE type "' + (fields[0] || '') + '".');
      ace.type = {
        code: typeCode || '?',
        hex: null,
        name: 'Unknown type',
        en: null,
        kind: 'unknown',
        desc: 'Unrecognised ACE type code.'
      };
    }

    // ---- Flags ----
    var flagsRaw = (fields[1] || '').trim();
    ace.flagsRaw = flagsRaw;
    if (flagsRaw) {
      var upper = flagsRaw.toUpperCase();
      var i = 0;
      while (i < upper.length) {
        var matched = null;
        for (var k = 0; k < D.ACE_FLAG_CODES.length; k++) {
          var code = D.ACE_FLAG_CODES[k];
          if (upper.substr(i, code.length) === code) { matched = code; break; }
        }
        if (matched) {
          ace.flags.push(D.ACE_FLAGS[matched]);
          i += matched.length;
        } else {
          ace.warnings.push('Unknown ACE flag "' + upper.substr(i, 2) + '".');
          i += 2;
        }
      }
    }

    // ---- Rights ----
    try {
      ace.rights = parseRights(fields[2], absStart);
    } catch (e) {
      ace.rights = { raw: fields[2], mask: 0, codes: [], items: [], isHex: false, hex: null, unknown: [] };
      ace.errors.push(e.message);
    }
    if (ace.rights.unknown && ace.rights.unknown.length) {
      ace.warnings.push('Unknown rights codes: ' + ace.rights.unknown.join(', '));
    }

    // ---- Object GUIDs ----
    var og = (fields[3] || '').trim();
    if (og) {
      ace.objectGuid = { guid: og.toLowerCase(), name: D.OBJECT_GUIDS[og.toLowerCase()] || null };
      if (!ace.objectGuid.name) ace.warnings.push('Object GUID not in the lookup table: ' + og);
    }

    var iog = (fields[4] || '').trim();
    if (iog) {
      ace.inheritObjectGuid = { guid: iog.toLowerCase(), name: D.OBJECT_GUIDS[iog.toLowerCase()] || null };
      if (!ace.inheritObjectGuid.name) ace.warnings.push('Inherited-object GUID not in the lookup table: ' + iog);
    }

    // ---- Trustee ----
    ace.sid = parseSid(fields[5], absStart);

    // ---- Condition / resource attribute ----
    // Conditional ACEs carry a condition expression; resource attribute ACEs
    // carry a resource attribute block. Both occupy the seventh field.
    if (fields.length > 6) {
      var extra = fields.slice(6).join(';').trim();
      if (extra) {
        var isConditional = typeCode === 'XA' || typeCode === 'XD' || typeCode === 'ZA' || typeCode === 'XU';
        if (isConditional) ace.condition = extra;
        else if (typeCode === 'RA') ace.resourceAttribute = extra;
        else if (extra.charAt(0) === '(') ace.resourceAttribute = extra;
        else ace.condition = extra;
      }
    }

    if ((typeCode === 'XA' || typeCode === 'XD' || typeCode === 'ZA' || typeCode === 'XU') && !ace.condition) {
      ace.warnings.push('Conditional ACE has no condition expression.');
    }

    if (OBJECT_ACE_TYPES[typeCode] && !ace.objectGuid && !ace.inheritObjectGuid) {
      ace.warnings.push('Object ACE specifies no GUID; Windows treats it as a plain ACE.');
    }

    if (typeCode === 'ML') {
      var bad = ace.rights.items.filter(function (r) { return r.cat !== 'mandatory'; });
      if (bad.length) {
        ace.warnings.push('Mandatory label ACE contains non-integrity rights: ' + bad.map(function (r) { return r.code; }).join(', '));
      }
    }

    var isAudit = ace.type.kind === 'audit';
    var auditFlags = ace.flags.filter(function (f) { return f.code === 'SA' || f.code === 'FA'; });
    if (auditFlags.length && !isAudit) {
      ace.warnings.push('ACE has audit flags (SA/FA) but is not an audit ACE; those flags have no effect.');
    }
    if (isAudit && !auditFlags.length) {
      ace.warnings.push('Audit ACE specifies neither SA nor FA, so it will never produce an audit record.');
    }

    return ace;
  }

  /* ------------------------------------------------------------------ *
   * ACL control flags
   * ------------------------------------------------------------------ */
  function parseSdFlags(raw) {
    var result = { raw: raw, flags: [], unknown: [] };
    if (!raw) return result;
    var upper = raw.toUpperCase();
    var i = 0;
    while (i < upper.length) {
      var matched = null;
      for (var k = 0; k < D.SD_FLAG_CODES.length; k++) {
        var code = D.SD_FLAG_CODES[k];
        if (upper.substr(i, code.length) === code) { matched = code; break; }
      }
      if (matched) {
        result.flags.push(D.SD_FLAGS[matched]);
        i += matched.length;
      } else {
        result.unknown.push(upper[i]);
        i++;
      }
    }
    return result;
  }

  /* ------------------------------------------------------------------ *
   * Main parse
   * ------------------------------------------------------------------ */
  function parse(input) {
    var warnings = [];
    var raw = String(input == null ? '' : input);

    // Trim and strip one layer of surrounding quotes (common when copying from PowerShell)
    var text = raw.trim();
    if (text.length >= 2 && text.charAt(0) === '"' && text.charAt(text.length - 1) === '"') {
      text = text.slice(1, -1).trim();
    }

    if (!text) {
      return {
        ok: false,
        error: new SddlError('Enter an SDDL string.', 0, 0, 'For example: O:BAG:SYD:(A;;GA;;;WD)'),
        raw: raw,
        text: text
      };
    }

    var result = {
      ok: true,
      raw: raw,
      text: text,
      owner: null,
      group: null,
      dacl: null,
      sacl: null,
      warnings: warnings
    };

    var i = 0;
    var len = text.length;
    var seen = {};

    while (i < len) {
      while (i < len && isSpace(text[i])) i++;
      if (i >= len) break;

      var letter = text[i].toUpperCase();
      if (text[i + 1] !== ':' || 'OGDS'.indexOf(letter) === -1) {
        throw new SddlError(
          'Unexpected character "' + text[i] + '" at offset ' + i + '.',
          i,
          1,
          'An SDDL string consists of the sections O:, G:, D: and S:, in that order.'
        );
      }

      if (seen[letter]) warnings.push('Section ' + letter + ': appears more than once; only the first one is used.');
      seen[letter] = true;
      i += 2;

      // ---- O: / G: ----
      if (letter === 'O' || letter === 'G') {
        var sidStart = i;
        var sidText = '';
        var fullSid = /^[Ss]-\d+-(?:0[xX][0-9a-fA-F]+|\d+)(?:-\d+)*/.exec(text.slice(i));
        if (fullSid) {
          sidText = fullSid[0];
          i += sidText.length;
        } else {
          while (i < len && /[A-Za-z]/.test(text[i]) && sidText.length < 2) { sidText += text[i]; i++; }
        }
        var sidObj = parseSid(sidText, sidStart);
        sidObj.start = sidStart;
        sidObj.end = i;
        if (!sidObj.resolved) {
          warnings.push('Owner/group SID "' + sidText + '" does not resolve to a known account.');
        }
        if (letter === 'O') result.owner = sidObj;
        else result.group = sidObj;
        continue;
      }

      // ---- D: / S: ----
      var flagStart = i;
      var flagText = '';
      while (i < len && /[A-Za-z_]/.test(text[i])) { flagText += text[i]; i++; }

      var acl = {
        letter: letter,
        present: true,
        flagRaw: flagText,
        flags: [],
        unknownFlags: [],
        aces: [],
        start: flagStart - 2,
        end: i,
        empty: false
      };

      var sdFlags = parseSdFlags(flagText);
      acl.flags = sdFlags.flags;
      acl.unknownFlags = sdFlags.unknown;
      if (sdFlags.unknown.length) {
        warnings.push(letter + ': unrecognised ACL control flags: ' + sdFlags.unknown.join(', '));
      }

      var aceIndex = 0;
      while (true) {
        while (i < len && isSpace(text[i])) i++;
        if (i >= len || text[i] !== '(') break;
        var close = matchParen(text, i);
        if (close === -1) {
          throw new SddlError(
            'ACE is missing its closing parenthesis.',
            i,
            len - i,
            'Every ACE must start with "(" and end with ")".'
          );
        }
        var ace = parseAce(text.slice(i, close + 1), i, aceIndex++);
        acl.aces.push(ace);
        i = close + 1;
      }

      acl.end = i;
      acl.empty = acl.aces.length === 0;

      // Anything left must be the start of the next section
      if (i < len) {
        while (i < len && isSpace(text[i])) i++;
        if (i < len && !(text[i + 1] === ':' && 'OGDS'.indexOf(text[i].toUpperCase()) !== -1)) {
          throw new SddlError(
            'Cannot parse "' + text.slice(i, i + 20) + '" at offset ' + i + '.',
            i,
            1,
            'After the ACEs only whitespace or another section (O:, G:, D:, S:) is allowed.'
          );
        }
      }

      if (letter === 'D') result.dacl = acl;
      else result.sacl = acl;
    }

    if (!result.dacl && !result.sacl && !result.owner && !result.group) {
      return {
        ok: false,
        error: new SddlError('No SDDL sections found.', 0, text.length, 'The string must contain at least one of O:, G:, D: or S:.'),
        raw: raw,
        text: text
      };
    }

    // ---- Semantic checks ----
    if (result.dacl) {
      var nullAcl = result.dacl.flags.some(function (f) { return f.code === 'NO_ACCESS_CONTROL'; });
      if (nullAcl && result.dacl.aces.length) {
        warnings.push('D: specifies both NO_ACCESS_CONTROL and ACEs; a NULL ACL makes the ACEs irrelevant.');
      }
      if (result.dacl.empty && !nullAcl) {
        warnings.push('D: is an empty ACL, which denies everyone. (Omitting D: entirely is different.)');
      }
      if (!result.owner) {
        warnings.push('No owner (O:) is specified; the default owner applies when the descriptor is used.');
      }
    }

    if (result.sacl && result.sacl.empty) {
      warnings.push('S: is an empty ACL, so no audit events will be recorded.');
    }

    return result;
  }

  /* ------------------------------------------------------------------ *
   * Public API
   * ------------------------------------------------------------------ */
  return {
    parse: parse,
    parseSid: parseSid,
    parseRights: parseRights,
    parseSdFlags: parseSdFlags,
    decodeMask: decodeMask,
    inferContexts: inferContexts,
    matchParen: matchParen,
    splitFields: splitFields,
    hex: hex,
    SddlError: SddlError
  };
});
