/*!
 * sddl-csv.js — turn a parsed SDDL result into CSV
 *
 * One row per principal (O:, G:) or per ACE (D:, S:), so the output can be
 * filtered and pivoted in Excel or any spreadsheet tool.
 *
 * Usable from Node and from the browser.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./sddl-parser.js'));
  } else {
    root.SDDLCsv = factory(root.SDDL);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (SDDL) {
  'use strict';

  var COLUMNS = [
    'Section',
    'ACE #',
    'ACL Flags',
    'Type Code',
    'Type',
    'ACE Flags',
    'Flag Names',
    'Trustee',
    'Account',
    'SID',
    'Rights Codes',
    'Right Names',
    'Access Mask',
    'Decoded Bits',
    'Object GUID',
    'Object GUID Name',
    'Inherit GUID',
    'Inherit GUID Name',
    'Condition',
    'Resource Attribute',
    'Warnings',
    'Raw'
  ];

  /**
   * Excel and LibreOffice treat a cell starting with = + - @ (or a tab /
   * carriage return) as a formula. SDDL is untrusted input, so neutralise
   * those by prefixing a single quote.
   *
   * Conditional ACE expressions are wrapped in parentheses, e.g.
   * "(=1+1)", which Excel does not treat as a formula — but the wrapper is
   * trivial to change, so look through leading parentheses too.
   */
  function sanitize(value) {
    var s = value == null ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
    if (/^\(+[=+\-@]/.test(s)) return "'" + s;
    return s;
  }

  function quote(value) {
    var s = sanitize(value);
    if (/[",\r\n]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function row(cells) {
    return cells.map(quote).join(',');
  }

  function aclFlagCodes(acl) {
    if (!acl) return '';
    return acl.flags.map(function (f) { return f.code; }).join(' ');
  }

  function principalRow(section, sid) {
    return [
      section,
      '',
      '',
      sid.kind === 'alias' ? 'alias' : (sid.kind === 'sid' ? 'sid' : sid.kind),
      sid.kind === 'alias' ? 'SDDL alias' : 'Principal',
      '',
      '',
      sid.name || '',
      sid.account || '',
      sid.sid || sid.raw || '',
      '', '', '', '', '', '', '', '', '', '',
      sid.resolved ? '' : 'SID does not resolve to a known account',
      sid.raw || ''
    ];
  }

  function aceRow(section, acl, ace) {
    var contexts = SDDL.inferContexts(ace.rights);
    var bits = SDDL.decodeMask(ace.rights.mask, contexts).map(function (b) { return b.name; });

    var notes = ace.errors.concat(ace.warnings);

    return [
      section,
      ace.index,
      aclFlagCodes(acl),
      ace.type.code || '',
      ace.type.name || '',
      ace.flagsRaw || '',
      ace.flags.map(function (f) { return f.name; }).join('; '),
      ace.sid.name || '',
      ace.sid.account || '',
      ace.sid.sid || ace.sid.raw || '',
      ace.rights.codes.join(' '),
      ace.rights.items.map(function (r) { return r.name; }).join('; '),
      ace.rights.hex || '',
      bits.join(' '),
      ace.objectGuid ? ace.objectGuid.guid : '',
      ace.objectGuid && ace.objectGuid.name ? ace.objectGuid.name : '',
      ace.inheritObjectGuid ? ace.inheritObjectGuid.guid : '',
      ace.inheritObjectGuid && ace.inheritObjectGuid.name ? ace.inheritObjectGuid.name : '',
      ace.condition || '',
      ace.resourceAttribute || '',
      notes.join('; '),
      ace.raw
    ];
  }

  function emptyAclRow(section, acl) {
    var isNull = acl.flags.some(function (f) { return f.code === 'NO_ACCESS_CONTROL'; });
    return [
      section,
      '',
      aclFlagCodes(acl),
      '',
      isNull ? 'NULL ACL' : 'Empty ACL',
      '',
      '',
      '',
      '',
      '',
      '', '', '', '', '', '', '', '', '', '',
      isNull
        ? 'NULL ACL grants full access to every principal'
        : 'Empty ACL denies access to every principal',
      section + ':' + (acl.flagRaw || '')
    ];
  }

  /**
   * Build the CSV text.
   * @param {object} result A successful result from SDDL.parse()
   * @param {object} [options] { bom: boolean, eol: string }
   * @returns {string}
   */
  function toCsv(result, options) {
    options = options || {};
    var eol = options.eol || '\r\n';
    var lines = [row(COLUMNS)];

    if (!result || !result.ok) {
      return (options.bom ? '﻿' : '') + lines.join(eol) + eol;
    }

    if (result.owner) lines.push(row(principalRow('O', result.owner)));
    if (result.group) lines.push(row(principalRow('G', result.group)));

    [['D', result.dacl], ['S', result.sacl]].forEach(function (pair) {
      var section = pair[0];
      var acl = pair[1];
      if (!acl) return;

      if (!acl.aces.length) {
        lines.push(row(emptyAclRow(section, acl)));
        return;
      }
      acl.aces.forEach(function (ace) {
        lines.push(row(aceRow(section, acl, ace)));
      });
    });

    return (options.bom ? '﻿' : '') + lines.join(eol) + eol;
  }

  return {
    toCsv: toCsv,
    COLUMNS: COLUMNS,
    sanitize: sanitize,
    quote: quote
  };
});
