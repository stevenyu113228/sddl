#!/usr/bin/env node
/* Simple assertion-based tests for the SDDL parser. Run: node tests/parser.test.js */
'use strict';

const assert = require('assert');
const path = require('path');
const S = require(path.join(__dirname, '..', 'js', 'sddl-parser.js'));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  ok   ' + name);
  } catch (e) {
    failed++;
    console.log('  FAIL ' + name);
    console.log('       ' + (e && e.message ? e.message.split('\n').join('\n       ') : e));
  }
}

function parses(sddl) {
  const r = S.parse(sddl);
  assert.strictEqual(r.ok, true, 'expected a successful parse');
  return r;
}

console.log('\nSecurity descriptor sections');

test('owner, group and DACL', () => {
  const r = parses('O:BAG:SYD:(A;;GA;;;WD)');
  assert.strictEqual(r.owner.code, 'BA');
  assert.strictEqual(r.owner.sid, 'S-1-5-32-544');
  assert.strictEqual(r.owner.name, 'Built-in Administrators');
  assert.strictEqual(r.group.sid, 'S-1-5-18');
  assert.strictEqual(r.dacl.aces.length, 1);
  assert.strictEqual(r.sacl, null);
});

test('sections are order independent in the result object', () => {
  const r = parses('D:(A;;GA;;;WD)S:(AU;SA;GA;;;WD)G:SYO:BA');
  assert.strictEqual(r.owner.code, 'BA');
  assert.strictEqual(r.group.code, 'SY');
  assert.strictEqual(r.dacl.aces.length, 1);
  assert.strictEqual(r.sacl.aces.length, 1);
});

test('surrounding quotes and whitespace are stripped', () => {
  const r = parses('  "O:BAG:SYD:(A;;GA;;;WD)"  ');
  assert.strictEqual(r.owner.code, 'BA');
  assert.strictEqual(r.dacl.aces.length, 1);
});

test('empty input is rejected', () => {
  assert.strictEqual(S.parse('').ok, false);
  assert.strictEqual(S.parse('   ').ok, false);
});

test('garbage input is rejected', () => {
  assert.throws(() => S.parse('hello'), S.SddlError);
});

console.log('\nACL control flags');

test('P, AI and AR are decoded', () => {
  const r = parses('D:PAI(A;;GA;;;WD)');
  const codes = r.dacl.flags.map((f) => f.code).sort();
  assert.deepStrictEqual(codes, ['AI', 'P']);

  const r2 = parses('D:AR(A;;GA;;;WD)');
  assert.deepStrictEqual(r2.dacl.flags.map((f) => f.code), ['AR']);
});

test('NO_ACCESS_CONTROL is decoded as a single token', () => {
  const r = parses('D:NO_ACCESS_CONTROL');
  assert.strictEqual(r.dacl.flags.length, 1);
  assert.strictEqual(r.dacl.flags[0].code, 'NO_ACCESS_CONTROL');
});

test('empty DACL warns about deny-everyone semantics', () => {
  const r = parses('O:BAG:SYD:');
  assert.strictEqual(r.dacl.aces.length, 0);
  assert.strictEqual(r.dacl.empty, true);
  assert.ok(r.warnings.some((w) => w.includes('denies everyone')));
});

console.log('\nACE parsing');

test('ACE type, flags, rights and trustee', () => {
  const r = parses('D:(A;OICI;FA;;;SY)');
  const ace = r.dacl.aces[0];
  assert.strictEqual(ace.type.code, 'A');
  assert.strictEqual(ace.type.en, 'ACCESS_ALLOWED_ACE_TYPE');
  assert.deepStrictEqual(ace.flags.map((f) => f.code), ['OI', 'CI']);
  assert.deepStrictEqual(ace.rights.codes, ['FA']);
  assert.strictEqual(ace.rights.mask, 0x001F01FF);
  assert.strictEqual(ace.sid.sid, 'S-1-5-18');
});

test('multiple ACEs are indexed in order', () => {
  const r = parses('D:(A;;GA;;;SY)(D;;GA;;;WD)(A;;FR;;;BU)');
  assert.strictEqual(r.dacl.aces.length, 3);
  assert.deepStrictEqual(r.dacl.aces.map((a) => a.index), [0, 1, 2]);
  assert.deepStrictEqual(r.dacl.aces.map((a) => a.type.code), ['A', 'D', 'A']);
});

test('ACE positions point into the original string', () => {
  const sddl = 'D:(A;;GA;;;WD)';
  const r = parses(sddl);
  const ace = r.dacl.aces[0];
  assert.strictEqual(sddl.slice(ace.start, ace.end), '(A;;GA;;;WD)');
});

test('hex access mask is accepted', () => {
  const r = parses('D:(A;;0x1F01FF;;;SY)');
  const ace = r.dacl.aces[0];
  assert.strictEqual(ace.rights.isHex, true);
  assert.strictEqual(ace.rights.mask, 0x1F01FF);
  assert.strictEqual(ace.rights.hex, '0x001F01FF');
});

test('object ACE with GUIDs', () => {
  const r = parses('D:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)');
  const ace = r.dacl.aces[0];
  assert.strictEqual(ace.type.code, 'OA');
  assert.strictEqual(ace.objectGuid.guid, 'ab721a53-1e2f-11d0-9819-00aa0040529b');
  assert.ok(ace.objectGuid.name.includes('Change password'));
  assert.strictEqual(ace.inheritObjectGuid, null);
  assert.deepStrictEqual(ace.rights.codes, ['CR']);
});

test('object ACE without a GUID warns', () => {
  const r = parses('D:(OA;;CR;;;WD)');
  assert.ok(r.dacl.aces[0].warnings.some((w) => w.includes('no GUID')));
});

test('audit ACE flags are recognised', () => {
  const r = parses('S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)');
  const ace = r.sacl.aces[0];
  assert.strictEqual(ace.type.kind, 'audit');
  assert.deepStrictEqual(ace.flags.map((f) => f.code), ['SA', 'FA']);
  assert.deepStrictEqual(ace.rights.codes, ['WD', 'WO', 'SD', 'WP', 'CC', 'DC', 'SW']);
});

test('audit ACE without SA/FA warns', () => {
  const r = parses('S:(AU;;GA;;;WD)');
  assert.ok(r.sacl.aces[0].warnings.some((w) => w.includes('neither SA nor FA')));
});

test('audit flags on a non-audit ACE warn', () => {
  const r = parses('D:(A;SA;GA;;;WD)');
  assert.ok(r.dacl.aces[0].warnings.some((w) => w.includes('not an audit ACE')));
});

test('mandatory label ACE', () => {
  const r = parses('S:(ML;;NW;;;LW)');
  const ace = r.sacl.aces[0];
  assert.strictEqual(ace.type.code, 'ML');
  assert.deepStrictEqual(ace.rights.codes, ['NW']);
  assert.strictEqual(ace.sid.sid, 'S-1-16-4096');
  assert.strictEqual(ace.sid.name, 'Low Integrity');
});

test('mandatory label with wrong rights warns', () => {
  const r = parses('S:(ML;;GA;;;LW)');
  assert.ok(r.sacl.aces[0].warnings.some((w) => w.includes('non-integrity rights')));
});

test('conditional ACE with a quoted condition containing semicolons', () => {
  const sddl = 'D:AI(XA;OICI;FA;;;WD;(Member_of {SID(S-1-5-32-544)}))';
  const r = parses(sddl);
  const ace = r.dacl.aces[0];
  assert.strictEqual(ace.type.code, 'XA');
  assert.ok(ace.condition);
  assert.ok(ace.condition.includes('Member_of'));
  assert.strictEqual(ace.sid.code, 'WD');
});

test('conditional ACE without a condition warns', () => {
  const r = parses('D:(XA;OICI;FA;;;WD)');
  assert.ok(r.dacl.aces[0].warnings.some((w) => w.includes('no condition')));
});

test('resource attribute ACE', () => {
  const sddl = 'D:AI(RA;CI;;;;S-1-1-0;(Project,TS,0,"Windows","SQL"))';
  const r = parses(sddl);
  const ace = r.dacl.aces[0];
  assert.strictEqual(ace.type.code, 'RA');
  assert.ok(ace.resourceAttribute.includes('Project'));
  assert.strictEqual(ace.sid.sid, 'S-1-1-0');
});

test('unbalanced parenthesis is reported', () => {
  assert.throws(() => S.parse('D:(A;;GA;;;WD'), S.SddlError);
});

console.log('\nSID resolution');

test('two-letter aliases resolve', () => {
  const cases = {
    SY: 'S-1-5-18', BA: 'S-1-5-32-544', WD: 'S-1-1-0', AU: 'S-1-5-11',
    IU: 'S-1-5-4', SU: 'S-1-5-6', BU: 'S-1-5-32-545', CO: 'S-1-3-0',
    LW: 'S-1-16-4096', HI: 'S-1-16-12288', AC: 'S-1-15-2-1'
  };
  for (const [alias, sid] of Object.entries(cases)) {
    assert.strictEqual(S.parseSid(alias).sid, sid, alias + ' should map to ' + sid);
  }
});

test('full well-known SIDs resolve', () => {
  assert.strictEqual(S.parseSid('S-1-5-18').name, 'Local System');
  assert.strictEqual(S.parseSid('S-1-5-32-544').name, 'Built-in Administrators');
  assert.strictEqual(S.parseSid('S-1-5-11').name, 'Authenticated Users');
  assert.strictEqual(S.parseSid('S-1-1-0').name, 'Everyone');
});

test('domain-relative SIDs resolve their RID', () => {
  const s = S.parseSid('S-1-5-21-1004336348-1177238915-682003330-512');
  assert.strictEqual(s.name, 'Domain Admins');
  assert.strictEqual(s.authority, 5);
  assert.deepStrictEqual(s.subAuthorities, [21, 1004336348, 1177238915, 682003330, 512]);
});

test('logon session SIDs are recognised', () => {
  const s = S.parseSid('S-1-5-5-0-123456');
  assert.strictEqual(s.name, 'Logon Session');
});

test('unknown alias is flagged', () => {
  const s = S.parseSid('ZZ');
  assert.strictEqual(s.resolved, false);
  assert.strictEqual(s.unknown, true);
});

test('invalid SID is flagged', () => {
  const s = S.parseSid('not-a-sid');
  assert.strictEqual(s.kind, 'invalid');
  assert.strictEqual(s.resolved, false);
});

console.log('\nRights');

test('rights codes accumulate into a mask', () => {
  const r = S.parseRights('RPWPCCDCLCSWRCWDWOGA');
  assert.strictEqual(r.mask >>> 0, 0x100E003F);
  assert.ok(r.codes.includes('GA'));
  assert.ok(r.codes.includes('RC'));
});

test('file rights map to the expected masks', () => {
  assert.strictEqual(S.parseRights('FA').mask, 0x001F01FF);
  assert.strictEqual(S.parseRights('FR').mask, 0x00120089);
  assert.strictEqual(S.parseRights('FW').mask, 0x00120116);
  assert.strictEqual(S.parseRights('FX').mask, 0x001200A0);
});

test('registry rights map to the expected masks', () => {
  assert.strictEqual(S.parseRights('KA').mask, 0x000F003F);
  assert.strictEqual(S.parseRights('KR').mask, 0x00020019);
  assert.strictEqual(S.parseRights('KW').mask, 0x00020006);
});

test('unknown rights codes are reported', () => {
  const r = S.parseRights('GAZZ');
  assert.deepStrictEqual(r.unknown, ['ZZ']);
  assert.strictEqual(r.mask, 0x10000000);
});

test('odd-length rights string throws', () => {
  assert.throws(() => S.parseRights('G'), S.SddlError);
});

test('empty rights field yields a zero mask', () => {
  const r = S.parseRights('');
  assert.strictEqual(r.mask, 0);
  assert.deepStrictEqual(r.codes, []);
});

console.log('\nMask decoding');

test('file context decodes FILE_* bits', () => {
  const bits = S.decodeMask(0x001F01FF, ['file']);
  const names = bits.map((b) => b.name);
  assert.ok(names.includes('FILE_READ_DATA'));
  assert.ok(names.includes('DELETE'));
  assert.ok(names.includes('GENERIC_ALL') === false);
});

test('registry context decodes KEY_* bits', () => {
  const bits = S.decodeMask(0x00020019, ['registry']);
  const names = bits.map((b) => b.name);
  assert.ok(names.includes('KEY_QUERY_VALUE'));
  assert.ok(names.includes('KEY_ENUMERATE_SUB_KEYS'));
  assert.ok(!names.includes('FILE_READ_DATA'));
});

test('inferContexts picks the right object type', () => {
  assert.deepStrictEqual(S.inferContexts(S.parseRights('FA')), ['file']);
  assert.deepStrictEqual(S.inferContexts(S.parseRights('KA')), ['registry']);
  assert.deepStrictEqual(S.inferContexts(S.parseRights('RPWP')), ['ds']);
  assert.deepStrictEqual(S.inferContexts(S.parseRights('NW')), ['mandatory']);
});

console.log('\nReal-world samples');

test('Windows service default SDDL', () => {
  const sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)';
  const r = parses(sddl);
  assert.strictEqual(r.dacl.aces.length, 4);
  assert.deepStrictEqual(r.dacl.aces.map((a) => a.sid.code), ['SY', 'BA', 'IU', 'SU']);
  assert.deepStrictEqual(r.dacl.aces[0].rights.codes,
    ['CC', 'LC', 'SW', 'RP', 'WP', 'DT', 'LO', 'CR', 'RC']);
});

test('full descriptor with SACL', () => {
  const r = parses('O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)');
  assert.strictEqual(r.owner.code, 'BA');
  assert.strictEqual(r.group.code, 'SY');
  assert.deepStrictEqual(r.dacl.flags.map((f) => f.code).sort(), ['AI', 'P']);
  assert.strictEqual(r.dacl.aces.length, 3);
  assert.strictEqual(r.sacl.aces.length, 1);
});

test('inherited ACEs with ID flag and hex mask', () => {
  const sddl = 'O:S-1-5-21-1004336348-1177238915-682003330-512G:S-1-5-21-1004336348-1177238915-682003330-513D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)';
  const r = parses(sddl);
  assert.strictEqual(r.owner.name, 'Domain Admins');
  assert.strictEqual(r.group.name, 'Domain Users');
  assert.strictEqual(r.dacl.aces.length, 3);
  assert.ok(r.dacl.aces.every((a) => a.flags.some((f) => f.code === 'ID')));
  assert.strictEqual(r.dacl.aces[2].rights.isHex, true);
});

test('registry key SDDL', () => {
  const r = parses('O:BAG:SYD:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)');
  assert.strictEqual(r.dacl.aces.length, 3);
  assert.ok(r.dacl.aces.every((a) => a.flags.some((f) => f.code === 'CI')));
  assert.deepStrictEqual(r.dacl.aces.map((a) => a.rights.codes[0]), ['KA', 'KA', 'KR']);
});

test('AD object with extended rights', () => {
  const sddl = 'O:DAG:DAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;AU)';
  const r = parses(sddl);
  assert.strictEqual(r.owner.name, 'Domain Admins');
  assert.strictEqual(r.dacl.aces.length, 3);
  assert.strictEqual(r.dacl.aces[1].type.code, 'OA');
  assert.ok(r.dacl.aces[1].objectGuid.name.includes('Change password'));
  assert.ok(r.dacl.aces[2].objectGuid.name.includes('Reset password'));
});

test('protected process light descriptor', () => {
  const r = parses('O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;LW)(TL;;NR;;;SI)');
  assert.strictEqual(r.dacl.aces.length, 2);
  assert.strictEqual(r.sacl.aces.length, 2);
  assert.deepStrictEqual(r.sacl.aces.map((a) => a.type.code), ['ML', 'TL']);
  assert.strictEqual(r.sacl.aces[1].sid.name, 'System Integrity');
});

test('whitespace and newlines between ACEs are tolerated', () => {
  const r = parses('D:\n  (A;;GA;;;SY)\n  (A;;GA;;;BA)\n');
  assert.strictEqual(r.dacl.aces.length, 2);
});

console.log('\n' + '-'.repeat(50));
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
