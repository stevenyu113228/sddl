#!/usr/bin/env node
/* CSV export tests. Run: node tests/csv.test.js */
'use strict';

const assert = require('assert');
const path = require('path');
const S = require(path.join(__dirname, '..', 'js', 'sddl-parser.js'));
const C = require(path.join(__dirname, '..', 'js', 'sddl-csv.js'));

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

// Minimal RFC 4180 reader, enough to verify our own output round-trips.
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"') { inQuotes = true; continue; }
    if (c === ',') { row.push(field); field = ''; continue; }
    if (c === '\r') continue;
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue; }
    field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const SERVICE_SDDL = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)';

console.log('\nCSV structure');

test('header matches the declared columns', () => {
  const csv = C.toCsv(S.parse('D:(A;;GA;;;WD)'));
  const rows = parseCsv(csv);
  assert.deepStrictEqual(rows[0], C.COLUMNS);
});

test('every row has the same number of columns as the header', () => {
  const csv = C.toCsv(S.parse('O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FR;;;BU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)'));
  const rows = parseCsv(csv);
  rows.forEach((r, i) => {
    assert.strictEqual(r.length, C.COLUMNS.length, 'row ' + i + ' has ' + r.length + ' columns');
  });
});

test('one row per ACE plus owner and group', () => {
  const csv = C.toCsv(S.parse('O:BAG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)'));
  const rows = parseCsv(csv);
  assert.strictEqual(rows.length, 1 + 1 + 1 + 2); // header + O + G + 2 ACEs
});

test('sections are labelled O, G, D and S', () => {
  const csv = C.toCsv(S.parse('O:BAG:SYD:(A;;FA;;;SY)S:(AU;SA;GA;;;WD)'));
  const rows = parseCsv(csv);
  assert.deepStrictEqual(rows.slice(1).map((r) => r[0]), ['O', 'G', 'D', 'S']);
});

test('CRLF line endings by default', () => {
  const csv = C.toCsv(S.parse('D:(A;;GA;;;WD)'));
  assert.ok(csv.includes('\r\n'));
  assert.ok(!/[^\r]\n/.test(csv));
});

test('custom EOL is honoured', () => {
  const csv = C.toCsv(S.parse('D:(A;;GA;;;WD)'), { eol: '\n' });
  assert.ok(!csv.includes('\r'));
});

test('BOM is optional and only added when asked', () => {
  assert.strictEqual(C.toCsv(S.parse('D:(A;;GA;;;WD)'))[0], 'S');
  assert.strictEqual(C.toCsv(S.parse('D:(A;;GA;;;WD)'), { bom: true }).charCodeAt(0), 0xFEFF);
});

console.log('\nCSV content');

test('trustee names and SIDs are resolved', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(A;;FA;;;BU)')));
  const ace = rows[1];
  const col = (n) => ace[C.COLUMNS.indexOf(n)];
  assert.strictEqual(col('Trustee'), 'Built-in Users');
  assert.strictEqual(col('Account'), 'BUILTIN\\Users');
  assert.strictEqual(col('SID'), 'S-1-5-32-545');
});

test('rights codes, names and mask are exported', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(A;;FA;;;SY)')));
  const col = (n) => rows[1][C.COLUMNS.indexOf(n)];
  assert.strictEqual(col('Rights Codes'), 'FA');
  assert.strictEqual(col('Right Names'), 'File full control');
  assert.strictEqual(col('Access Mask'), '0x001F01FF');
  assert.ok(col('Decoded Bits').includes('FILE_READ_DATA'));
});

test('decoded bits follow the object type', () => {
  const fileRows = parseCsv(C.toCsv(S.parse('D:(A;;FA;;;SY)')));
  const regRows = parseCsv(C.toCsv(S.parse('D:(A;;KA;;;SY)')));
  assert.ok(fileRows[1][C.COLUMNS.indexOf('Decoded Bits')].includes('FILE_'));
  assert.ok(regRows[1][C.COLUMNS.indexOf('Decoded Bits')].includes('KEY_'));
  assert.ok(!regRows[1][C.COLUMNS.indexOf('Decoded Bits')].includes('FILE_'));
});

test('ACE flags are exported as codes and names', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(A;OICI;FA;;;SY)')));
  const col = (n) => rows[1][C.COLUMNS.indexOf(n)];
  assert.strictEqual(col('ACE Flags'), 'OICI');
  assert.strictEqual(col('Flag Names'), 'Object inherit; Container inherit');
});

test('ACL control flags repeat on every ACE row', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:PAI(A;;GA;;;SY)(A;;GA;;;BA)')));
  assert.strictEqual(rows[1][C.COLUMNS.indexOf('ACL Flags')], 'P AI');
  assert.strictEqual(rows[2][C.COLUMNS.indexOf('ACL Flags')], 'P AI');
});

test('object GUIDs are exported with their friendly name', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)')));
  const col = (n) => rows[1][C.COLUMNS.indexOf(n)];
  assert.strictEqual(col('Object GUID'), 'ab721a53-1e2f-11d0-9819-00aa0040529b');
  assert.ok(col('Object GUID Name').includes('Change password'));
});

test('conditions are exported verbatim', () => {
  const sddl = 'D:AI(XA;OICI;FA;;;WD;(Member_of {SID(S-1-5-32-544)}))';
  const rows = parseCsv(C.toCsv(S.parse(sddl)));
  assert.strictEqual(rows[1][C.COLUMNS.indexOf('Condition')], '(Member_of {SID(S-1-5-32-544)})');
});

test('resource attributes are exported verbatim', () => {
  const sddl = 'D:AI(RA;CI;;;;S-1-1-0;(Project,TS,0,"Windows","SQL"))';
  const rows = parseCsv(C.toCsv(S.parse(sddl)));
  assert.ok(rows[1][C.COLUMNS.indexOf('Resource Attribute')].includes('Project'));
});

test('warnings are joined into one cell', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(OA;;CR;;;WD)')));
  assert.ok(rows[1][C.COLUMNS.indexOf('Warnings')].includes('no GUID'));
});

test('empty DACL gets a row explaining deny-everyone', () => {
  const rows = parseCsv(C.toCsv(S.parse('O:BAG:SYD:')));
  const d = rows.find((r) => r[0] === 'D');
  assert.ok(d, 'expected a D row');
  assert.strictEqual(d[C.COLUMNS.indexOf('Type')], 'Empty ACL');
  assert.ok(d[C.COLUMNS.indexOf('Warnings')].includes('denies access'));
});

test('NULL ACL gets a row explaining full access', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:NO_ACCESS_CONTROL')));
  const d = rows.find((r) => r[0] === 'D');
  assert.strictEqual(d[C.COLUMNS.indexOf('Type')], 'NULL ACL');
  assert.ok(d[C.COLUMNS.indexOf('Warnings')].includes('full access'));
});

test('service SDDL exports one row per ACE', () => {
  const rows = parseCsv(C.toCsv(S.parse(SERVICE_SDDL)));
  assert.strictEqual(rows.length, 1 + 4);
  assert.deepStrictEqual(
    rows.slice(1).map((r) => r[C.COLUMNS.indexOf('SID')]),
    ['S-1-5-18', 'S-1-5-32-544', 'S-1-5-4', 'S-1-5-6']
  );
});

console.log('\nCSV escaping');

test('commas and quotes are escaped per RFC 4180', () => {
  assert.strictEqual(C.quote('a,b'), '"a,b"');
  assert.strictEqual(C.quote('say "hi"'), '"say ""hi"""');
  assert.strictEqual(C.quote('line1\nline2'), '"line1\nline2"');
  assert.strictEqual(C.quote('plain'), 'plain');
});

test('quoted fields survive a round trip', () => {
  const rows = parseCsv(C.toCsv(S.parse('D:(A;;GA;;;WD)')));
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1][C.COLUMNS.indexOf('Raw')], '(A;;GA;;;WD)');
});

test('formula-injection prefixes are neutralised', () => {
  assert.strictEqual(C.sanitize('=cmd|calc'), "'=cmd|calc");
  assert.strictEqual(C.sanitize('+1'), "'+1");
  assert.strictEqual(C.sanitize('-1'), "'-1");
  assert.strictEqual(C.sanitize('@SUM(A1)'), "'@SUM(A1)");
  assert.strictEqual(C.sanitize('\tx'), "'\tx");
  assert.strictEqual(C.sanitize('normal'), 'normal');
});

test('a condition that looks like a formula is neutralised', () => {
  const sddl = 'D:AI(XA;OICI;FA;;;WD;(=1+1))';
  const csv = C.toCsv(S.parse(sddl));
  const rows = parseCsv(csv);
  const cond = rows[1][C.COLUMNS.indexOf('Condition')];
  assert.ok(cond.startsWith("'"), 'condition should be prefixed, got: ' + cond);
});

test('invalid parse yields a header-only CSV', () => {
  const csv = C.toCsv({ ok: false, error: { message: 'boom' } });
  const rows = parseCsv(csv);
  assert.strictEqual(rows.length, 1);
  assert.deepStrictEqual(rows[0], C.COLUMNS);
});

console.log('\n' + '-'.repeat(50));
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
