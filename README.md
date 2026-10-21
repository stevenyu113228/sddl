# SDDL Viewer

A pure front-end web page that parses Windows SDDL (Security Descriptor
Definition Language) strings and renders them as readable tables.

No build step, no dependencies, no network calls. Open `index.html` in a
browser and paste a security descriptor.

## Usage

```sh
# just open the file
open index.html

# or serve it (needed if you want to load examples via ?sddl=)
python3 -m http.server 8765
```

Share a descriptor by putting it in the URL:

```
http://localhost:8765/index.html?sddl=O:BAG:SYD:(A;;GA;;;SY)
```

## What it decodes

| Part | Decoded into |
|---|---|
| `O:` / `G:` | Account name, `DOMAIN\Name`, full SID, alias explanation |
| ACL control flags | `P`, `AI`, `AR`, `NO_ACCESS_CONTROL` with descriptions |
| ACE type | Allow / Deny / Audit / Mandatory label / Resource attribute / Conditional |
| ACE flags | `OI`, `CI`, `NP`, `IO`, `ID`, `SA`, `FA`, `TP`, `CR` |
| Rights | Each two-letter code with its name and mask, plus a decoded bit list |
| Object GUIDs | AD extended rights and schema classes |
| Conditions | Conditional ACE expressions shown verbatim |

The decoded bit list adapts to the object type: `FA` is expanded into
`FILE_*` bits, `KA` into `KEY_*` bits, `RP`/`WP` into `ADS_RIGHT_*` bits.

## What it warns about

- Empty DACL (`D:`) means *deny everyone*, which is not the same as omitting `D:`
- `NO_ACCESS_CONTROL` together with ACEs (the ACEs are irrelevant)
- Audit ACEs without `SA` or `FA` (they will never fire)
- `SA`/`FA` on non-audit ACEs
- Object ACEs with no GUID
- Conditional ACEs with no condition
- Mandatory label ACEs with non-integrity rights
- Unknown SIDs, aliases, rights codes, flags and GUIDs
- Parse errors with a caret pointing at the exact offset

## Export

**Export CSV** writes one row per principal (`O:`, `G:`) and per ACE (`D:`,
`S:`), which is convenient for filtering and pivoting in a spreadsheet.

| Column | Contents |
|---|---|
| Section | `O`, `G`, `D` or `S` |
| ACE # | Index within its ACL |
| ACL Flags | `P AI`, `NO_ACCESS_CONTROL`, … repeated on every ACE row |
| Type Code / Type | `A` / `Access allowed` |
| ACE Flags / Flag Names | `OICI` / `Object inherit; Container inherit` |
| Trustee / Account / SID | Resolved name, `DOMAIN\Name`, full SID |
| Rights Codes / Right Names | `FA` / `File full control` |
| Access Mask / Decoded Bits | `0x001F01FF` / `FILE_READ_DATA FILE_LIST_DIRECTORY …` |
| Object GUID / Inherit GUID | GUID plus friendly name where known |
| Condition / Resource Attribute | Verbatim |
| Warnings | Semicolon-joined notes for that ACE |
| Raw | The original ACE text |

The file is UTF-8 with a BOM and CRLF line endings so Excel opens it correctly
on double-click. Cells starting with `=`, `+`, `-` or `@` are prefixed with a
single quote to prevent CSV formula injection.

**Download JSON** exports the full parse tree instead.

## Files

```
index.html            page shell
css/style.css         styles, light and dark via prefers-color-scheme
js/sddl-data.js       reference tables (SIDs, ACE types, flags, rights, GUIDs)
js/sddl-parser.js     the parser, no DOM dependencies, usable from Node
js/sddl-csv.js        CSV export, no DOM dependencies
js/app.js             rendering
tests/parser.test.js  parser tests
tests/csv.test.js     CSV export tests
```

`js/sddl-parser.js` and `js/sddl-csv.js` have no browser dependencies, so they
can be required from Node or bundled into another tool:

```js
const SDDL = require('./js/sddl-parser.js');
const CSV  = require('./js/sddl-csv.js');

const result = SDDL.parse('O:BAG:SYD:(A;;GA;;;WD)');
console.log(result.owner.name);                 // Built-in Administrators
console.log(result.dacl.aces[0].rights.codes);  // [ 'GA' ]

const csv = CSV.toCsv(result, { bom: true });   // string
```

## Tests

```sh
node tests/parser.test.js
node tests/csv.test.js
```

## References

- [Security Descriptor Definition Language](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-definition-language)
- [Security Descriptor String Format](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format)
- [ACE Strings](https://learn.microsoft.com/windows/win32/secauthz/ace-strings)
- [SID Strings](https://learn.microsoft.com/windows/win32/secauthz/sid-strings)
- [Well-known SIDs](https://learn.microsoft.com/windows/win32/secauthz/well-known-sids)
