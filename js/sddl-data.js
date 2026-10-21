/*!
 * sddl-data.js — Reference tables for Windows SDDL
 *
 * Sources (Microsoft Learn):
 *   - SID Strings                https://learn.microsoft.com/windows/win32/secauthz/sid-strings
 *   - ACE Strings                https://learn.microsoft.com/windows/win32/secauthz/ace-strings
 *   - Security Descriptor Format https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format
 *   - Well-known SIDs            https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SDDLData = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   * ACL control flags (appear after D: / S:, before the ACE list)
   * ------------------------------------------------------------------ */
  var SD_FLAGS = {
    'NO_ACCESS_CONTROL': {
      code: 'NO_ACCESS_CONTROL',
      name: 'NULL ACL',
      en: 'SDDL_NULL_ACL',
      bit: 0x0004,
      desc: 'The ACL is NULL, which grants full access to everyone. High risk.'
    },
    'P': {
      code: 'P',
      name: 'Protected',
      en: 'SDDL_PROTECTED',
      bit: 0x1000,
      desc: 'SE_DACL_PROTECTED / SE_SACL_PROTECTED. Inheritable ACEs from the parent are not applied.'
    },
    'AR': {
      code: 'AR',
      name: 'Auto-inherit required',
      en: 'SDDL_AUTO_INHERIT_REQ',
      bit: 0x0100,
      desc: 'SE_DACL_AUTO_INHERIT_REQ. Asks the system to propagate inheritable ACEs.'
    },
    'AI': {
      code: 'AI',
      name: 'Auto-inherited',
      en: 'SDDL_AUTO_INHERITED',
      bit: 0x0400,
      desc: 'SE_DACL_AUTO_INHERITED. The ACL was produced by the system auto-inheritance mechanism.'
    }
  };

  // Longest first so greedy matching works
  var SD_FLAG_CODES = Object.keys(SD_FLAGS).sort(function (a, b) {
    return b.length - a.length;
  });

  /* ------------------------------------------------------------------ *
   * ACE types
   * ------------------------------------------------------------------ */
  var ACE_TYPES = {
    'A':  { code: 'A',  hex: 0x00, name: 'Access allowed',        en: 'ACCESS_ALLOWED_ACE_TYPE',                  kind: 'allow',   desc: 'Grants the listed access rights to the trustee.' },
    'D':  { code: 'D',  hex: 0x01, name: 'Access denied',         en: 'ACCESS_DENIED_ACE_TYPE',                   kind: 'deny',    desc: 'Denies the listed access rights to the trustee.' },
    'AU': { code: 'AU', hex: 0x02, name: 'Audit',                 en: 'SYSTEM_AUDIT_ACE_TYPE',                    kind: 'audit',   desc: 'Records successful and/or failed use of the rights (SACL only).' },
    'AL': { code: 'AL', hex: 0x03, name: 'Alarm',                 en: 'SYSTEM_ALARM_ACE_TYPE',                    kind: 'alarm',   desc: 'Legacy alarm ACE. Not implemented by Windows.' },
    'OA': { code: 'OA', hex: 0x05, name: 'Access allowed (object)', en: 'ACCESS_ALLOWED_OBJECT_ACE_TYPE',         kind: 'allow',   desc: 'Allows access to a specific AD property or extended right.' },
    'OD': { code: 'OD', hex: 0x06, name: 'Access denied (object)',  en: 'ACCESS_DENIED_OBJECT_ACE_TYPE',          kind: 'deny',    desc: 'Denies access to a specific AD property or extended right.' },
    'OU': { code: 'OU', hex: 0x07, name: 'Audit (object)',        en: 'SYSTEM_AUDIT_OBJECT_ACE_TYPE',             kind: 'audit',   desc: 'Audits access to a specific AD property or extended right.' },
    'OL': { code: 'OL', hex: 0x08, name: 'Alarm (object)',        en: 'SYSTEM_ALARM_OBJECT_ACE_TYPE',             kind: 'alarm',   desc: 'Object alarm ACE. Not implemented.' },
    'XA': { code: 'XA', hex: 0x09, name: 'Access allowed (conditional)', en: 'ACCESS_ALLOWED_CALLBACK_ACE_TYPE', kind: 'allow',   desc: 'Allows access only when the attached condition expression evaluates to true.' },
    'XD': { code: 'XD', hex: 0x0A, name: 'Access denied (conditional)',  en: 'ACCESS_DENIED_CALLBACK_ACE_TYPE',  kind: 'deny',    desc: 'Denies access when the attached condition expression evaluates to true.' },
    'ZA': { code: 'ZA', hex: 0x0B, name: 'Access allowed (conditional object)', en: 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE', kind: 'allow', desc: 'Object-specific conditional allow ACE.' },
    'XU': { code: 'XU', hex: 0x0F, name: 'Audit (conditional)',   en: 'SYSTEM_AUDIT_CALLBACK_ACE_TYPE',           kind: 'audit',   desc: 'Audit ACE with an attached condition expression.' },
    'ML': { code: 'ML', hex: 0x11, name: 'Mandatory label',       en: 'SYSTEM_MANDATORY_LABEL_ACE_TYPE',          kind: 'label',   desc: 'Defines the integrity level of the object for Mandatory Integrity Control.' },
    'RA': { code: 'RA', hex: 0x12, name: 'Resource attribute',    en: 'SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE',       kind: 'attr',    desc: 'Attaches a resource attribute to the object (dynamic access control).' },
    'SP': { code: 'SP', hex: 0x13, name: 'Scoped policy ID',      en: 'SYSTEM_SCOPED_POLICY_ID_ACE_TYPE',         kind: 'attr',    desc: 'Scoped policy ID used by central access policies.' },
    'TL': { code: 'TL', hex: 0x14, name: 'Process trust label',   en: 'SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE',      kind: 'label',   desc: 'Trust label used by Protected Process Light.' },
    'FL': { code: 'FL', hex: 0x15, name: 'Access filter',         en: 'SYSTEM_ACCESS_FILTER_ACE_TYPE',            kind: 'other',   desc: 'Access filter ACE.' }
  };

  /* ------------------------------------------------------------------ *
   * ACE flags (inheritance and auditing)
   * ------------------------------------------------------------------ */
  var ACE_FLAGS = {
    'OI': { code: 'OI', bit: 0x01,  name: 'Object inherit',       en: 'OBJECT_INHERIT_ACE',        desc: 'Inherited by child files and child objects.' },
    'CI': { code: 'CI', bit: 0x02,  name: 'Container inherit',    en: 'CONTAINER_INHERIT_ACE',     desc: 'Inherited by child containers and subdirectories.' },
    'NP': { code: 'NP', bit: 0x04,  name: 'No propagate inherit', en: 'NO_PROPAGATE_INHERIT_ACE',  desc: 'Propagates only one level; grandchildren do not inherit.' },
    'IO': { code: 'IO', bit: 0x08,  name: 'Inherit only',         en: 'INHERIT_ONLY_ACE',          desc: 'Does not apply to the object itself, only to children.' },
    'ID': { code: 'ID', bit: 0x10,  name: 'Inherited',            en: 'INHERITED_ACE',             desc: 'Inherited from the parent object.' },
    'TP': { code: 'TP', bit: 0x20,  name: 'Trust protected filter', en: 'TRUST_PROTECTED_FILTER_ACE_FLAG', desc: 'Used to filter access for protected processes.' },
    'SA': { code: 'SA', bit: 0x40,  name: 'Audit success',        en: 'SUCCESSFUL_ACCESS_ACE_FLAG', desc: 'Audit successful access (audit ACEs only).' },
    'FA': { code: 'FA', bit: 0x80,  name: 'Audit failure',        en: 'FAILED_ACCESS_ACE_FLAG',     desc: 'Audit failed access (audit ACEs only).' },
    'CR': { code: 'CR', bit: 0x100, name: 'Critical ACE',         en: 'CRITICAL_ACE_FLAG',          desc: 'Marks the ACE as critical.' }
  };

  var ACE_FLAG_CODES = Object.keys(ACE_FLAGS);

  /* ------------------------------------------------------------------ *
   * Access right codes
   *
   * The same two-letter code can mean different things depending on the
   * field it appears in. For example "KA" in the rights field is
   * KEY_ALL_ACCESS, but in the trustee field it is the Key Admins alias.
   * ------------------------------------------------------------------ */
  var RIGHTS = [
    // ---- Generic ----
    { code: 'GA', mask: 0x10000000, cat: 'generic',  name: 'Full control',       en: 'GENERIC_ALL',     desc: 'All rights to the object. Equivalent to FILE_ALL_ACCESS / KEY_ALL_ACCESS.' },
    { code: 'GR', mask: 0x80000000, cat: 'generic',  name: 'Generic read',       en: 'GENERIC_READ',    desc: 'Generic read access to the object and its properties.' },
    { code: 'GW', mask: 0x40000000, cat: 'generic',  name: 'Generic write',      en: 'GENERIC_WRITE',   desc: 'Generic write access to the object and its properties.' },
    { code: 'GX', mask: 0x20000000, cat: 'generic',  name: 'Generic execute',    en: 'GENERIC_EXECUTE', desc: 'Generic execute access (run a program, traverse a directory).' },

    // ---- Standard ----
    { code: 'RC', mask: 0x00020000, cat: 'standard', name: 'Read permissions',   en: 'READ_CONTROL',    desc: 'Read the security descriptor (DACL, owner, group).' },
    { code: 'SD', mask: 0x00010000, cat: 'standard', name: 'Delete',             en: 'DELETE',          desc: 'Delete the object.' },
    { code: 'WD', mask: 0x00040000, cat: 'standard', name: 'Change permissions', en: 'WRITE_DAC',       desc: 'Modify the DACL, i.e. rewrite everyone else\'s access.' },
    { code: 'WO', mask: 0x00080000, cat: 'standard', name: 'Take ownership',     en: 'WRITE_OWNER',     desc: 'Change the owner of the object.' },

    // ---- Directory service (Active Directory) ----
    { code: 'RP', mask: 0x00000010, cat: 'ds',       name: 'Read property',      en: 'ADS_RIGHT_DS_READ_PROP',    desc: 'Read properties of an AD object.' },
    { code: 'WP', mask: 0x00000020, cat: 'ds',       name: 'Write property',     en: 'ADS_RIGHT_DS_WRITE_PROP',   desc: 'Write properties of an AD object.' },
    { code: 'CC', mask: 0x00000001, cat: 'ds',       name: 'Create child',       en: 'ADS_RIGHT_DS_CREATE_CHILD', desc: 'Create child objects in a container.' },
    { code: 'DC', mask: 0x00000002, cat: 'ds',       name: 'Delete child',       en: 'ADS_RIGHT_DS_DELETE_CHILD', desc: 'Delete child objects from a container.' },
    { code: 'LC', mask: 0x00000004, cat: 'ds',       name: 'List children',      en: 'ADS_RIGHT_ACTRL_DS_LIST',   desc: 'List child objects of a container.' },
    { code: 'SW', mask: 0x00000008, cat: 'ds',       name: 'Self write',         en: 'ADS_RIGHT_DS_SELF',         desc: 'Perform a validated write (write to a specific property only).' },
    { code: 'LO', mask: 0x00000080, cat: 'ds',       name: 'List object',        en: 'ADS_RIGHT_DS_LIST_OBJECT',  desc: 'List the object in an access control list view.' },
    { code: 'DT', mask: 0x00000040, cat: 'ds',       name: 'Delete tree',        en: 'ADS_RIGHT_DS_DELETE_TREE',  desc: 'Delete an entire subtree.' },
    { code: 'CR', mask: 0x00000100, cat: 'ds',       name: 'Control access',     en: 'ADS_RIGHT_DS_CONTROL_ACCESS', desc: 'Extended right (for example reset password).' },

    // ---- File system ----
    { code: 'FA', mask: 0x001F01FF, cat: 'file',     name: 'File full control',  en: 'FILE_ALL_ACCESS',      desc: 'Full access to a file or folder.' },
    { code: 'FR', mask: 0x00120089, cat: 'file',     name: 'File read',          en: 'FILE_GENERIC_READ',    desc: 'Read data, attributes and extended attributes, plus read permissions and synchronize.' },
    { code: 'FW', mask: 0x00120116, cat: 'file',     name: 'File write',         en: 'FILE_GENERIC_WRITE',   desc: 'Write data, append data, attributes and extended attributes, plus read permissions and synchronize.' },
    { code: 'FX', mask: 0x001200A0, cat: 'file',     name: 'File execute',       en: 'FILE_GENERIC_EXECUTE', desc: 'Execute / traverse and read attributes, plus read permissions and synchronize.' },

    // ---- Registry key ----
    { code: 'KA', mask: 0x000F003F, cat: 'registry', name: 'Key full control',   en: 'KEY_ALL_ACCESS', desc: 'Full access to a registry key.' },
    { code: 'KR', mask: 0x00020019, cat: 'registry', name: 'Key read',           en: 'KEY_READ',       desc: 'Query values, enumerate subkeys, notify, plus read permissions.' },
    { code: 'KW', mask: 0x00020006, cat: 'registry', name: 'Key write',          en: 'KEY_WRITE',      desc: 'Set values and create subkeys, plus read permissions.' },
    { code: 'KX', mask: 0x00020019, cat: 'registry', name: 'Key execute',        en: 'KEY_EXECUTE',    desc: 'Same as KEY_READ.' },

    // ---- Mandatory integrity label ----
    { code: 'NR', mask: 0x00000001, cat: 'mandatory', name: 'No read up',   en: 'SYSTEM_MANDATORY_LABEL_NO_READ_UP',    desc: 'Lower-integrity processes may not read this object.' },
    { code: 'NW', mask: 0x00000002, cat: 'mandatory', name: 'No write up',  en: 'SYSTEM_MANDATORY_LABEL_NO_WRITE_UP',   desc: 'Lower-integrity processes may not write to this object.' },
    { code: 'NX', mask: 0x00000004, cat: 'mandatory', name: 'No execute up', en: 'SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP', desc: 'Lower-integrity processes may not execute this object.' }
  ];

  var RIGHTS_BY_CODE = {};
  RIGHTS.forEach(function (r) { RIGHTS_BY_CODE[r.code] = r; });

  var CATEGORY_NAMES = {
    generic: 'Generic rights',
    standard: 'Standard rights',
    ds: 'Directory service rights',
    file: 'File system rights',
    registry: 'Registry key rights',
    mandatory: 'Mandatory label rights'
  };

  /* ------------------------------------------------------------------ *
   * Single-bit names, used when decoding a raw hexadecimal access mask.
   * ctx '*' means the bit means the same thing on every object type.
   * ------------------------------------------------------------------ */
  var BITS = [
    { bit: 0x00000001, ctx: 'file',     name: 'FILE_READ_DATA',             desc: 'Read file data' },
    { bit: 0x00000001, ctx: 'file',     name: 'FILE_LIST_DIRECTORY',        desc: 'List directory contents' },
    { bit: 0x00000001, ctx: 'registry', name: 'KEY_QUERY_VALUE',            desc: 'Query key values' },
    { bit: 0x00000001, ctx: 'ds',       name: 'ADS_RIGHT_DS_CREATE_CHILD',  desc: 'Create child object' },

    { bit: 0x00000002, ctx: 'file',     name: 'FILE_WRITE_DATA',            desc: 'Write file data' },
    { bit: 0x00000002, ctx: 'file',     name: 'FILE_ADD_FILE',              desc: 'Add a file to a directory' },
    { bit: 0x00000002, ctx: 'registry', name: 'KEY_SET_VALUE',              desc: 'Set a key value' },
    { bit: 0x00000002, ctx: 'ds',       name: 'ADS_RIGHT_DS_DELETE_CHILD',  desc: 'Delete child object' },

    { bit: 0x00000004, ctx: 'file',     name: 'FILE_APPEND_DATA',           desc: 'Append data' },
    { bit: 0x00000004, ctx: 'file',     name: 'FILE_ADD_SUBDIRECTORY',      desc: 'Add a subdirectory' },
    { bit: 0x00000004, ctx: 'registry', name: 'KEY_CREATE_SUB_KEY',         desc: 'Create a subkey' },
    { bit: 0x00000004, ctx: 'ds',       name: 'ADS_RIGHT_ACTRL_DS_LIST',    desc: 'List children' },

    { bit: 0x00000008, ctx: 'file',     name: 'FILE_READ_EA',               desc: 'Read extended attributes' },
    { bit: 0x00000008, ctx: 'registry', name: 'KEY_ENUMERATE_SUB_KEYS',     desc: 'Enumerate subkeys' },
    { bit: 0x00000008, ctx: 'ds',       name: 'ADS_RIGHT_DS_SELF',          desc: 'Validated write' },

    { bit: 0x00000010, ctx: 'file',     name: 'FILE_WRITE_EA',              desc: 'Write extended attributes' },
    { bit: 0x00000010, ctx: 'registry', name: 'KEY_NOTIFY',                 desc: 'Subscribe to change notifications' },
    { bit: 0x00000010, ctx: 'ds',       name: 'ADS_RIGHT_DS_READ_PROP',     desc: 'Read properties' },

    { bit: 0x00000020, ctx: 'file',     name: 'FILE_EXECUTE',               desc: 'Execute' },
    { bit: 0x00000020, ctx: 'file',     name: 'FILE_TRAVERSE',              desc: 'Traverse a directory' },
    { bit: 0x00000020, ctx: 'registry', name: 'KEY_CREATE_LINK',            desc: 'Create a symbolic link' },
    { bit: 0x00000020, ctx: 'ds',       name: 'ADS_RIGHT_DS_WRITE_PROP',    desc: 'Write properties' },

    { bit: 0x00000040, ctx: 'file',     name: 'FILE_DELETE_CHILD',          desc: 'Delete a child' },
    { bit: 0x00000040, ctx: 'ds',       name: 'ADS_RIGHT_DS_DELETE_TREE',   desc: 'Delete a subtree' },

    { bit: 0x00000080, ctx: 'file',     name: 'FILE_READ_ATTRIBUTES',       desc: 'Read attributes' },
    { bit: 0x00000080, ctx: 'ds',       name: 'ADS_RIGHT_DS_LIST_OBJECT',   desc: 'List object' },

    { bit: 0x00000100, ctx: 'file',     name: 'FILE_WRITE_ATTRIBUTES',      desc: 'Write attributes' },
    { bit: 0x00000100, ctx: 'ds',       name: 'ADS_RIGHT_DS_CONTROL_ACCESS', desc: 'Control access (extended right)' },

    { bit: 0x00010000, ctx: '*',        name: 'DELETE',                     desc: 'Delete' },
    { bit: 0x00020000, ctx: '*',        name: 'READ_CONTROL',               desc: 'Read permissions' },
    { bit: 0x00040000, ctx: '*',        name: 'WRITE_DAC',                  desc: 'Change permissions' },
    { bit: 0x00080000, ctx: '*',        name: 'WRITE_OWNER',                desc: 'Take ownership' },
    { bit: 0x00100000, ctx: '*',        name: 'SYNCHRONIZE',                desc: 'Synchronize' },
    { bit: 0x01000000, ctx: '*',        name: 'ACCESS_SYSTEM_SECURITY',     desc: 'Access the system ACL (SACL)' },
    { bit: 0x10000000, ctx: '*',        name: 'GENERIC_ALL',                desc: 'Full control' },
    { bit: 0x20000000, ctx: '*',        name: 'GENERIC_EXECUTE',            desc: 'Generic execute' },
    { bit: 0x40000000, ctx: '*',        name: 'GENERIC_WRITE',              desc: 'Generic write' },
    { bit: 0x80000000, ctx: '*',        name: 'GENERIC_READ',               desc: 'Generic read' }
  ];

  /* ------------------------------------------------------------------ *
   * SID aliases (two-letter SDDL constants)
   *   sid     : the full SID. <domain> stands for the domain SID.
   * ------------------------------------------------------------------ */
  var SID_ALIASES = {
    AA: { sid: 'S-1-5-32-579', name: 'Access Control Assistance Operators', account: 'BUILTIN\\Access Control Assistance Operators' },
    AC: { sid: 'S-1-15-2-1',   name: 'All Application Packages',           account: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES' },
    AN: { sid: 'S-1-5-7',      name: 'Anonymous Logon',                    account: 'NT AUTHORITY\\ANONYMOUS LOGON' },
    AO: { sid: 'S-1-5-32-548', name: 'Account Operators',                  account: 'BUILTIN\\Account Operators' },
    AP: { sid: 'S-1-5-21-<domain>-525', name: 'Protected Users',           account: 'Protected Users' },
    AU: { sid: 'S-1-5-11',     name: 'Authenticated Users',                account: 'NT AUTHORITY\\Authenticated Users' },
    BA: { sid: 'S-1-5-32-544', name: 'Built-in Administrators',            account: 'BUILTIN\\Administrators' },
    BG: { sid: 'S-1-5-32-546', name: 'Built-in Guests',                    account: 'BUILTIN\\Guests' },
    BO: { sid: 'S-1-5-32-551', name: 'Backup Operators',                   account: 'BUILTIN\\Backup Operators' },
    BU: { sid: 'S-1-5-32-545', name: 'Built-in Users',                     account: 'BUILTIN\\Users' },
    CA: { sid: 'S-1-5-21-<domain>-517', name: 'Cert Publishers',           account: 'Cert Publishers' },
    CD: { sid: 'S-1-5-32-574', name: 'Certificate Service DCOM Access',    account: 'BUILTIN\\Certificate Service DCOM Access' },
    CG: { sid: 'S-1-3-1',      name: 'Creator Group',                      account: 'CREATOR GROUP' },
    CN: { sid: 'S-1-5-21-<domain>-522', name: 'Cloneable Domain Controllers', account: 'Cloneable Domain Controllers' },
    CO: { sid: 'S-1-3-0',      name: 'Creator Owner',                      account: 'CREATOR OWNER' },
    CY: { sid: 'S-1-5-32-569', name: 'Cryptographic Operators',           account: 'BUILTIN\\Cryptographic Operators' },
    DA: { sid: 'S-1-5-21-<domain>-512', name: 'Domain Admins',             account: 'Domain Admins' },
    DC: { sid: 'S-1-5-21-<domain>-515', name: 'Domain Computers',          account: 'Domain Computers' },
    DD: { sid: 'S-1-5-21-<domain>-516', name: 'Domain Controllers',        account: 'Domain Controllers' },
    DG: { sid: 'S-1-5-21-<domain>-514', name: 'Domain Guests',             account: 'Domain Guests' },
    DU: { sid: 'S-1-5-21-<domain>-513', name: 'Domain Users',              account: 'Domain Users' },
    EA: { sid: 'S-1-5-21-<domain>-519', name: 'Enterprise Admins',         account: 'Enterprise Admins' },
    ED: { sid: 'S-1-5-9',      name: 'Enterprise Domain Controllers',     account: 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' },
    EK: { sid: 'S-1-5-21-<domain>-527', name: 'Enterprise Key Admins',     account: 'Enterprise Key Admins' },
    ER: { sid: 'S-1-5-32-573', name: 'Event Log Readers',                  account: 'BUILTIN\\Event Log Readers' },
    ES: { sid: 'S-1-5-32-576', name: 'RDS Endpoint Servers',               account: 'BUILTIN\\RDS Endpoint Servers' },
    HA: { sid: 'S-1-5-32-578', name: 'Hyper-V Administrators',             account: 'BUILTIN\\Hyper-V Administrators' },
    HI: { sid: 'S-1-16-12288', name: 'High Integrity',                     account: 'Mandatory Label\\High Mandatory Level' },
    HO: { sid: 'S-1-5-32-584', name: 'User Mode Hardware Operators',       account: 'BUILTIN\\User Mode Hardware Operators' },
    IS: { sid: 'S-1-5-32-568', name: 'IIS_IUSRS',                          account: 'BUILTIN\\IIS_IUSRS' },
    IU: { sid: 'S-1-5-4',      name: 'Interactive Logon',                  account: 'NT AUTHORITY\\INTERACTIVE' },
    KA: { sid: 'S-1-5-21-<domain>-526', name: 'Key Admins',                account: 'Key Admins' },
    LA: { sid: 'S-1-5-21-<domain>-500', name: 'Local Administrator',       account: 'Administrator' },
    LG: { sid: 'S-1-5-21-<domain>-501', name: 'Local Guest',               account: 'Guest' },
    LS: { sid: 'S-1-5-19',     name: 'Local Service',                      account: 'NT AUTHORITY\\LOCAL SERVICE' },
    LU: { sid: 'S-1-5-32-559', name: 'Performance Log Users',              account: 'BUILTIN\\Performance Log Users' },
    LW: { sid: 'S-1-16-4096',  name: 'Low Integrity',                      account: 'Mandatory Label\\Low Mandatory Level' },
    ME: { sid: 'S-1-16-8192',  name: 'Medium Integrity',                   account: 'Mandatory Label\\Medium Mandatory Level' },
    MP: { sid: 'S-1-16-8448',  name: 'Medium Plus Integrity',              account: 'Mandatory Label\\Medium Plus Mandatory Level' },
    MU: { sid: 'S-1-5-32-558', name: 'Performance Monitor Users',          account: 'BUILTIN\\Performance Monitor Users' },
    NO: { sid: 'S-1-5-32-556', name: 'Network Configuration Operators',    account: 'BUILTIN\\Network Configuration Operators' },
    NS: { sid: 'S-1-5-20',     name: 'Network Service',                    account: 'NT AUTHORITY\\NETWORK SERVICE' },
    NU: { sid: 'S-1-5-2',      name: 'Network Logon',                      account: 'NT AUTHORITY\\NETWORK' },
    OW: { sid: 'S-1-3-4',      name: 'Owner Rights',                       account: 'OWNER RIGHTS' },
    PA: { sid: 'S-1-5-21-<domain>-520', name: 'Group Policy Creator Owners', account: 'Group Policy Creator Owners' },
    PO: { sid: 'S-1-5-32-550', name: 'Print Operators',                    account: 'BUILTIN\\Print Operators' },
    PS: { sid: 'S-1-5-10',     name: 'Principal Self',                     account: 'NT AUTHORITY\\SELF' },
    PU: { sid: 'S-1-5-32-547', name: 'Power Users',                        account: 'BUILTIN\\Power Users' },
    RA: { sid: 'S-1-5-32-575', name: 'RDS Remote Access Servers',          account: 'BUILTIN\\RDS Remote Access Servers' },
    RC: { sid: 'S-1-5-12',     name: 'Restricted Code',                    account: 'NT AUTHORITY\\RESTRICTED' },
    RD: { sid: 'S-1-5-32-555', name: 'Remote Desktop Users',               account: 'BUILTIN\\Remote Desktop Users' },
    RE: { sid: 'S-1-5-32-552', name: 'Replicator',                         account: 'BUILTIN\\Replicator' },
    RO: { sid: 'S-1-5-21-<domain>-498', name: 'Enterprise Read-only Domain Controllers', account: 'Enterprise Read-only Domain Controllers' },
    RS: { sid: 'S-1-5-32-553', name: 'RAS and IAS Servers',               account: 'BUILTIN\\RAS and IAS Servers' },
    RU: { sid: 'S-1-5-32-554', name: 'Pre-Windows 2000 Compatible Access', account: 'BUILTIN\\Pre-Windows 2000 Compatible Access' },
    SA: { sid: 'S-1-5-21-<domain>-518', name: 'Schema Admins',             account: 'Schema Admins' },
    SH: { sid: 'S-1-5-32-585', name: 'OpenSSH Users',                      account: 'BUILTIN\\OpenSSH Users' },
    SI: { sid: 'S-1-16-16384', name: 'System Integrity',                   account: 'Mandatory Label\\System Mandatory Level' },
    SO: { sid: 'S-1-5-32-549', name: 'Server Operators',                   account: 'BUILTIN\\Server Operators' },
    SS: { sid: 'S-1-18-1',     name: 'Service Asserted Identity',          account: 'AUTHENTICATION AUTHORITY\\Service asserted identity' },
    SU: { sid: 'S-1-5-6',      name: 'Service Logon',                      account: 'NT AUTHORITY\\SERVICE' },
    SY: { sid: 'S-1-5-18',     name: 'Local System',                       account: 'NT AUTHORITY\\SYSTEM' },
    UD: { sid: 'S-1-5-96-0',   name: 'User Mode Drivers',                  account: 'NT AUTHORITY\\USER MODE DRIVERS' },
    WD: { sid: 'S-1-1-0',      name: 'Everyone',                           account: 'Everyone' },
    WR: { sid: 'S-1-5-33',     name: 'Write Restricted Code',              account: 'NT AUTHORITY\\WRITE RESTRICTED' }
  };

  /* ------------------------------------------------------------------ *
   * Full SID -> name
   * ------------------------------------------------------------------ */
  var WELL_KNOWN_SIDS = {
    'S-1-0-0':  { name: 'Null SID',             account: 'NULL SID',            desc: 'A group with no members, used when a SID value is not known.' },
    'S-1-1-0':  { name: 'Everyone',             account: 'Everyone',            desc: 'A group that includes all users.' },
    'S-1-2-0':  { name: 'Local',                account: 'LOCAL',               desc: 'Users who log on to terminals physically connected to the system.' },
    'S-1-2-1':  { name: 'Console Logon',        account: 'CONSOLE LOGON',       desc: 'Users logged on at the physical console.' },
    'S-1-3-0':  { name: 'Creator Owner',        account: 'CREATOR OWNER',       desc: 'Placeholder in an inheritable ACE, replaced by the SID of the object creator.' },
    'S-1-3-1':  { name: 'Creator Group',        account: 'CREATOR GROUP',       desc: 'Replaced by the primary group of the object creator.' },
    'S-1-3-4':  { name: 'Owner Rights',         account: 'OWNER RIGHTS',        desc: 'Represents the object owner, used to limit the implicit rights of the owner.' },
    'S-1-5-1':  { name: 'Dialup Logon',         account: 'NT AUTHORITY\\DIALUP', desc: 'Users who log on using a dial-up modem.' },
    'S-1-5-2':  { name: 'Network Logon',        account: 'NT AUTHORITY\\NETWORK', desc: 'Users who log on across a network.' },
    'S-1-5-3':  { name: 'Batch Logon',          account: 'NT AUTHORITY\\BATCH', desc: 'Users who log on through a batch queue facility.' },
    'S-1-5-4':  { name: 'Interactive Logon',    account: 'NT AUTHORITY\\INTERACTIVE', desc: 'Users who log on for interactive operation.' },
    'S-1-5-6':  { name: 'Service Logon',        account: 'NT AUTHORITY\\SERVICE', desc: 'Accounts authorized to log on as a service.' },
    'S-1-5-7':  { name: 'Anonymous Logon',      account: 'NT AUTHORITY\\ANONYMOUS LOGON', desc: 'Anonymous or null session logon.' },
    'S-1-5-8':  { name: 'Proxy',                account: 'NT AUTHORITY\\PROXY', desc: 'Proxy identity.' },
    'S-1-5-9':  { name: 'Enterprise Domain Controllers', account: 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS', desc: 'All domain controllers in the enterprise.' },
    'S-1-5-10': { name: 'Principal Self',       account: 'NT AUTHORITY\\SELF',  desc: 'Replaced with the SID of the object itself during an access check.' },
    'S-1-5-11': { name: 'Authenticated Users',  account: 'NT AUTHORITY\\Authenticated Users', desc: 'All users whose identity has been authenticated.' },
    'S-1-5-12': { name: 'Restricted Code',      account: 'NT AUTHORITY\\RESTRICTED', desc: 'A restricted token created with CreateRestrictedToken.' },
    'S-1-5-13': { name: 'Terminal Server User', account: 'NT AUTHORITY\\Terminal Server User', desc: 'Users logged on to a terminal server.' },
    'S-1-5-14': { name: 'Remote Interactive Logon', account: 'NT AUTHORITY\\REMOTE INTERACTIVE LOGON', desc: 'Remote interactive logon.' },
    'S-1-5-17': { name: 'IUSR',                 account: 'NT AUTHORITY\\IUSR',  desc: 'IIS anonymous internet user.' },
    'S-1-5-18': { name: 'Local System',         account: 'NT AUTHORITY\\SYSTEM', desc: 'A special account used by the operating system. Highest privilege.' },
    'S-1-5-19': { name: 'Local Service',        account: 'NT AUTHORITY\\LOCAL SERVICE', desc: 'The Local Service account.' },
    'S-1-5-20': { name: 'Network Service',      account: 'NT AUTHORITY\\NETWORK SERVICE', desc: 'The Network Service account.' },
    'S-1-5-33': { name: 'Write Restricted Code', account: 'NT AUTHORITY\\WRITE RESTRICTED', desc: 'A write-restricted token.' },
    'S-1-5-96-0': { name: 'User Mode Drivers',  account: 'NT AUTHORITY\\USER MODE DRIVERS', desc: 'User-mode driver host.' },
    'S-1-5-113': { name: 'Local Account',       account: 'NT AUTHORITY\\LOCAL ACCOUNT', desc: 'A local (non-domain) account.' },
    'S-1-5-114': { name: 'Local Account and Member of Administrators', account: 'NT AUTHORITY\\LOCAL ACCOUNT AND MEMBER OF ADMINISTRATORS GROUP', desc: 'A local account that is also a member of the Administrators group.' },
    'S-1-15-2-1': { name: 'All Application Packages', account: 'ALL APPLICATION PACKAGES', desc: 'All applications running in an app package context.' },
    'S-1-15-2-2': { name: 'All Restricted Application Packages', account: 'ALL RESTRICTED APPLICATION PACKAGES', desc: 'All restricted app packages.' },
    'S-1-16-0':     { name: 'Untrusted Integrity',       account: 'Untrusted Mandatory Level', desc: 'Integrity level 0x0000.' },
    'S-1-16-4096':  { name: 'Low Integrity',             account: 'Low Mandatory Level',       desc: 'Integrity level 0x1000. Used by browser sandboxes.' },
    'S-1-16-8192':  { name: 'Medium Integrity',          account: 'Medium Mandatory Level',    desc: 'Integrity level 0x2000. Normal user processes.' },
    'S-1-16-8448':  { name: 'Medium Plus Integrity',     account: 'Medium Plus Mandatory Level', desc: 'Integrity level 0x2100.' },
    'S-1-16-12288': { name: 'High Integrity',            account: 'High Mandatory Level',      desc: 'Integrity level 0x3000. Elevated administrator processes.' },
    'S-1-16-16384': { name: 'System Integrity',          account: 'System Mandatory Level',    desc: 'Integrity level 0x4000. System services.' },
    'S-1-16-20480': { name: 'Protected Process Integrity', account: 'Protected Process Mandatory Level', desc: 'Integrity level 0x5000. Protected processes.' },
    'S-1-18-1': { name: 'Service Asserted Identity',     account: 'Service asserted identity', desc: 'An identity asserted by a service.' },
    'S-1-18-2': { name: 'Authentication Authority Asserted Identity', account: 'Authentication authority asserted identity', desc: 'An identity asserted by the authentication authority.' }
  };

  // Built-in domain aliases S-1-5-32-xxx
  var BUILTIN_ALIASES = {
    'S-1-5-32-544': { name: 'Built-in Administrators', account: 'BUILTIN\\Administrators' },
    'S-1-5-32-545': { name: 'Built-in Users',          account: 'BUILTIN\\Users' },
    'S-1-5-32-546': { name: 'Built-in Guests',         account: 'BUILTIN\\Guests' },
    'S-1-5-32-547': { name: 'Power Users',             account: 'BUILTIN\\Power Users' },
    'S-1-5-32-548': { name: 'Account Operators',       account: 'BUILTIN\\Account Operators' },
    'S-1-5-32-549': { name: 'Server Operators',        account: 'BUILTIN\\Server Operators' },
    'S-1-5-32-550': { name: 'Print Operators',         account: 'BUILTIN\\Print Operators' },
    'S-1-5-32-551': { name: 'Backup Operators',        account: 'BUILTIN\\Backup Operators' },
    'S-1-5-32-552': { name: 'Replicator',              account: 'BUILTIN\\Replicator' },
    'S-1-5-32-553': { name: 'RAS and IAS Servers',     account: 'BUILTIN\\RAS and IAS Servers' },
    'S-1-5-32-554': { name: 'Pre-Windows 2000 Compatible Access', account: 'BUILTIN\\Pre-Windows 2000 Compatible Access' },
    'S-1-5-32-555': { name: 'Remote Desktop Users',    account: 'BUILTIN\\Remote Desktop Users' },
    'S-1-5-32-556': { name: 'Network Configuration Operators', account: 'BUILTIN\\Network Configuration Operators' },
    'S-1-5-32-557': { name: 'Incoming Forest Trust Builders', account: 'BUILTIN\\Incoming Forest Trust Builders' },
    'S-1-5-32-558': { name: 'Performance Monitor Users', account: 'BUILTIN\\Performance Monitor Users' },
    'S-1-5-32-559': { name: 'Performance Log Users',   account: 'BUILTIN\\Performance Log Users' },
    'S-1-5-32-560': { name: 'Windows Authorization Access Group', account: 'BUILTIN\\Windows Authorization Access Group' },
    'S-1-5-32-561': { name: 'Terminal Server License Servers', account: 'BUILTIN\\Terminal Server License Servers' },
    'S-1-5-32-562': { name: 'Distributed COM Users',   account: 'BUILTIN\\Distributed COM Users' },
    'S-1-5-32-568': { name: 'IIS_IUSRS',               account: 'BUILTIN\\IIS_IUSRS' },
    'S-1-5-32-569': { name: 'Cryptographic Operators', account: 'BUILTIN\\Cryptographic Operators' },
    'S-1-5-32-571': { name: 'Cacheable Principals',    account: 'BUILTIN\\Cacheable Principals' },
    'S-1-5-32-572': { name: 'Non Cacheable Principals', account: 'BUILTIN\\Non Cacheable Principals' },
    'S-1-5-32-573': { name: 'Event Log Readers',       account: 'BUILTIN\\Event Log Readers' },
    'S-1-5-32-574': { name: 'Certificate Service DCOM Access', account: 'BUILTIN\\Certificate Service DCOM Access' },
    'S-1-5-32-575': { name: 'RDS Remote Access Servers', account: 'BUILTIN\\RDS Remote Access Servers' },
    'S-1-5-32-576': { name: 'RDS Endpoint Servers',    account: 'BUILTIN\\RDS Endpoint Servers' },
    'S-1-5-32-577': { name: 'RDS Management Servers',  account: 'BUILTIN\\RDS Management Servers' },
    'S-1-5-32-578': { name: 'Hyper-V Administrators',  account: 'BUILTIN\\Hyper-V Administrators' },
    'S-1-5-32-579': { name: 'Access Control Assistance Operators', account: 'BUILTIN\\Access Control Assistance Operators' },
    'S-1-5-32-580': { name: 'Remote Management Users', account: 'BUILTIN\\Remote Management Users' },
    'S-1-5-32-581': { name: 'System Managed Accounts Group', account: 'BUILTIN\\System Managed Accounts Group' },
    'S-1-5-32-582': { name: 'Storage Replica Administrators', account: 'BUILTIN\\Storage Replica Administrators' },
    'S-1-5-32-583': { name: 'Device Owners',           account: 'BUILTIN\\Device Owners' },
    'S-1-5-32-584': { name: 'User Mode Hardware Operators', account: 'BUILTIN\\User Mode Hardware Operators' },
    'S-1-5-32-585': { name: 'OpenSSH Users',           account: 'BUILTIN\\OpenSSH Users' }
  };

  // Domain-relative RIDs (S-1-5-21-x-y-z-RID)
  var DOMAIN_RIDS = {
    498: 'Enterprise Read-only Domain Controllers',
    500: 'Administrator',
    501: 'Guest',
    502: 'krbtgt',
    512: 'Domain Admins',
    513: 'Domain Users',
    514: 'Domain Guests',
    515: 'Domain Computers',
    516: 'Domain Controllers',
    517: 'Cert Publishers',
    518: 'Schema Admins',
    519: 'Enterprise Admins',
    520: 'Group Policy Creator Owners',
    521: 'Read-only Domain Controllers',
    522: 'Cloneable Domain Controllers',
    525: 'Protected Users',
    526: 'Key Admins',
    527: 'Enterprise Key Admins',
    553: 'RAS and IAS Servers',
    571: 'Cacheable Principals',
    572: 'Non Cacheable Principals'
  };

  /* ------------------------------------------------------------------ *
   * Well-known object GUIDs (AD schema classes and extended rights)
   * ------------------------------------------------------------------ */
  var OBJECT_GUIDS = {
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'Change password (User-Change-Password)',
    '00299570-246d-11d0-a768-00aa006e0529': 'Reset password (User-Force-Change-Password)',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'Account restrictions (User-Account-Restrictions)',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'Logon information (User-Logon)',
    'bf967aba-0de6-11d0-a285-00aa003049e2': 'user class',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'group class',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'computer class',
    'bf967aa5-0de6-11d0-a285-00aa003049e2': 'organizationalUnit class',
    'bf967a87-0de6-11d0-a285-00aa003049e2': 'container class',
    '19195a5b-6da0-11d0-afd3-00c04fd930c9': 'domainDNS class',
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1': 'groupPolicyContainer class',
    '28630eb8-41d5-11d1-a9c1-0000f80367c1': 'serviceConnectionPoint class'
  };

  /* ------------------------------------------------------------------ *
   * Sample SDDL strings shown in the UI
   * ------------------------------------------------------------------ */
  var EXAMPLES = [
    {
      name: 'Windows service (default)',
      sddl: 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
    },
    {
      name: 'Full security descriptor',
      sddl: 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)'
    },
    {
      name: 'File with inherited ACEs',
      sddl: 'O:S-1-5-21-1004336348-1177238915-682003330-512G:S-1-5-21-1004336348-1177238915-682003330-513D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)'
    },
    {
      name: 'Registry key',
      sddl: 'O:BAG:SYD:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)'
    },
    {
      name: 'Low integrity label',
      sddl: 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;LW)'
    },
    {
      name: 'Protected process light',
      sddl: 'O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;LW)(TL;;NR;;;SI)'
    },
    {
      name: 'AD object with property rights',
      sddl: 'O:DAG:DAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;AU)'
    },
    {
      name: 'Empty DACL (deny all)',
      sddl: 'O:BAG:SYD:'
    },
    {
      name: 'NULL DACL (everyone full)',
      sddl: 'O:BAG:SYD:NO_ACCESS_CONTROL'
    },
    {
      name: 'Conditional ACE',
      sddl: 'D:AI(XA;OICI;FA;;;WD;(Member_of {SID(S-1-5-32-544)}))'
    },
    {
      name: 'Resource attribute',
      sddl: 'D:AI(RA;CI;;;;S-1-1-0;(Project,TS,0,"Windows","SQL"))'
    },
    {
      name: 'Printer',
      sddl: 'O:BAG:SYD:(A;;LCSWSDRCWDWO;;;BA)(A;;LCSWSDRCWDWO;;;SY)(A;;LC;;;PU)(A;;LCSWSDRCWDWO;;;CO)(A;;LCSWSDRCWDWO;;;WD)'
    }
  ];

  return {
    SD_FLAGS: SD_FLAGS,
    SD_FLAG_CODES: SD_FLAG_CODES,
    ACE_TYPES: ACE_TYPES,
    ACE_FLAGS: ACE_FLAGS,
    ACE_FLAG_CODES: ACE_FLAG_CODES,
    RIGHTS: RIGHTS,
    RIGHTS_BY_CODE: RIGHTS_BY_CODE,
    CATEGORY_NAMES: CATEGORY_NAMES,
    BITS: BITS,
    SID_ALIASES: SID_ALIASES,
    WELL_KNOWN_SIDS: WELL_KNOWN_SIDS,
    BUILTIN_ALIASES: BUILTIN_ALIASES,
    DOMAIN_RIDS: DOMAIN_RIDS,
    OBJECT_GUIDS: OBJECT_GUIDS,
    EXAMPLES: EXAMPLES
  };
});
