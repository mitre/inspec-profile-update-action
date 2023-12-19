control 'SV-220269' do
  title 'The DBMS must generate audit records for the DoD-selected list of auditable events, to the extent such information is available.'
  desc 'Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited, as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

Organizations may define the organizational personnel accountable for determining which application components shall provide auditable events.

Auditing provides accountability for changes made to the DBMS configuration or its objects and data. It provides a means to discover suspicious activity and unauthorized changes. Without auditing, a compromise may go undetected and without a means to determine accountability.

The Department of Defense has established the following as the minimum set of auditable events. Most can be audited via Oracle settings; some - marked here with an asterisk - cannot, and may require OS settings.
- Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g. classification levels).
- Successful and unsuccessful logon attempts, privileged activities or other system level access
- Starting and ending time for user access to the system, concurrent logons from different workstations.
- Successful and unsuccessful accesses to objects.
- All program initiations.
- *All direct access to the information system.
- All account creations, modifications, disabling, and terminations.
- *All kernel module loads, unloads, and restarts.'
  desc 'check', "Check DBMS settings to determine if auditing is being performed on the events on the DoD-selected list of auditable events that lie within the scope of Oracle audit capabilities:
- Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).
- Successful and unsuccessful logon attempts, privileged activities or other system-level access
- Starting and ending time for user access to the system, concurrent logons from different workstations.
- Successful and unsuccessful accesses to objects.
- All program initiations.
- All account creations, modifications, disabling, and terminations.

If auditing is not being performed for any of these events, this is a finding.

Notes on Oracle audit capabilities follow.

Unified Audit supports named audit policies, which are defined using the CREATE AUDIT POLICY statement. A policy specifies the actions that should be audited and the objects to which it should apply. If no specific objects are included in the policy definition, it applies to all objects.

A named policy is enabled using the AUDIT POLICY statement. It can be enabled for all users, for specific users only, or for all except a specified list of users. The policy can audit successful actions, unsuccessful actions, or both.

Verifying existing audit policy:  existing Unified Audit policies are listed in the view AUDIT_UNIFIED_POLICIES. The AUDIT_OPTION column contains one of the actions specified in a CREATE AUDIT POLICY statement. The AUDIT_OPTION_TYPE column contains 'STANDARD ACTION' for a policy that applies to all objects or 'OBJECT ACTION' for a policy that audits actions on a specific object.

select POLICY_NAME from SYS.AUDIT_UNIFIED_POLICIES where AUDIT_OPTION='GRANT' and AUDIT_OPTION_TYPE='STANDARD ACTION';

To find policies that audit privilege grants on specific objects:

select POLICY_NAME,OBJECT_SCHEMA,OBJECT_NAME from SYS.AUDIT_UNIFIED_POLICIES where AUDIT_OPTION='GRANT' and AUDIT_OPTION_TYPE='OBJECT ACTION';

The view AUDIT_UNIFIED_ENABLED_POLICIES shows which Unified Audit policies are enabled. The ENABLED_OPT and USER_NAME columns show the users for whom the policy is enabled or 'ALL USERS'. The SUCCESS and FAILURE columns indicate if the policy is enabled for successful or unsuccessful actions, respectively.

select POLICY_NAME,ENABLED_OPT,USER_NAME,SUCCESS,FAILURE from SYS.AUDIT_UNIFIED_ENABLED_POLICIES where POLICY_NAME='POLICY1';"
  desc 'fix', "Configure the DBMS's auditing settings to include auditing of events on the DoD-selected list of auditable events.

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels)

To audit granting and revocation of any privilege:
create audit policy policy1 actions grant;
create audit policy policy2 actions revoke;

To audit grants of object privileges on a specific object:
create audit policy policy3 actions grant on <schema>.<object>;

If Oracle Label Security is enabled, this will audit all OLS administrative actions:
create audit policy policy4 actions component = OLS all;

2) Successful and unsuccessful logon attempts, privileged activities or other system-level access
 
To audit all user logon attempts:
create audit policy policy5 actions logon;

To audit only logon attempts using administrative privileges (e.g. AS SYSDBA):
audit policy policy5 by SYS, SYSOPER, SYSBACKUP, SYSDG, SYSKM;

3) Starting and ending time for user access to the system, concurrent logons from different workstations

This policy will audit all logon and logoff events. An individual session is identified in the UNIFIED_AUDIT_TRAIL by the tuple (DBID, INSTANCE_ID, SESSIONID) and the start and end time will be indicated by the EVENT_TIMESTAMP of the logon and logoff events:
create audit policy policy6 actions logon, logoff;

4) Successful and unsuccessful accesses to objects

To audit all accesses to a specific table:
create audit policy policy7 actions select, insert, delete, alter on <schema>.<object>; 

Different actions are defined for other object types. To audit all supported actions on a specific object:
create audit policy policy8 actions all on <schema>.<object>;

5) All program initiations

To audit execution of any PL/SQL program unit:
create audit policy policy9 actions EXECUTE;

To audit execution of a specific function, procedure, or package:
create audit policy policy10 actions EXECUTE on <schema>.<object>;

6) All direct access to the information system

[Not applicable to Database audit. Monitor using OS auditing.]

7) All account creations, modifications, disabling, and terminations

To audit all user administration actions:
create audit policy policy11 actions create user, alter user, drop user, change password;

8) All kernel module loads, unloads, and restarts

[Not applicable to Database audit. Monitor using OS auditing.]

9) All database parameter changes

To audit any database parameter changes, dynamic or static:
create audit policy policy12 actions alter database, alter system, create spfile;

Applying the Policy

The following command will enable the policy in all database sessions and audit both successful and unsuccessful actions:
audit policy policy1;

To audit only unsuccessful actions, add the WHENEVER NOT SUCCESSFUL modifier:
audit policy policy1 whenever not successful;

Either command above can be limited to only database sessions started by a specific user as follows:
audit policy policy1 by <user>;
audit policy policy1 by <user> whenever not successful;"
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21984r391938_chk'
  tag severity: 'medium'
  tag gid: 'V-220269'
  tag rid: 'SV-220269r879561_rule'
  tag stig_id: 'O121-C2-007000'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-21976r391939_fix'
  tag 'documentable'
  tag legacy: ['SV-76115', 'V-61625']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
