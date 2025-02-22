control 'SV-238446' do
  title 'The DBA role must not be assigned excessive or unauthorized privileges.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account. 

Audit of privileged activity may require physical separation employing information systems on which the user does not have privileged access.

To limit exposure and provide forensic history of activity when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to organization-defined lists of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

If feasible, applications must provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.

DBAs, if assigned excessive privileges, could perform actions that endanger the information system or hide evidence of malicious activity.'
  desc 'check', %q(Review access permissions for objects owned by application owners or other non-administrative users.

If DBA or administrative accounts have unauthorized application roles or permissions beyond those needed for administration, this is a finding.

To obtain a list of privileges assigned to the DBMS user accounts, run the query:
SELECT * from dba_sys_privs where grantee='DBA' order by privilege;

To check to see what roles are assigned to a user, run the query:
SELECT * from dba_role_privs where grantee = '<applicable account>';

To check to see what privileges are assigned to a role, run the query:
SELECT * from role_sys_privs;

To show privileges by object, run the query:
SELECT table_name, grantee,
MAX(DECODE(privilege, 'SELECT', 'SELECT')) AS select_priv,
MAX(DECODE(privilege, 'DELETE', 'DELETE')) AS delete_priv,
MAX(DECODE(privilege, 'UPDATE', 'UPDATE')) AS update_priv,
MAX(DECODE(privilege, 'INSERT', 'INSERT')) AS insert_priv
FROM dba_tab_privs
WHERE grantee IN (SELECT role FROM dba_roles)
GROUP BY table_name, grantee
ORDER BY table_name, grantee;

This query will list the system privileges assigned to a specific user:
SELECT LPAD(' ', 2*level) || granted_role "USER PRIVS"
FROM 
(
SELECT NULL grantee, username granted_role
FROM dba_users
WHERE username LIKE UPPER('%&uname%')
UNION
SELECT grantee, granted_role
FROM dba_role_privs
UNION
SELECT grantee, privilege
FROM dba_sys_privs
)
START WITH grantee IS NULL
CONNECT BY grantee = prior granted_role;

To list all administrative privileges granted to users via roles, run the query:
SELECT 
username,
rp.granted_role,
privilege
FROM
dba_users u,
dba_role_privs rp,
dba_sys_privs sp
WHERE username = rp.grantee
AND rp.granted_role = sp.grantee
AND privilege NOT IN 
(
'CREATE SEQUENCE', 'CREATE TRIGGER',
'SET CONTAINER', 'CREATE CLUSTER',
'CREATE PROCEDURE', 'CREATE TYPE',
'CREATE SESSION', 'CREATE OPERATOR',
'CREATE TABLE', 'CREATE INDEXTYPE' 
)
AND username NOT IN 
(
'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM',
'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
'SYSMAN', 'APEX_040200', 'WMSYS', 'SYSDG',
'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
'SPATIAL_CSW_ADMIN_US','GSMCATUSER',
'OLAPSYS', 'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS',
'ORDDATA', 'OJVMSYS', 'ORACLE_OCM', 'MDSYS',
'ORDPLUGINS', 'GSMADMIN_INTERNAL', 'MDDATA',
'FLOWS_FILES', 'DIP', 'CTXSYS', 'AUDSYS', 'APPQOSSYS',
'APEX_PUBLIC_USER', 'ANONYMOUS',
'SPATIAL_CSW_ADMIN_USR', 'SYSKM',
'SYSMAN_TYPES', 'MGMT_VIEW', 'EUS_ENGINE_USER',
'EXFSYS', 'SYSMAN_APM','IX','OWBSYS'
) 
ORDER by 1, 2, 3;

(The list of special accounts that are excluded from this requirement may not be complete. It is expected that the DBA will edit the list to suit local circumstances, adding other special accounts as necessary, and removing any that are not supposed to be in use in the Oracle deployment that is under review. Similarly, the list of privileges excluded from the list may be modified according to circumstances.)

Data Dictionary Objects Related To System Privileges:
all_sys_privs
session_privs
user_sys_privs
dba_sys_privs
system_privilege_map)
  desc 'fix', 'Remove permissions from DBAs and other administrative users beyond those required for administrative functions.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41657r667510_chk'
  tag severity: 'medium'
  tag gid: 'V-238446'
  tag rid: 'SV-238446r667512_rule'
  tag stig_id: 'O112-C2-004300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41616r667511_fix'
  tag 'documentable'
  tag legacy: ['V-52393', 'SV-66609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
