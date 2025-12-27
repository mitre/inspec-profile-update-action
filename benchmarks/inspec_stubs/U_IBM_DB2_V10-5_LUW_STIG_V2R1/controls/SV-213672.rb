control 'SV-213672' do
  title 'DB2 must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS.  To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems.  If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', "Use the following query to determine if PUBLIC has been directly granted any privileges on objects in the database:

DB2> SELECT PRIVILEGE, OBJECTNAME, OBJECTSCHEMA, OBJECTTYPE FROM SYSIBMADM.PRIVILEGES WHERE AUTHID = 'PUBLIC'

If any rows are returned, this is a finding.

Use the following query to determine if PUBLIC has been granted membership in any database roles:

DB2> SELECT ROLENAME  FROM TABLE (SYSPROC.AUTH_LIST_ROLES_FOR_AUTHID ('PUBLIC', 'G') )

For each role returned by this query, determine if any privileges have been granted to it with the following query:

DB2> SELECT PRIVILEGE, OBJECTNAME, OBJECTSCHEMA, OBJECTTYPE FROM SYSIBMADM.PRIVILEGES WHERE AUTHID = '<rolename>' AND AUTHIDTYPE = 'R'

If any rows are returned, this is a finding.

Use the following query to determine if PUBLIC has been granted any database authorities directly or indirectly through a database role:

DB2> SELECT AUTHORITY, D_PUBLIC, ROLE_PUBLIC FROM TABLE(SYSPROC.AUTH_LIST_AUTHORITIES_FOR_AUTHID ('PUBLIC', 'G') )

If any of the rows have a ‘Y’ value in the D_PUBLIC column, this is a finding. If any of the rows have a ‘Y’ value in the ROLE_PUBLIC column, this is a finding."
  desc 'fix', "If a privilege is granted directly to PUBLIC, revoke it using the appropriate variation of the REVOKE statement specific to the object on which the privilege is granted. For example, if PUBLIC has EXECUTE privileges are on a package X.Y, revoke them using the REVOKE (package privileges).

DB2> REVOKE EXECUTE ON PACKAGE X.Y FROM PUBLIC

If a privilege has been granted indirectly to PUBLIC through membership in a database role, revoke membership in that database role from PUBLIC using the REVOKE (role) statement. 

DB2> REVOKE ROLE <role name> FROM PUBLIC

If an authority is granted directly to PUBLIC, revoke it using the appropriate variation of the REVOKE (database authorities) statement. For example, if the CONNECT row shows a ‘Y’ value in the D_PUBLIC column, revoke CONNECT authority using this statement: 

DB2> REVOKE CONNECT ON DATABASE FROM PUBLIC

If an authority is granted indirectly to PUBLIC through a database role, revoke membership in that database role from PUBLIC using the REVOKE (role) statement. 

DB2> REVOKE ROLE <role name> FROM PUBLIC

To determine what database roles PUBLIC belongs, issue this query:

DB2> SELECT ROLENAME  FROM TABLE (SYSPROC.AUTH_LIST_ROLES_FOR_AUTHID ('PUBLIC', 'G') )

Notes: To prevent the default assignment of authorities and privileges to PUBLIC when a database is created, one should use the restrictive option on the create database statement as demonstrated below:

DB2> CREATE DATABASE <dbname> RESTRICTIVE

One can determine if a database was created with restrictive by looking at the value of restrict_access database configuration parameter using the following command at the command prompt: 

$db2 get db cfg

http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000981.html?cp=SSEPGG_10.5.0%2F2-12-7-181&lang=en

As authorities and privileges can be granted to PUBLIC after the database is created, it is recommended to run the above checks on a regular basis."
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14893r295065_chk'
  tag severity: 'medium'
  tag gid: 'V-213672'
  tag rid: 'SV-213672r879530_rule'
  tag stig_id: 'DB2X-00-000400'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-14891r295066_fix'
  tag 'documentable'
  tag legacy: ['SV-89107', 'V-74433']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
