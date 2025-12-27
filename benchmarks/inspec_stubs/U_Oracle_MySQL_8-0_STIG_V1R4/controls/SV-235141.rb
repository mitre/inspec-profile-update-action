control 'SV-235141' do
  title 'The MySQL Database Server 8.0 must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the Database Management System (DBMS). To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', "Check MySQL settings to determine whether users are restricted from accessing objects and data they are not authorized to access. 
Review the system documentation to determine the required levels of protection for DBMS server securables, by type of login. 

Review the permissions actually in place on the server. 

If the actual permissions do not match the documented requirements, this is a finding. 

The following tables contain access control data. Run these scripts:

For information about database-level privileges:
The server uses the user and db tables in the mysql database at both the first and second stages of access control.
SELECT * FROM mysql.db;
SELECT * FROM mysql.user;

During the second stage of access control, the server performs request verification to ensure each client has sufficient privileges for each request it issues. 

These provide finer privilege control at the table and column levels.
SELECT * FROM mysql.tables_priv;
SELECT * FROM mysql.columns_priv;

For verification of requests that involve stored routines.
SELECT * FROM mysql.procs_priv;
Information about proxy accounts
SELECT * from mysql.proxies_priv;

Lists current assignments of dynamic global privileges to user accounts.
SELECT * from mysql.global_grants;
Lists default user roles
SELECT * FROM mysql.default_roles;

Lists edges for role subgraphs, showing roles assigned to other roles hierarchy.
SELECT * FROM mysql.role_edges;

To inspect permissions on specific table(s):
WITH
  tableprivs AS (SELECT user, host, 'mysql.tables_priv' as PRIV_SOURCE , DB as _db, Table_Name as _obj , ' ' as _col FROM mysql.tables_priv where Table_name like '%' ),
  colprivs AS (SELECT User, Host, 'mysql.columns_priv' as PRIV_SOURCE , DB as _db, table_name as _obj , column_name as _col FROM mysql.columns_priv WHERE Table_name like '%' )
SELECT user,host, PRIV_SOURCE , _db as _db, _obj, _col FROM
(
SELECT user,host, PRIV_SOURCE, _db, _obj, _col FROM colprivs UNION
SELECT user,host, PRIV_SOURCE, _db, _obj, _col FROM tableprivs) as tt group by user, host, PRIV_SOURCE, _db, _obj, _col;

To inspect specific user, role or user using role:
Example
User or role
SHOW GRANTS FOR 'app_developer'@'%';
User with Role
SHOW GRANTS FOR 'u1'@'localhost' USING 'r1';

If appropriate access controls are not implemented to restrict access to authorized users and to restrict the access of those users to objects and data they are authorized to see, this is a finding."
  desc 'fix', 'Configure the MySQL Database Server 8.0 settings and access controls to permit user access only to objects and data that the user is authorized to view or interact with, and to prevent access to all other objects and data.

Use GRANT, REVOKE, ALTER statements to add and remove permissions on server-level securables, bringing them into line with the documented requirements.'
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38360r623543_chk'
  tag severity: 'high'
  tag gid: 'V-235141'
  tag rid: 'SV-235141r879530_rule'
  tag stig_id: 'MYS8-00-005400'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-38323r623544_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
