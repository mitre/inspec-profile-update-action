control 'SV-224163' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

EDB Postgres Advanced Server may spawn additional external processes to execute procedures that are defined in EDB Postgres Advanced Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than EDB Postgres Advanced Server and provide unauthorized access to the host system.'
  desc 'check', %q(Check for EDB Postgres Advanced Server related programs that have been installed but not documented as approved. Open Control Program >> Programs >> Programs and Features. Look specifically for publishers of EnterpriseDB, pgAdmin, or PostgreSQL. If any programs are installed which are not documented as needed by the organization for the system, this is a finding.

The Postgres COPY command provides options for reading or writing files or running a program that the server has privileges to access. These options are only allowed for users who have been granted superuser privilege or have been granted the pg_read_server_files, pg_write_server_files, or pg_execute_server_program roles. The SUPERUSER privilege and the roles that provide access to files on the underlying server should only be granted to approved users.

To check for user and group roles that have been granted the SUPERUSER privilege, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 WITH RECURSIVE roles( granted_role_id, granted_role_name, role_id, role_name, can_login, how_superuser, root_role_name )
 AS (
 SELECT NULL::oid granted_role_id
 , NULL::name granted_role_name
 , r1.oid role_id
 , r1.rolname role_name
 , r1.rolcanlogin can_login
 , 'Assigned Superuser Privilege' how_superuser
 , r1.rolname root_role_name
 FROM pg_authid r1
 WHERE r1.rolsuper = 't'
 UNION
 SELECT m.roleid
 , r3.rolname
 , m.member
 , r2.rolname
 , r2.rolcanlogin
 , 'Granted Role with Superuser Privilege'
 , r1.root_role_name
 FROM pg_auth_members m
 JOIN pg_authid r2
 ON r2.oid = m.member
 JOIN pg_authid r3
 ON r3.oid = m.roleid
 JOIN roles r1
 ON m.roleid = r1.role_id
 )
 SELECT DISTINCT r.role_name, r.can_login, hs.how_superuser, gr.granted_roles, rr.root_superuser_roles
 FROM roles r
 JOIN ( SELECT role_name, string_agg(how_superuser, ', ') how_superuser 
 FROM ( SELECT DISTINCT role_name, how_superuser FROM roles ORDER BY 2 )
 GROUP BY role_name
 ) hs
 ON r.role_name = hs.role_name
 JOIN ( SELECT role_name, string_agg(granted_role_name, ', ') granted_roles
 FROM ( SELECT DISTINCT role_name, granted_role_name FROM roles ORDER BY 2 ) 
 GROUP BY role_name
 ) gr
 ON r.role_name = gr.role_name
 JOIN ( SELECT role_name, string_agg(root_role_name, ', ') root_superuser_roles 
 FROM ( SELECT DISTINCT role_name, root_role_name FROM roles ORDER BY 2 )
 GROUP BY role_name
 ) rr 
 ON r.role_name = rr.role_name
 ORDER BY 3,1;

The above query will list all user and group roles that have either been granted the SUPERUSER privilege explicitly or via one of the roles in the hierarchy of roles they have been granted.

If a user or group roles has the SUPERUSER privilege either directly or via one of the roles in the hierarchy of roles it has been granted, and the role is not documented as being approved to have this privilege, this is a finding.

To check for user and group roles that have been granted any of the pg_read_server_files, pg_write_server_files, or pg_execute_server_program roles, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 WITH RECURSIVE roles( granted_role_id, granted_role_name, role_id, role_name, can_login, root_role_name )
 AS (
 SELECT NULL::oid granted_role_id
 , NULL::name granted_role_name
 , r1.oid role_id
 , r1.rolname role_name
 , r1.rolcanlogin can_login
 , r1.rolname root_role_name
 FROM pg_authid r1
 WHERE r1.rolname IN ( 'pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program' )
 UNION
 SELECT m.roleid
 , r3.rolname
 , m.member
 , r2.rolname
 , r2.rolcanlogin
 , r1.root_role_name
 FROM pg_auth_members m
 JOIN pg_authid r2
 ON r2.oid = m.member
 JOIN pg_authid r3
 ON r3.oid = m.roleid
 JOIN roles r1
 ON m.roleid = r1.role_id
 )
 SELECT DISTINCT r.role_name, r.can_login, gr.granted_roles, rr.server_os_access_roles
 FROM roles r
 JOIN ( SELECT role_name, string_agg(granted_role_name, ', ') granted_roles
 FROM ( SELECT DISTINCT role_name, granted_role_name FROM roles ORDER BY 2 ) 
 GROUP BY role_name
 ) gr
 ON r.role_name = gr.role_name
 JOIN ( SELECT role_name, string_agg(root_role_name, ', ') server_os_access_roles 
 FROM ( SELECT DISTINCT role_name, root_role_name FROM roles ORDER BY 2 )
 GROUP BY role_name
 ) rr 
 ON r.role_name = rr.role_name
 WHERE gr.granted_roles IS NOT NULL
 ORDER BY 1;

The above query will list all user and group roles that have been granted one of these roles either explicitly or via one of the roles in the hierarchy of roles they have been granted.

If a user or group roles has been granted one of these roles either explicitly or via one of the roles in the hierarchy of roles they have been granted, and the role is not documented as being approved to have this role, this is a finding.

It is possible for a Postgres database extension to contain code that could access external executables via SQL. To list all installed extensions, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL ORDER BY 1;

If any extensions are installed that are not documented as being approved, this is a finding.

It is possible to create database functions that are written in C or other procedural languages that reference code in externally loaded modules that may enable interaction with the OS. To list such functions, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 SELECT n.nspname "Schema", p.proname "Function", p.prosrc "Source", p.probin "Library", l.lanname "Language"
 FROM pg_proc p
 JOIN pg_namespace n ON p.pronamespace = n.oid 
 JOIN pg_language l on p.prolang = l.oid 
 WHERE n.nspname NOT IN ('pg_catalog', 'sys', 'information_schema')
 AND (l .lanpltrusted = 'f' AND l.lanname != 'internal' )
 ORDER BY 4, 1, 2, 3;

If any C-language or other procedural language function is listed that is not documented as being approved, this is a finding.)
  desc 'fix', 'To uninstall programs that are not approved, open Control Program | Programs | Programs and Features. Select any programs that should not be installed, click the "uninstall" button, and follow the prompts to uninstall the software.

To remove the SUPERUSER privilege from a role, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 ALTER ROLE <role name> WITH NOSUPERUSER;

To remove a role that has been granted to another role, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 REVOKE ROLE <name of role to be removed> FROM <role name>;

To remove an extension from a Postgres database, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 DROP EXTENSION <name of extension to be removed>;

To remove a function from a Postgres database, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 DROP FUNCTION <name of function to be removed>;

If the unapproved function is contained in an EDB-SPL database package, drop the package specification and body or replace the package specification and package body source with an updated version of the source that does not include the unapproved function. 

To drop a package, execute the following SQL statements in psql or another EDB Postgres Advanced Server SQL client as enterprisedb:

 DROP PACKAGE BODY <name of package to be dropped>;
 DROP PACKAGE <name of package to be dropped>;

To update a package, execute the "CREATE OR REPLACE PACKAGE <package name>" and "CREATE OR REPLACE PACKAGE BODY <package name>" SQL statements in psql or another EDB Postgres Advanced Server SQL client. See the EnterpriseDB "Database Compatibility for Oracle Developers Reference Guide" for more information about the commands for creating, replacing, and dropping database packages.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25836r495507_chk'
  tag severity: 'medium'
  tag gid: 'V-224163'
  tag rid: 'SV-224163r508023_rule'
  tag stig_id: 'EP11-00-004000'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-25824r495508_fix'
  tag 'documentable'
  tag legacy: ['SV-109457', 'V-100353']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
