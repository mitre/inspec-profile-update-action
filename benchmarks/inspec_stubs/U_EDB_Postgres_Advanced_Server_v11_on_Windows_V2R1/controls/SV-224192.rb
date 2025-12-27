control 'SV-224192' do
  title 'The EDB Postgres Advanced Server must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

System documentation should include a definition of the functionality considered privileged.

Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

A privileged function in the DBMS/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE

There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples include:

TRUNCATE TABLE;
DELETE, or
DELETE affecting more than n rows, for some n, or
DELETE without a WHERE clause;

UPDATE or
UPDATE affecting more than n rows, for some n, or
UPDATE without a WHERE clause;

any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.

Depending on the capabilities of the DBMS and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these.

In Postgres, a user or group role that has been granted the SUPERUSER privilege can perform any action in the database. As such, the SUPERUSER privilege should only be granted to a limited set of approved users. The SUPERUSER privilege can be assigned to a role when the role is created. It can also be assigned or removed from a role via an ALTER ROLE statement.

Postgres also provides the CREATEROLE, CREATEDB, REPLICATION, and BYPASSURLS privileges that can be granted to non-superuser roles to allow them to perform a limited set of privileged activities such as creating databases, creating user and group roles, managing replication slots, and bypassing row level security restrictions. Although not as all-encompassing as the SUPERUSER privilege, these privileges must only be granted to users who are approved to perform these activities. Like the SUPERUSER privilege, these privileges can be assigned to a role when the role is created. They can also be assigned or removed from a role via an ALTER ROLE statement. The PostgreSQL CREATE ROLE documentation provides more information about these privileges. See: https://www.postgresql.org/docs/current/sql-createrole.html

In addition to the SUPERUSER, CREATEDB, and CREATEROLE privileges, a user may be granted one or more default roles that provide access to certain privileged capabilities and activities. A listing and description of the default roles provided with Postgres is documented at the following link:

 https://www.postgresql.org/docs/current/default-roles.html

Roles and privileges on database objects can be granted to or revoked from a user using the GRANT and REVOKE statements. Users that are granted a role with the ADMIN OPTION can in turn grant the role to other users and roles. The ADMIN OPTION should only be granted to user and group roles that are approved to grant the roles. A description of the available privileges that may be granted to the different types of Postgres database objects is documented at the following link:

 https://www.postgresql.org/docs/current/ddl-priv.html

Also in Postgres, for most object types, object owners can perform any action on the objects they own, including dropping or altering them and assigning or revoking privileges on them. As such, database objects should only be owned by users who are approved to own them.

Another security risk to consider, is that Postgres can be extended with additional procedural languages that can be used to create user defined functions (i.e., not provided by EDB Postgres Advanced Server out-of-the-box). Some of these languages, such as pl/Python and pl/R are defined as "untrusted" languages. Any users who are granted access to these untrusted languages are able to run user defined functions to escalate privileges and perform unintended functions. These languages allow a Postgres database to be extended with additional capabilities that may be of benefit to a system. However, usage of these languages should only be granted to approved users for documented and approved purposes.'
  desc 'check', %q(Review the system documentation to obtain the definition of the EDB Postgres Advanced Server functionality considered privileged in the context of the system in question.

Review the EDB Postgres Advanced Server security configuration and/or other means used to protect privileged functionality from unauthorized use.

If the configuration does not protect all of the actions defined as privileged, this is a finding.

To list the user and group roles in an EDB Postgres Advanced Server along with the privileges that have been assigned to each role and the roles that have been granted to each role, execute the following command in psql as a database superuser:

 \du+

If any user or group role is assigned a privilege or is a member of a role that provides the ability to perform an action that is considered privileged and is not documented as being approved to have these privileges or roles, this is a finding.

# Check for SUPERUSER privilege
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

The above query will list all user and group roles that have either been granted the SUPERUSER privilege explicitly, or via one of the roles in the hierarchy of roles they have been granted.

If a user or group role has the SUPERUSER privilege either directly or via one of the roles in the hierarchy of roles it has been granted and the role is not documented as being approved to have this privilege, this is a finding.

# Check for CREATEROLE, CREATEDB, REPLICATION, and BYPASSURLS privileges
To check for user and group roles that have been granted the CREATEROLE, CREATEDB, REPLICATION, or BYPASSSRLS privileges, execute the following SQL statement in psql or another Postgres SQL client as enterprisedb:

 WITH RECURSIVE roles( granted_role_id, granted_role_name, role_id, role_name, can_login, how_privileged, root_role_name )
 AS (
 SELECT NULL::oid granted_role_id
 , NULL::name granted_role_name
 , r1.oid role_id
 , r1.rolname role_name
 , r1.rolcanlogin can_login
 , 'Assigned Privilege' how_privileged
 , r1.rolname root_role_name
 , pr.privilege
 , pr.sortkey
 FROM ( SELECT 1 sortkey, oid, 'CREATEROLE' privilege FROM pg_authid WHERE rolcreaterole = 't'
 UNION
 SELECT 2 sortkey, oid, 'CREATEDB' privilege FROM pg_authid WHERE rolcreatedb = 't'
 UNION
 SELECT 3 sortkey, oid, 'REPLICATION' privilege FROM pg_authid WHERE rolreplication = 't'
 UNION
 SELECT 4 sortkey, oid, 'BYPASSRLS' privilege FROM pg_authid WHERE rolbypassrls = 't'
 ) pr 
 JOIN pg_authid r1 ON pr.oid = r1.oid
 UNION
 SELECT m.roleid
 , r3.rolname
 , m.member
 , r2.rolname
 , r2.rolcanlogin
 , 'Granted Role with Privilege'
 , r1.root_role_name
 , r1.privilege
 , r1.sortkey
 FROM pg_auth_members m
 JOIN pg_authid r2
 ON r2.oid = m.member
 JOIN pg_authid r3
 ON r3.oid = m.roleid
 JOIN roles r1
 ON m.roleid = r1.role_id
 )
 SELECT DISTINCT r.sortkey, r.privilege, r.role_name, r.can_login, hs.how_privileged, gr.granted_roles, rr.root_roles_with_priv
 FROM roles r
 JOIN ( SELECT role_name, string_agg(how_privileged, ', ') how_privileged 
 FROM ( SELECT DISTINCT role_name, how_privileged FROM roles ORDER BY 2 )
 GROUP BY role_name
 ) hs
 ON r.role_name = hs.role_name
 JOIN ( SELECT role_name, string_agg(granted_role_name, ', ') granted_roles
 FROM ( SELECT DISTINCT role_name, granted_role_name FROM roles ORDER BY 2 ) 
 GROUP BY role_name
 ) gr
 ON r.role_name = gr.role_name
 JOIN ( SELECT role_name, string_agg(root_role_name, ', ') root_roles_with_priv 
 FROM ( SELECT DISTINCT role_name, root_role_name FROM roles ORDER BY 2 )
 GROUP BY role_name
 ) rr 
 ON r.role_name = rr.role_name
 ORDER BY r.sortkey, r.privilege, hs.how_privileged, r.role_name;

The above query will list all user and group roles that have either been granted the CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS privileges explicitly or via one of the roles in the hierarchy of roles they have been granted.

If a user or group role has one of these privileges either directly or via one of the roles in the hierarchy of roles it has been granted and the role is not documented as being approved to have this privilege, this is a finding.

# Check for default role assignments 
In addition to the SUPERUSER, CREATEDB, and CREATEROLE privileges, a user may be granted one or more default roles that provide access to certain privileged capabilities and activities. A listing and description of the default roles provided with Postgres is documented at the following link:

 https://www.postgresql.org/docs/current/default-roles.html

To check for user and group roles that have been granted a role, execute the following SQL statement in psql or another Postgres SQL client as a database administrator, replacing <ROLE NAME> with the name of the role to be checked:

 WITH RECURSIVE roles( granted_role_id, granted_role_name, role_id, role_name, can_login, root_role_name )
 AS (
 SELECT NULL::oid granted_role_id
 , NULL::name granted_role_name
 , r1.oid role_id
 , r1.rolname role_name
 , r1.rolcanlogin can_login
 , r1.rolname root_role_name
 FROM pg_authid r1
 WHERE r1.rolname = '<ROLE NAME>'
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

Note that in the above query, to do a check for more than one role in a single query, replace "r1.rolname = '<ROLE NAME>'" with a comma separated list of roles in an SQL "IN" clause (e.g., "r1.rolname IN ( '<ROLE 1 NAME>', '<ROLE 2 NAME>', 
<'ROLE N NAME'> )").

The above query will list all user and group roles that have been granted the specified role(s) either explicitly or via one of the roles in the hierarchy of roles they have been granted.

If a user or group role has been granted one of the default privileged roles explicitly or via one of the roles in the hierarchy of roles they have been granted, and the role is not documented as being approved to have this role, this is a finding.

# Check for object ownership and privileges
# Check for database owners and granted privileges
To list all the databases contained in an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners and the privileges that have been granted on the databases, connect to a database as a database superuser using psql and execute the following psql command:

 \l

Review the results of the above command.

If any database is owned by a user or group role that is not documented as being approved to own the database, this is a finding.

If any user or group role has been granted privileges on a database that is not documented and approved, this is a finding.

# Check for schema owners and granted privileges
To list all the schemas contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners and the privileges that have been granted on the schemas, connect to the database as a database superuser using psql and execute the following psql command:

 \dn+ *

Review the results of the above command.

If any schema is owned by a user or group role that is not documented as being approved to own the schema, this is a finding.

If any user or group role has been granted privileges on a schema that is not documented and approved, this is a finding.

# Check for table, sequence, and view owners
To list all the tables, sequences, and views contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners, connect to the database as a database superuser using psql and execute the following psql commands: 
 \dt *.*
 \ds *.*
 \dv *.*

Review the results of the above commands.

If any table, sequence, or view is owned by a user or group role that is not documented as being approved to own the object, this is a finding.

# Check for table, sequence, and view access privileges 
To list all the privileges that have been granted on the tables, sequences, and views in a database, connect to the database as a database superuser using psql and execute the following psql command: 

 \dp *.*

Review the results of the above command.

If any user or group role has been granted privileges on an object that is not documented and approved, this is a finding.

# Check for function/procedure owners and access privileges
To list all the functions and procedures contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners and the privileges that have been granted on the schemas, connect to the database as a database superuser using psql and execute the following SQL statement:

 SELECT r.rolname as owner
 , n.nspname as namespace
 , p.proname as name
 , pg_get_function_identity_arguments(p.oid)
 , p.prokind as kind
 , p.proacl as access_privileges
 FROM pg_proc p 
 JOIN pg_namespace n ON p.pronamespace = n.oid
 JOIN pg_authid r ON p.proowner = r.oid
 ORDER BY 1, 2, 3, 4;

Review the results of the above query.

If any function or procedure is owned by a user or group role that is not documented as being approved to own the object, this is a finding.

If any user or group role has been granted privileges on a function or procedure that is not documented and approved, this is a finding.

# Check for additional installed procedural languages
To list the procedural languages that are available for use in a database within an EDB Postgres Advanced Server database, connect to the database as a database superuser using psql and execute the following psql command: 

 \dL+

Review the results of the above command. A value of "f" in the "Trusted" column of the results indicates that the language is defined as an "untrusted" language. If no Access Privileges are listed for a particular language, this means that default privileges are assigned. In Postgres, unless overridden by using the ALTER DEFAULT PRIVILEGES command, the USAGE privilege on languages is assigned to PUBLIC by default.

If any "untrusted" language is listed in the results of the above command and not approved for use by the system, this is finding.

If any user or group role has been granted USAGE on an "untrusted" language that is not documented and approved, this is a finding.

# Check for functions that are written in untrusted procedural languages
To check whether any user defined functions contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) are written in an untrusted procedural language, connect to the database as a database superuser using psql and execute the following SQL statement:

 SELECT n.nspname "Schema", p.proname "Function", p.prosrc "Source", p.probin "Library", l.lanname "Language", p.proacl "Access Privileges"
 FROM pg_proc p
 JOIN pg_namespace n ON p.pronamespace = n.oid 
 JOIN pg_language l on p.prolang = l.oid 
 WHERE (l .lanpltrusted = 'f' AND l.lanname != 'internal' )
 AND n.nspname NOT IN ('pg_catalog', 'sys', 'information_schema')
 ORDER BY 5, 1, 2;

Review the results of the above query. Note that if no Access Privileges are listed for a particular function, this means that default privileges are assigned. In Postgres, unless overridden by using the ALTER DEFAULT PRIVILEGES command, the EXECUTE privilege on functions is assigned to PUBLIC by default.

If any user defined function is listed and is not documented as being approved for use, this is a finding.

If any user defined function is listed and is documented as being approved, but has execute privilege granted to a user or group role that has not been documented as having been approved for this permission, this is a finding.)
  desc 'fix', 'Update system documentation to accurately identify all user and group roles that are authorized to perform privileged actions.

If the SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS privileges have been assigned to a user or group role that is not approved to have these privileges, remove the privilege using the ALTER ROLE SQL command as necessary.

 The syntax is:
 ALTER ROLE <role> NOSUPERUSER
 ALTER ROLE <role> NOCREATEROLE
 ALTER ROLE <role> NOCREATEDB
 ALTER ROLE <role> NOREPLICATION
 ALTER ROLE <role> NOBYPASSURLS

 Examples: 
 ALTER ROLE testuser NOSUPERUSER
 ALTER ROLE testuser NOCREATEROLE
 ALTER ROLE testuser NOCREATEDB
 ALTER ROLE testuser NOREPLICATION
 ALTER ROLE testuser NOBYPASSURLS

If an unapproved user or group role is the owner of a database object, change the owner to an approved user or group role using one of the following ALTER SQL commands as appropriate:

 The syntax is:
 ALTER DATABASE <database name> OWNER TO <new_owner>
 ALTER SCHEMA <schema name> OWNER TO <new_owner>
 ALTER TABLE <table name> OWNER TO <new_owner>
 ALTER SEQUENCE <sequence name> OWNER TO <new_owner>
 ALTER VIEW <view name> OWNER TO <new_owner>
 ALTER FUNCTION <function name> (<args>) OWNER TO <new_owner>
 ALTER PROCEDURE <procedure name> (<args>) OWNER TO <new_owner>

 Examples:
 ALTER DATABASE test_db OWNER TO app_admin
 ALTER SCHEMA test_schema OWNER TO app_admin
 ALTER TABLE test_tbl OWNER TO app_admin
 ALTER SEQUENCE test_seq OWNER TO app_admin
 ALTER VIEW test_vw OWNER TO app_admin
 ALTER FUNCTION test_func (p1 numeric, p2 text) OWNER TO app_admin
 ALTER PROCEDURE test_proc (p1 numeric, p2 text) OWNER TO app_admin

If a user or group role has been granted an unapproved role or object privilege, execute the appropriate REVOKE command as documented here:

 http://www.postgresql.org/docs/current/static/sql-revoke.html

Update the system documentation to identify the intended use, scope, and justification for any "untrusted" procedural languages that are being used for user defined functions as well as the users who are approved to use these languages and corresponding functions.

If an unapproved user defined function exists, remove it from the database by executing the DROP FUNCTION SQL command as documented here:

 https://www.postgresql.org/docs/current/sql-dropfunction.html

If an unapproved procedural language is installed, remove it from the database by executing the following SQL command:

 DROP EXTENSION <extension_name>'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25865r495594_chk'
  tag severity: 'medium'
  tag gid: 'V-224192'
  tag rid: 'SV-224192r508023_rule'
  tag stig_id: 'EP11-00-007400'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-25853r495595_fix'
  tag 'documentable'
  tag legacy: ['SV-109509', 'V-100405']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
