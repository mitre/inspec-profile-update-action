control 'SV-224191' do
  title 'EDB Postgres Advanced Server must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Review system documentation to identify the required discretionary access control (DAC).

Review the security configuration of the database and EDB Postgres Advanced Server. If applicable, review the security configuration of the application(s) using the database.

If the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.

Check the EDB Postgres instance for the ownership and privileges assigned to database objects.

# Check for object ownership and privileges
# Check for database owners and granted privileges
To list all the databases contained in an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners and the privileges that have been granted on the databases, connect to a database as a database superuser using psql and execute the following psql command:

   \\l

Review the results of the above command.

If any database is owned by a user or group role that is not documented as being approved to own the database, this is a finding.

If any user or group role has been granted privileges on a database that is not documented and approved, this is a finding.
   
# Check for schema owners and granted privileges
To list all the schemas contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners and the privileges that have been granted on the schemas, connect to the database as a database superuser using psql and execute the following psql command:

   \\dn+ *
   
Review the results of the above command.

If any schema is owned by a user or group role that is not documented as being approved to own the schema, this is a finding.

If any user or group role has been granted privileges on a schema that is not documented and approved, this is a finding.

# Check for table, sequence, and view owners
To list all the tables, sequences, and views contained in a database within an EDB Postgres Advanced Server cluster (i.e., instance) as well as their owners, connect to the database as a database superuser using psql and execute the following psql commands: 
   \\dt *.*
   \\ds *.*
   \\dv *.*
   
Review the results of the above commands.

If any table, sequence, or view is owned by a user or group role that is not documented as being approved to own the object, this is a finding.

# Check for table, sequence, and view access privileges 
To list all the privileges that have been granted on the tables, sequences, and views in a database, connect to the database as a database superuser using psql and execute the following psql command:     

   \\dp *.*

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

If any user or group role has been granted privileges on a function or procedure that is not documented and approved, this is a finding.'
  desc 'fix', "Implement the organization's DAC policy in the security configuration of the database and EDB Postgres Advanced Server, and, if applicable, the security configuration of the application(s) using the database.

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

  http://www.postgresql.org/docs/current/static/sql-revoke.html"
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25864r495591_chk'
  tag severity: 'medium'
  tag gid: 'V-224191'
  tag rid: 'SV-224191r508023_rule'
  tag stig_id: 'EP11-00-007300'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-25852r495592_fix'
  tag 'documentable'
  tag legacy: ['SV-110301', 'V-101197']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
