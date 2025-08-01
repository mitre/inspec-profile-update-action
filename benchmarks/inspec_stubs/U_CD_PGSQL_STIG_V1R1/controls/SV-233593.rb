control 'SV-233593' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

PostgreSQLs may spawn additional external processes to execute procedures that are defined in PostgreSQL but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than PostgreSQL and provide unauthorized access to the host system.'
  desc 'check', %q(PostgreSQL's Copy command can interact with the underlying OS. Only superuser has access to this command.

First, as the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c "\du"

If any role has "superuser" that should not, this is a finding.

It is possible for an extension to contain code that could access external executables via SQL. To list all installed extensions, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -x -c "SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL"

If any extensions are installed that are not approved, this is a finding.)
  desc 'fix', 'To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"

To remove extensions from PostgreSQL, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "DROP EXTENSION extension_name"'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36787r607002_chk'
  tag severity: 'medium'
  tag gid: 'V-233593'
  tag rid: 'SV-233593r617333_rule'
  tag stig_id: 'CD12-00-009100'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-36752r607003_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
