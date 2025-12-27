control 'SV-224201' do
  title 'The EDB Postgres Advanced Server must enforce access restrictions associated with changes to the configuration of the EDB Postgres Advanced Server or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the security configuration of the EDB Postgres database(s).

If EDB Postgres Advanced Server does not enforce access restrictions associated with changes to the configuration of the database(s), this is a finding.

- - - - -

To assist in conducting reviews of permissions, the following commands, which are run using psql, describe permissions of databases, schemas, and users:

\\l
\\dn+
\\du

Permissions of concern in this respect include the following, and possibly others:

- any user with SUPERUSER privileges
- any database or schema with "C" (create) or "w" (update) privileges that are not necessary

If any users are listed that have SUPERUSER privileges who are not authorized for these privileges, this is a finding.

If any user has create or update privileges on a database and schema who is not authorized for these privileges, this is a finding.'
  desc 'fix', 'Configure EDB Postgres Advanced Server to enforce access restrictions associated with changes to the configuration of the EDB Postgres database(s).

Remove superuser rights from unauthorized database users via the ALTER ROLE or ALTER USER SQL command.

 The syntax is:
 ALTER ROLE <role> NOSUPERUSER
 or
 ALTER USER <user> NOSUPERUSER

 Example: 
 ALTER ROLE testuser NOSUPERUSER;
 OR 
 ALTER USER testuser NOSUPERUSER;

Use the REVOKE SQL command to remove privileges from databases and schemas.

 For example:
 REVOKE ALL PRIVILEGES ON <table> FROM <role_name>;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25874r495621_chk'
  tag severity: 'medium'
  tag gid: 'V-224201'
  tag rid: 'SV-224201r508023_rule'
  tag stig_id: 'EP11-00-008500'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-25862r495622_fix'
  tag 'documentable'
  tag legacy: ['V-100423', 'SV-109527']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
