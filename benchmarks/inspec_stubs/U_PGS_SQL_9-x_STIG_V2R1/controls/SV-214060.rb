control 'SV-214060' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (functions, trigger procedures, links to software external to PostgreSQL, etc.) must be restricted to authorized users.'
  desc 'If PostgreSQL were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as "postgres"), list all users and their permissions by running the following SQL:

$ sudo su - postgres
$ psql -c "\\dp *.*"

Verify that all objects have the correct privileges. If they do not, this is a finding.

Next, as the database administrator (shown here as "postgres"), verify the permissions of the database directory on the filesystem:

$ ls -la ${PGDATA?}

If permissions of the database directory are not limited to an authorized user account, this is a finding.'
  desc 'fix', 'As the database administrator, revoke any permissions from a role that are deemed unnecessary by running the following SQL:

ALTER ROLE bob NOCREATEDB;
ALTER ROLE bob NOCREATEROLE;
ALTER ROLE bob NOSUPERUSER;
ALTER ROLE bob NOINHERIT;
REVOKE SELECT ON some_function FROM bob;'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15276r505254_chk'
  tag severity: 'medium'
  tag gid: 'V-214060'
  tag rid: 'SV-214060r508027_rule'
  tag stig_id: 'PGS9-00-001300'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-15274r505255_fix'
  tag 'documentable'
  tag legacy: ['V-72865', 'SV-87517']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
