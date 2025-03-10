control 'SV-214105' do
  title 'PostgreSQL must generate audit records when privileges/permissions are modified.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, modifying permissions is typically done via the GRANT and REVOKE commands.'
  desc 'check', 'First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain pgaudit, this is a finding.

Next, verify that role is enabled:

$ psql -c "SHOW pgaudit.log"

If the output does not contain role, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit. 

With pgaudit installed the following configurations can be made: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameters (or edit existing parameters): 

pgaudit.log='role' 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15321r360946_chk'
  tag severity: 'medium'
  tag gid: 'V-214105'
  tag rid: 'SV-214105r508027_rule'
  tag stig_id: 'PGS9-00-006400'
  tag gtitle: 'SRG-APP-000495-DB-000328'
  tag fix_id: 'F-15319r360947_fix'
  tag 'documentable'
  tag legacy: ['V-72965', 'SV-87617']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
