control 'SV-214107' do
  title 'PostgreSQL must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', 'First, as the database administrator, verify pgaudit is enabled by running the following SQL: 

$ sudo su - postgres 
$ psql -c "SHOW shared_preload_libraries" 

If the results does not contain pgaudit, this is a finding. 

Next, verify that role, read, write, and ddl auditing are enabled: 

$ psql -c "SHOW pgaudit.log" 

If the output does not contain role, read, write, and ddl, this is a finding. 

Next, verify that accessing the catalog is audited by running the following SQL: 

$ psql -c "SHOW pgaudit.log_catalog" 

If log_catalog is not on, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

Using pgaudit the DBMS (PostgreSQL) can be configured to audit these requests. See supplementary content `APPENDIX-B` for documentation on installing `pgaudit`. 

With pgaudit installed the following configurations can be made: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameters (or edit existing parameters): 

pgaudit.log_catalog = 'on' 
pgaudit.log='ddl, role, read, write' 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15323r360952_chk'
  tag severity: 'medium'
  tag gid: 'V-214107'
  tag rid: 'SV-214107r508027_rule'
  tag stig_id: 'PGS9-00-006600'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-15321r360953_fix'
  tag 'documentable'
  tag legacy: ['SV-87623', 'V-72971']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
