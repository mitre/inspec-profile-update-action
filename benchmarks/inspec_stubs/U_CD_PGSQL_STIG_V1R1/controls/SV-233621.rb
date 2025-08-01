control 'SV-233621' do
  title 'PostgreSQL must generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

In a SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', 'As the database administrator, verify pgaudit is enabled by running the following SQL: 

$ sudo su - postgres 
$ psql -c "SHOW shared_preload_libraries" 

If the output does not contain "pgaudit", this is a finding. 

Verify that role, read, write, and ddl auditing are enabled: 

$ psql -c "SHOW pgaudit.log" 

If the output does not contain role, read, write, and ddl, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

If logging is enabled, the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier. 

As the database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Edit the following parameters: 

log_connections = on 
log_line_prefix = '< %m %u %c: >' 
pgaudit.log = 'read, write' 

Where: 
* %m is the time and date 
* %u is the username 
* %c is the session ID for the connection 

As the system administrator, reload the server with the new configuration: 

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36815r607086_chk'
  tag severity: 'medium'
  tag gid: 'V-233621'
  tag rid: 'SV-233621r617333_rule'
  tag stig_id: 'CD12-00-012600'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-36780r607087_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
