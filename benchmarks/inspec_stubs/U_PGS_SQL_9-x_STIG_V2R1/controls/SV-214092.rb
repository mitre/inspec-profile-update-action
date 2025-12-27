control 'SV-214092' do
  title 'PostgreSQL must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to PostgreSQL.'
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

First, as the database administrator (shown here as "postgres"), check if log_connections is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_connections"

If log_connections is off, this is a finding.

Next, verify the logs that the previous connection to the database was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-02-16 15:54:03.934 EST postgres postgres 56c64b8b.aeb: >LOG: connection authorized: user=postgres database=postgres

If an audit record is not generated each time a user (or other principal) logs on or connects to PostgreSQL, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

If logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier. 

First, as the database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Edit the following parameters as such: 

log_connections = on 
log_line_prefix = '< %m %u %d %c: >'  

Where: 
* %m is the time and date 
* %u is the username 
* %d is the database 
* %c is the session ID for the connection 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?} 

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload)
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15308r360907_chk'
  tag severity: 'medium'
  tag gid: 'V-214092'
  tag rid: 'SV-214092r508027_rule'
  tag stig_id: 'PGS9-00-005100'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-15306r360908_fix'
  tag 'documentable'
  tag legacy: ['V-72933', 'SV-87585']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
