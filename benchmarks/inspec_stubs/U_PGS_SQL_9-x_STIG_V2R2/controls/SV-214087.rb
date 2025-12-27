control 'SV-214087' do
  title 'PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to PostgreSQL. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

In this example the user joe will log into the Postgres database unsuccessfully:

$ psql -d postgres -U joe

As the database administrator (shown here as "postgres"), check pg_log for a FATAL connection audit trail:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/postgresql-Tue.log
< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >LOG: connection authorized: user=joe database=postgres
< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >FATAL: role "joe" does not exist

If an audit record is not generated each time a user (or other principal) attempts, but fails to log on or connect to PostgreSQL (including attempts where the user ID is invalid/unknown), this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

If logging is enabled the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier. 

First, as the database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Edit the following parameters: 

log_connections = on 
log_line_prefix = '< %m %u %c: >'  

Where: 
* %m is the time and date 
* %u is the username 
* %c is the session ID for the connection 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload)
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15303r360892_chk'
  tag severity: 'medium'
  tag gid: 'V-214087'
  tag rid: 'SV-214087r508027_rule'
  tag stig_id: 'PGS9-00-004600'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-15301r360893_fix'
  tag 'documentable'
  tag legacy: ['SV-87575', 'V-72923']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
