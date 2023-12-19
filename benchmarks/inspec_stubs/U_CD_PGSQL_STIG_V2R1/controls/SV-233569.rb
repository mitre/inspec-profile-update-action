control 'SV-233569' do
  title 'PostgreSQL must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to PostgreSQL.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication, may indicate unauthorized account sharing, or may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this).'
  desc 'check', 'First, as the database administrator, verify that log_connections and log_disconnections are enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_connections"
$ psql -c "SHOW log_disconnections"

If either is off, this is a finding.

Next, verify that log_line_prefix contains sufficient information by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_line_prefix"

If log_line_prefix does not contain at least %m %u %d %c, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

First, as the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters as such:

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %d %c: >'

Where:
* %m is the time and date
* %u is the username
* %d is the database
* %c is the session ID for the connection

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36763r606930_chk'
  tag severity: 'medium'
  tag gid: 'V-233569'
  tag rid: 'SV-233569r606932_rule'
  tag stig_id: 'CD12-00-006200'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-36728r606931_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
