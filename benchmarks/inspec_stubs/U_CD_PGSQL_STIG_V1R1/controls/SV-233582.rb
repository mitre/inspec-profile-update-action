control 'SV-233582' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc "Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.

1) Linux's sudo and su feature enables a user (with sufficient OS privileges) to emulate another user, and it is the identity of the emulated user that is seen by PostgreSQL and logged in the audit trail. Therefore, care must be taken (outside of Postgresql) to restrict sudo/su to the minimum set of users necessary.

2) PostgreSQL's SET ROLE feature enables a user (with sufficient PostgreSQL privileges) to emulate another user running statements under the permission set of the emulated user. In this case, it is the emulating user's identity, and not that of the emulated user, that gets logged in the audit trail. While this is definitely better than the other way around, ideally, both identities would be recorded."
  desc 'check', 'Check PostgreSQL settings and existing audit records to verify a user name associated with the event is being captured and stored with the audit records. If audit records exist without specific user information, this is a finding.

First, as the database administrator (shown here as "postgres"), verify the current setting of log_line_prefix by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_line_prefix"

If log_line_prefix does not contain %m, %u, %d, %p, %r, %a, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Logging must be enabled in order to capture the identity of any user/subject or process associated with an event. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

To enable username, database name, process ID, remote host/port and application name in logging, as the database administrator (shown here as "postgres"), edit the following in postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_line_prefix = '< %m %u %d %p %r %a >'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36776r606969_chk'
  tag severity: 'medium'
  tag gid: 'V-233582'
  tag rid: 'SV-233582r617333_rule'
  tag stig_id: 'CD12-00-007800'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag fix_id: 'F-36741r606970_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
