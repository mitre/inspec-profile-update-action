control 'SV-82429' do
  title 'SQL Server must generate Trace or Audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to SQL Server.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', 'If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, verify that all required events are being audited.  From the query prompt:
SELECT * FROM sys.traces;
All currently defined traces for the SQL server instance will be listed.

If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should be among those listed; if not, this is a finding:

14  -- Audit Login
15  -- Audit Logout
16  -- Attention
17  -- ExistingConnection

If SQL Server Audit is in use, verify that the SUCCESSFUL_LOGIN_GROUP and LOGOUT_GROUP are enabled, as described in other STIG requirements; if not, this is a finding.'
  desc 'fix', 'Where SQL Server Trace is in use, define and enable a trace that captures all auditable events.  The script provided in the supplemental file Trace.sql can be used to do this.

Where SQL Server Audit is in use, enable the SUCCESSFUL_LOGIN_GROUP and LOGOUT_GROUP, as described in other STIG requirements.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68509r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67939'
  tag rid: 'SV-82429r1_rule'
  tag stig_id: 'SQL4-00-038000'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-74055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
