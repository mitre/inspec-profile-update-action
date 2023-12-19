control 'SV-82427' do
  title 'SQL Server must generate Trace or Audit records when logoffs or disconnections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to and off from SQL Server.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', %q(If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

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


If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the server-level audit action group LOGOUT_GROUP for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand 
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also, 
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all logons and connections are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'LOGOUT_GROUP';
GO

If no row is returned, this is a finding.

If the audited_result column is not "SUCCESS AND FAILURE", this is a finding.)
  desc 'fix', 'Where SQL Server Trace is in use, define and enable a trace that captures all auditable events.  The script provided in the supplemental file Trace.sql can be used to do this.

Where SQL Server Audit is in use, design and deploy a SQL Server Audit that captures all auditable events.  The script provided in the supplemental file Audit.sql can be used for this.

Alternatively, to add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD (LOGOUT_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68507r3_chk'
  tag severity: 'medium'
  tag gid: 'V-67937'
  tag rid: 'SV-82427r2_rule'
  tag stig_id: 'SQL4-00-037900'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-74053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
