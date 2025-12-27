control 'SV-213812' do
  title 'Where SQL Server Audit is in use, SQL Server must generate audit records when privileges/permissions are retrieved.'
  desc 'The system must monitor who/what is reading privilege/permission/role information.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.

This requirement applies to SQL Server Audit-based audit trails; Trace does not have this capability.'
  desc 'check', %q(If SQL Server Trace is in use for audit purposes, and SQL Server Audit is not in use, this is not a finding.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the broad, server-level audit action group SCHEMA_OBJECT_ACCESS_GROUP for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand 
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also, 
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all SELECT actions on the permissions-related system views, and any locally-defined permissions tables, are being audited:

USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';

If no row is returned, this is a finding.

If the audited_result column is not "SUCCESS" or "SUCCESS AND FAILURE", this is a finding.)
  desc 'fix', 'Design and deploy a SQL Server Audit that captures all auditable events.  The script provided in the supplemental file Audit.sql can be used for this.

Alternatively, to add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD (SCHEMA_OBJECT_ACCESS_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15031r312787_chk'
  tag severity: 'medium'
  tag gid: 'V-213812'
  tag rid: 'SV-213812r395712_rule'
  tag stig_id: 'SQL4-00-011410'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-15029r312788_fix'
  tag 'documentable'
  tag legacy: ['SV-82259', 'V-67769']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
