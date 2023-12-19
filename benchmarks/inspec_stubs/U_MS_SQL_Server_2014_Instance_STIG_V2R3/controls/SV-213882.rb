control 'SV-213882' do
  title 'SQL Server must produce Trace or Audit records when unsuccessful attempts to access security objects occur.'
  desc "Changes to the security configuration must be tracked.  To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via SQL Server's built-in security functionality (GRANT, REVOKE, DENY, ALTER [SERVER] ROLE ... ADD/DROP MEMBER ..., etc.).

In SQL Server, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

Since the system views are read-only, and the underlying tables are kept hidden by SQL Server, the Insert, Update and Delete cases are relevant only where the database includes user-defined tables to support additional security functionality.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.  Note also that Trace does not support auditing of SELECT statements, whereas Audit does.

Use of SQL Server Audit's SCHEMA_OBJECT_ACCESS_GROUP causes capture of all accesses, successful and otherwise, to all schema-scoped objects.  The [Succeeded] column in the audit output indicates the success or failure of the attempted action.  Be aware, however, that it may report True in some cases where one would intuitively expect False.  For example, SELECT 1/0 FROM SYS.ALL_OBJECTS will appear in the audit trail as successful, if the user has permission to perform that action, even though it contains an invalid expression.  Some other actions that one would consider failures (such as selecting from a table that does not exist) may not appear at all."
  desc 'check', %q(If there are no locally-defined security tables, functions, or procedures, this is not applicable (NA).

If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

Obtain the list of locally-defined security tables that require tracking of Insert-Update-Delete operations.  

If SQL Server Trace is in use for audit purposes, review these tables for the existence of triggers to raise a custom event on each Insert-Update-Delete operation.

If such triggers are not present, this is a finding.

Check to see that all required event classes are being audited.  From the query prompt:
SELECT * FROM sys.traces; 

All currently defined traces for the SQL server instance will be listed.

If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should be among those listed; if not, this is a finding:

42  -- SP:Starting
43  -- SP:Completed
82-91  -- User-defined Event (at least one of these; 90 is used in the supplied script)
162 -- User error message


If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the broad, server-level audit action group SCHEMA_OBJECT_ACCESS_GROUP for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand 
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also, 
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all SELECT, INSERT, UPDATE, and DELETE actions on locally-defined permissions tables, and EXECUTE actions on locally-defined permissions functions and procedures, are being audited:

USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';

If no row is returned, this is a finding.

If the audited_result column is not "FAILURE" or "SUCCESS AND FAILURE", this is a finding.)
  desc 'fix', 'Where SQL Server Trace is in use, create triggers to raise a custom event on each table that requires tracking of Insert-Update-Delete operations.  The examples provided in the supplemental file CustomTraceEvents.sql can serve as the basis for these.  

Add a block of code to the supplemental file Trace.sql for each custom event class (integers in the range 82-91; the same event class may be used for all such triggers) used in these triggers.  Execute Trace.sql.

If SQL Server Audit is in use, design and deploy an Audit that captures all auditable events and data items.  The script provided in the supplemental file Audit.sql can be used as the basis for this.  Supplement the standard audit data as necessary, using Extended Events and/or triggers.

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
  tag check_id: 'C-15101r312997_chk'
  tag severity: 'medium'
  tag gid: 'V-213882'
  tag rid: 'SV-213882r400753_rule'
  tag stig_id: 'SQL4-00-035700'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-15099r312998_fix'
  tag 'documentable'
  tag legacy: ['SV-82409', 'V-67919']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
