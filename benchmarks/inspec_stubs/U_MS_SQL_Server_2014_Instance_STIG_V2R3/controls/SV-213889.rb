control 'SV-213889' do
  title 'SQL Server must generate Trace or Audit records for all privileged activities or other system-level access.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. This encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE
DENY

There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include:

TRUNCATE TABLE;
DELETE, or
DELETE affecting more than n rows, for some n, or
DELETE without a WHERE clause;

UPDATE or
UPDATE affecting more than n rows, for some n, or
UPDATE without a WHERE clause;

any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', %q(If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, verify that all required events are being audited.  From the query prompt:
SELECT * FROM sys.traces; 

All currently defined traces for the SQL server instance will be listed. If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should all be among those listed; if not, this is a finding:

46  -- Object:Created
47  -- Object:Deleted
82-91  -- User-defined Event (required only where there are locally-defined auditable actions)
115  -- Audit Backup/Restore Event
116  -- Audit DBCC Event
117  -- Audit Change Audit Event
118  -- Audit Object Derived Permission Event
128  -- Audit Database Management Event
129  -- Audit Database Object Management Event
130  -- Audit Database Principal Management Event
131  -- Audit Schema Object Management Event
164  -- Object:Altered
170  -- Audit Server Scope GDR Event
171  -- Audit Server Object GDR Event
172  -- Audit Database Object GDR Event
173  -- Audit Server Operation Event
175  -- Audit Server Alter Trace Event
176  -- Audit Server Object Management Event
177  -- Audit Server Principal Management Event

From the system security plan, obtain the list of any other actions considered privileged.  For each, verify that event IDs (and triggers, where necessary) have been defined to capture audit information for these.

If they have not, this is a finding.


If SQL Server Audit is in use, verify that execution of all CREATE, ALTER, DROP, GRANT, REVOKE and DENY statements, all execution of security-related functions and procedures, and all other actions locally defined as privileged, is audited.

If any such actions are not audited, this is a finding.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses broad, server-level audit action groups for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand 
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also, 
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following code to verify that all configuration-related actions are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>');
GO

Examine the list produced by the query.

If the audited_result column is not  "SUCCESS" or "SUCCESS AND FAILURE" on every row, this is a finding.

If any of the audit action groups listed below is not included in the query results, this is a finding.

If there are locally-defined privileged activities not encompassed by the list below and not tracked in any other way, this is a finding. 

APPLICATION_ROLE_CHANGE_PASSWORD_GROUP
AUDIT_CHANGE_GROUP
BACKUP_RESTORE_GROUP
DATABASE_CHANGE_GROUP
DATABASE_OBJECT_ACCESS_GROUP
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP
DATABASE_OPERATION_GROUP
DATABASE_OWNERSHIP_CHANGE_GROUP
DATABASE_PERMISSION_CHANGE_GROUP
DATABASE_PRINCIPAL_CHANGE_GROUP
DATABASE_PRINCIPAL_IMPERSONATION_GROUP
DATABASE_ROLE_MEMBER_CHANGE_GROUP
DBCC_GROUP
FAILED_LOGIN_GROUP
LOGIN_CHANGE_PASSWORD_GROUP
LOGOUT_GROUP
SCHEMA_OBJECT_ACCESS_GROUP
SCHEMA_OBJECT_CHANGE_GROUP
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP
SERVER_OBJECT_CHANGE_GROUP
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP
SERVER_OBJECT_PERMISSION_CHANGE_GROUP
SERVER_OPERATION_GROUP
SERVER_PERMISSION_CHANGE_GROUP
SERVER_PRINCIPAL_CHANGE_GROUP
SERVER_PRINCIPAL_IMPERSONATION_GROUP
SERVER_ROLE_MEMBER_CHANGE_GROUP
SERVER_STATE_CHANGE_GROUP
SUCCESSFUL_LOGIN_GROUP
TRACE_CHANGE_GROUP)
  desc 'fix', 'Where SQL Server Trace is in use, define  and enable a trace that captures all auditable events.  The script provided in the supplemental file Trace.sql can be used to do this.

For additional actions considered privileged, identify the available event class IDs, or define custom event class IDs (integers in the range 82-91).  Add blocks of code for these event IDs to Trace.sql.

Execute Trace.sql.

Define triggers as necessary to support data capture. 

Where SQL Server Audit is in use, design and deploy a SQL Server Audit that captures all auditable events.  The script provided in the supplemental file Audit.sql can be used to create an audit; supplement it as necessary to capture any additional, locally-defined privileged activity.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15108r313018_chk'
  tag severity: 'medium'
  tag gid: 'V-213889'
  tag rid: 'SV-213889r400846_rule'
  tag stig_id: 'SQL4-00-037700'
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag fix_id: 'F-15106r313019_fix'
  tag 'documentable'
  tag legacy: ['SV-82423', 'V-67933']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
