control 'SV-82393' do
  title 'SQL Server must produce Trace or Audit records of its enforcement of access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.

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

102 -- Audit Statement GDR Event
103 -- Audit Object GDR Event
104 -- Audit AddLogin Event
105 -- Audit Login GDR Event
106 -- Audit Login Change Property Event
107 -- Audit Login Change Password Event
108 -- Audit Add Login to Server Role Event
109 -- Audit Add DB User Event
110 -- Audit Add Member to DB Role Event
111 -- Audit Add Role Event
112 -- Audit App Role Change Password Event
113 -- Audit Statement Permission Event
115 -- Audit Backup/Restore Event
116 -- Audit DBCC Event
117 -- Audit Change Audit Event
118 -- Audit Object Derived Permission Event
128 -- Audit Database Management Event
129 -- Audit Database Object Management Event
130 -- Audit Database Principal Management Event
131 -- Audit Schema Object Management Event
132 -- Audit Server Principal Impersonation Event
133 -- Audit Database Principal Impersonation Event
134 -- Audit Server Object Take Ownership Event
135 -- Audit Database Object Take Ownership Event
152 -- Audit Change Database Owner
153 -- Audit Schema Object Take Ownership Event
162 -- User error message
170 -- Audit Server Scope GDR Event
171 -- Audit Server Object GDR Event
172 -- Audit Database Object GDR Event
173 -- Audit Server Operation Event
175 -- Audit Server Alter Trace Event
176 -- Audit Server Object Management Event
177 -- Audit Server Principal Management Event


If SQL Server Audit is in use, proceed as follows.

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
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name IN
(
'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_ACCESS_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP'
);
GO

Examine the list produced by the query.

If any of the audit action groups specified in the WHERE clause are not included in the list, this is a finding.

If the audited_result column is not  "SUCCESS AND FAILURE" on every row, this is a finding.)
  desc 'fix', 'Design and deploy a SQL Server Audit or Trace that captures all auditable events.  The script provided in the supplemental file Trace.sql can be used to create a trace.

Where SQL Server Audit is in use, design and deploy a SQL Server Audit that captures all auditable events.  The script provided in the supplemental file Audit.sql can be used for this.

Alternatively, to add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name>
 ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP),
 ADD (AUDIT_CHANGE_GROUP),
 ADD (BACKUP_RESTORE_GROUP),
 ADD (DATABASE_CHANGE_GROUP),
 ADD (DATABASE_OBJECT_ACCESS_GROUP),
 ADD (DATABASE_OBJECT_CHANGE_GROUP),
 ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
 ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
 ADD (DATABASE_OPERATION_GROUP),
 ADD (DATABASE_OWNERSHIP_CHANGE_GROUP),
 ADD (DATABASE_PERMISSION_CHANGE_GROUP),
 ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
 ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
 ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
 ADD (DBCC_GROUP),
 ADD (LOGIN_CHANGE_PASSWORD_GROUP),
 ADD (SCHEMA_OBJECT_CHANGE_GROUP),
 ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP),
 ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
 ADD (SERVER_OBJECT_CHANGE_GROUP),
 ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP),
 ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
 ADD (SERVER_OPERATION_GROUP),
 ADD (SERVER_PERMISSION_CHANGE_GROUP),
 ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),
 ADD (SERVER_STATE_CHANGE_GROUP),
 ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
 ADD (TRACE_CHANGE_GROUP)
;
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68473r4_chk'
  tag severity: 'medium'
  tag gid: 'V-67903'
  tag rid: 'SV-82393r3_rule'
  tag stig_id: 'SQL4-00-034000'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-74019r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
