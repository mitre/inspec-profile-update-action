control 'SV-81849' do
  title 'SQL Server must generate Trace or Audit records for organization-defined auditable events.'
  desc 'Audit records can be generated from various components within the information system (e.g., network interface, hard disk, modem, etc.). From an application perspective, certain specific application functionalities may be audited as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.  Examples are auditable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

Organizations define which application components shall provide auditable events.

The DBMS must provide auditing for the list of events defined by the organization or risk negatively impacting forensic investigations into malicious behavior in the information system.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', %q(If there are no locally-defined security tables or procedures, this is not applicable.

If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, verify that all required events are being audited. From the query prompt:
SELECT * FROM sys.traces;

All currently defined traces for the SQL server instance will be listed. If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should all be among those listed; if not, this is a finding.

Any additional events locally defined should also be in the list; if not, this is a finding.

14 -- Audit Login
15 -- Audit Logout
16 -- Attention
17 -- ExistingConnection
18 -- Audit Server Starts and Stops
20 -- Audit Login Failed
42 -- SP:Starting
43 -- SP:Completed
46 -- Object:Created
47 -- Object:Deleted
90 -- User-defined Event
102 -- Audit Database Scope GDR Event
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
164 -- Object:Altered
170 -- Audit Server Scope GDR Event
171 -- Audit Server Object GDR Event
172 -- Audit Database Object GDR Event
173 -- Audit Server Operation Event
175 -- Audit Server Alter Trace Event
176 -- Audit Server Object Management Event
177 -- Audit Server Principal Management Event
178 -- Audit Database Operation Event
180 -- Audit Database Object Access Event


If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses broad, server-level audit action groups for this purpose. SQL Server Audit's flexibility makes other techniques possible.

If an alternative technique is in use and demonstrated effective, this is not a finding.

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

If the audited_result column is not "SUCCESS AND FAILURE" on every row, this is a finding.

If any of the following audit action groups is not included in the list, this is a finding.

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
  desc 'fix', 'Design and deploy a SQL Server Audit or Trace that captures all auditable events.

The script provided in the supplemental file Trace.sql can be used to create a trace; edit it as necessary to capture any additional, locally-defined events.

The script provided in the supplemental file Audit.sql can be used to create an audit; edit it as necessary to capture any additional, locally-defined events.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67937r4_chk'
  tag severity: 'medium'
  tag gid: 'V-67359'
  tag rid: 'SV-81849r2_rule'
  tag stig_id: 'SQL4-00-011200'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-73471r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
