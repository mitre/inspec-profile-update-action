control 'SV-82269' do
  title 'SQL Server must produce Trace or Audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes, but is not limited to:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

SQL Server is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know the outcome of attempted actions. This requires specific information regarding the outcome of the action or event that the audit record is referring to. If outcome status information is not recorded and stored with the audit record, the record itself is of very limited use.

Success and failure indicators ascertain the outcome of a particular event. As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response. Without knowing the outcome of audit events, it is very difficult to accurately recreate the series of events during forensic analysis.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.

If Trace is enabled for auditing, SQL Server does capture the outcome status information in all audit records.

If SQL Server Audit is enabled, the [Succeeded] column in the audit output indicates the success or failure of the attempted action.  Be aware, however, that it may report True in some cases where one would intuitively expect False.  For example, SELECT 1/0 FROM SYS.ALL_OBJECTS will appear in the audit trail as successful, if the user has permission to perform that action, even though it contains an invalid expression.  Some other actions that one would consider failures (such as selecting from a table that does not exist) may not appear at all.'
  desc 'check', "If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Audit is in use, the Succeeded column is populated for all relevant events:  this is not a finding.

If SQL Server Trace is in use for audit purposes, verify that for all events it captures the Success flag (successful use of permissions), State and Error number (each where relevant).
From the query prompt:

SELECT * FROM sys.traces; 

All currently defined traces for the SQL server instance will be listed.

If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:

WITH 
EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo(#)),
E AS (SELECT DISTINCT eventid FROM EC)
SELECT
    E.eventid,
    CASE WHEN EC23.columnid IS NULL THEN 'Success (successful use of permissions) (23) missing' ELSE '23 OK' END AS field23,
    CASE WHEN EC30.columnid IS NULL THEN 'State (30) missing' ELSE '30 OK' END AS field30,
    CASE WHEN EC31.columnid IS NULL THEN 'Error (31) missing' ELSE '31 OK' END AS field31
FROM E E 
    LEFT OUTER JOIN EC EC23
        ON  EC23.eventid = E.eventid
        AND EC23.columnid = 23
    LEFT OUTER JOIN EC EC30
        ON  EC30.eventid = E.eventid
        AND EC30.columnid = 30
    LEFT OUTER JOIN EC EC31
        ON  EC31.eventid = E.eventid
        AND EC31.columnid = 31
WHERE
       EC23.columnid IS NULL OR EC30.columnid IS NULL OR EC31.columnid IS NULL;

If the resulting list indicates any field specifications are missing, this is a finding."
  desc 'fix', 'If Trace is in use for audit purposes, design and deploy a Trace  that captures the NT User Name, NT Domain Name, Host Name, Login Name, DB User Name and Login SID (each where relevant) for all auditable events.  The script provided in the supplemental file Trace.sql can be used to create a trace.

If SQL Server Audit is intended to be in use, design and deploy an Audit that captures all auditable events. The code provided in the supplemental file Audit.sql can be used as the basis for creating an Audit.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68345r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67779'
  tag rid: 'SV-82269r2_rule'
  tag stig_id: 'SQL4-00-012200'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-73893r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
