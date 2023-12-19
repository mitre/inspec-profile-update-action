control 'SV-213817' do
  title 'SQL Server must produce Trace or Audit records containing sufficient information to establish the identity of any user/subject associated with the event.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly who performed a given action. If user identification information is not recorded and stored with the audit record, the record itself is of very limited use.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', "If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Audit is in use, the Principal Name columns are populated for all relevant events:  this is not a finding.

If SQL Server Trace is in use for audit purposes, verify that for all events it captures the NT User Name, NT Domain Name, Host Name, Login Name, DB User Name and Login SID (each where relevant).
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
    CASE WHEN EC6.columnid IS NULL THEN 'NT User Name (6) missing' ELSE '6 OK' END AS field26,
    CASE WHEN EC7.columnid IS NULL THEN 'NT Domain Name (7) missing' ELSE '7 OK' END AS field7,
    CASE WHEN EC8.columnid IS NULL THEN 'Host Name (8) missing' ELSE '8 OK' END AS field8,
    CASE WHEN EC11.columnid IS NULL THEN 'Login Name (11) missing' ELSE '11 OK' END AS field11,
    CASE WHEN EC40.columnid IS NULL THEN 'DB User Name (40) missing' ELSE '40 OK' END AS field40,
    CASE WHEN EC41.columnid IS NULL THEN 'Login SID (41) missing' ELSE '41 OK' END AS field41
FROM E E 
    LEFT OUTER JOIN EC EC6
        ON  EC6.eventid = E.eventid
        AND EC6.columnid = 6 
    LEFT OUTER JOIN EC EC7
        ON  EC7.eventid = E.eventid
        AND EC7.columnid = 7
    LEFT OUTER JOIN EC EC8
        ON  EC8.eventid = E.eventid
        AND EC8.columnid = 8
    LEFT OUTER JOIN EC EC11
        ON  EC11.eventid = E.eventid
        AND EC11.columnid = 11
    LEFT OUTER JOIN EC EC40
        ON  EC40.eventid = E.eventid
        AND EC40.columnid = 40
    LEFT OUTER JOIN EC EC41
        ON  EC41.eventid = E.eventid
        AND EC41.columnid = 41
WHERE
    EC6.columnid IS NULL OR EC7.columnid IS NULL OR EC8.columnid IS NULL
    OR EC11.columnid IS NULL OR EC40.columnid IS NULL OR EC41.columnid IS NULL;

If the resulting list indicates any field specifications are missing, this is a finding."
  desc 'fix', 'If Trace is in use for audit purposes, design and deploy a Trace  that captures the NT User Name, NT Domain Name, Host Name, Login Name, DB User Name and Login SID (each where relevant) for all auditable events.  The script provided in the supplemental file Trace.sql can be used to create a trace.

If SQL Server Audit is intended to be in use, design and deploy an Audit that captures all auditable events. The code provided in the supplemental file Audit.sql can be used as the basis for creating an Audit.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15036r312802_chk'
  tag severity: 'medium'
  tag gid: 'V-213817'
  tag rid: 'SV-213817r395736_rule'
  tag stig_id: 'SQL4-00-012300'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag fix_id: 'F-15034r312803_fix'
  tag 'documentable'
  tag legacy: ['SV-82271', 'V-67781']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
