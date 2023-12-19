control 'SV-213813' do
  title 'SQL Server must produce Trace or Audit records containing sufficient information to establish when the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes, but is not limited to:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

SQL Server is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when actions were performed. This requires specific information regarding the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', "If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Audit is in use, the event time and date are always captured: this is not a finding.

If SQL Server Trace is in use for audit purposes, verify that for all events it captures the start and (where relevant) end time.
From the query prompt:
SELECT * FROM sys.traces; 

All currently defined traces for the SQL server instance will be listed.

If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
WITH 
EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo(2)),
E AS (SELECT DISTINCT eventid FROM EC)
SELECT
    E.eventid,
       CASE WHEN EC14.columnid IS NULL THEN 'Start Time (14) missing' ELSE '14 OK' END AS field14,
       CASE WHEN EC15.columnid IS NULL THEN 'End Time (15) missing' ELSE '15 OK' END AS field15
FROM E E 
    LEFT OUTER JOIN EC EC14
        ON  EC14.eventid = E.eventid
        AND EC14.columnid = 14 
    LEFT OUTER JOIN EC EC15
        ON  EC15.eventid = E.eventid
        AND EC15.columnid = 15
WHERE
       EC14.columnid IS NULL OR EC15.columnid IS NULL;

If the resulting list indicates any field specifications are missing, this is a finding."
  desc 'fix', 'Design and deploy a SQL Server Audit or a Trace that captures Start Time and (where relevant) End Time for all auditable events.  

The script provided in the supplemental file Trace.sql can be used to create a trace.

The script provided in the supplemental file Audit.sql can be used to create an audit..'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15032r312790_chk'
  tag severity: 'medium'
  tag gid: 'V-213813'
  tag rid: 'SV-213813r395724_rule'
  tag stig_id: 'SQL4-00-011900'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag fix_id: 'F-15030r312791_fix'
  tag 'documentable'
  tag legacy: ['SV-82263', 'V-67773']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
