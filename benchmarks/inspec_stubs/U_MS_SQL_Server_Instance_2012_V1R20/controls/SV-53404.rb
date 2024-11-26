control 'SV-53404' do
  title 'SQL Server must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes, but is not limited to:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked. 

SQL Server is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know the outcome of attempted actions. This requires specific information regarding the outcome of the action or event that the audit record is referring to. If outcome status information is not recorded and stored with the audit record, the record itself is of very limited use.

Success and failure indicators ascertain the outcome of a particular event. As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response. Without knowing the outcome of audit events, it is very difficult to accurately recreate the series of events during forensic analysis.

If auditing is enabled, SQL Server does capture the outcome status-specific information in all audit records.'
  desc 'check', 'Check to see that all required events are being audited.
From the query prompt:
     SELECT DISTINCT traceid FROM sys.fn_trace_getinfo(0);
All currently defined traces for the SQL server instance will be listed. If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement. 
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
     SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);
The following required event IDs should be listed:
     14, 15, 18, 20, 
     102, 103, 104, 105, 106, 107, 108, 109, 110, 
     111, 112, 113, 115, 116, 117, 118, 
     128, 129, 130, 
     131, 132, 133, 134, 135, 
     152, 153, 
     170, 171, 172, 173, 175, 176, 177, 178.
If any of the audit event IDs required above is not listed, this is a finding.

Notes:
1. It is acceptable to have the required event IDs spread across multiple traces, provided all of the traces are always active, and the event IDs are grouped in a logical manner.
2. It is acceptable, from an auditing point of view, to include the same event IDs in multiple traces.  However, the effect of this redundancy on performance, storage, and the consolidation of audit logs into a central repository, should be taken into account.
3. It is acceptable to trace additional event IDs. This is the minimum list.
4. Once this check is satisfied, the DBA may find it useful to disable or modify the default trace that is set up by the SQL Server installation process. (Note that the Fix does NOT include code to do this.)  
Use the following query to obtain a list of all event IDs, and their meaning:
     SELECT * FROM sys.trace_events; 
5. Because this check procedure is designed to address multiple requirements/vulnerabilities, it may appear to exceed the needs of some individual requirements.  However, it does represent the aggregate of all such requirements.
6. Microsoft has flagged the trace techniques and tools used in this Check and Fix as deprecated.  They will be removed at some point after SQL Server 2014.  The replacement feature is Extended Events.  If Extended Events are in use, and cover all the required audit events listed above, this is not a finding.'
  desc 'fix', 'Create a trace that meets all auditing requirements.

The script provided in the supplemental file, Trace.sql, can be used to do this; edit it as necessary to capture any additional, locally defined events.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47646r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41029'
  tag rid: 'SV-53404r4_rule'
  tag stig_id: 'SQL2-00-012200'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-46328r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
