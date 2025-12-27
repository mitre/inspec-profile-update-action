control 'SV-53402' do
  title 'SQL Server must include organization-defined additional, more detailed information in the audit records for audit events identified by type, location, or subject.'
  desc 'SQL Server auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

SQL Server does have a means available to add organizationally defined additional, more detailed information in the audit event records. These events may be identified by type, location, or subject. An example of more detailed information the organization may require in audit records could be the name of the application where the request is coming from.

Some organizations may determine that more detailed information is required for specific database event types. If this information is not available, it could negatively impact forensic investigations into user actions or other malicious events.'
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
  tag check_id: 'C-47644r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41027'
  tag rid: 'SV-53402r4_rule'
  tag stig_id: 'SQL2-00-012400'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-46326r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
