control 'SV-53928' do
  title 'SQL Server must provide audit record generation capability for organization-defined auditable events within the database.'
  desc 'Audit records can be generated from various components within the information system (e.g., network interface, hard disk, modem, etc.). From an application perspective, certain specific application functionalities may be audited as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.  Examples are auditable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

Organizations define which application components shall provide auditable events. 

The DBMS must provide auditing for the list of events defined by the organization or risk negatively impacting forensic investigations into malicious behavior in the information system.'
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
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47940r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41402'
  tag rid: 'SV-53928r4_rule'
  tag stig_id: 'SQL2-00-011200'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-46828r6_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
