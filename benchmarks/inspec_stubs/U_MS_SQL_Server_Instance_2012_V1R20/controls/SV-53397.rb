control 'SV-53397' do
  title 'SQL Server must shutdown immediately in the event of an audit failure, unless an alternative audit capability exists.'
  desc 'It is critical that, when SQL Server is at risk of failing to process audit logs as required, it takes action to mitigate the failure. If the system were to continue processing without auditing enabled, actions could be taken on the system that could not be tracked and recorded for later forensic analysis.

In many system configurations, the disk space allocated to the auditing system is separate from the disks allocated for the operating system; therefore, this may not result in a system outage. This places the onus on the DBMS to detect and take actions.

A failure of SQL Server auditing will result in either the database continuing to function without auditing, or the halting of SQL Server operations. In this case, the database must cease processing immediately in order to not allow unlogged transaction to occur.

Note that trace file rollover does not count as an audit failure, provided that the system is also configured to shut down when it runs out of space.  Trace file rollover can be a useful technique for breaking the log into manageable pieces, for archiving, or for transfer to a log management system.'
  desc 'check', 'From the query prompt:

SELECT DISTINCT traceid FROM sys.fn_trace_getinfo(0);

All currently defined traces for the SQL Server instance will be listed. If no traces are returned, this is a finding.

Determine the trace being used for the auditing requirement. Replace # in the following code with a traceid being used for the auditing requirements.

From the query prompt, determine whether the trace options include the value 4, which means SHUTDOWN_ON_ERROR:
SELECT CAST(value AS INT) 
FROM sys.fn_trace_getinfo(#)
where property = 1;

If the query does not return a value, this is a finding.
If a value is returned but is not 4 or 6, this is a finding.
(6 represents the combination of values 2 and 4.  2 means TRACE_FILE_ROLLOVER.)


NOTE:  Microsoft has flagged the trace techniques and tools used in this STIG as deprecated. They will be removed at some point after SQL Server 2014. The replacement feature is Extended Events. If Extended Events are in use and configured to satisfy this requirement, this is not a finding.  The following code can be used to check Extended Events settings.
/********************************** 
Check to verify shutdown on failure is set.
The following settings are what should be returned: 
name = <name of audit> 
on_failure = 1 
on_failure_desc = SHUTDOWN SERVER INSTANCE 
**********************************/ 
SELECT name, on_failure, on_failure_desc 
FROM sys.server_audits'
  desc 'fix', 'If a trace does not exist, create a trace specification that complies with requirements.

If a trace exists, but is not set to SHUTDOWN_ON_ERROR, modify the SQL Server audit setting to immediately shutdown the database in the event of an audit failure by setting property 1 to a value of 4 or 6 for the audit.

(See the SQL Server Help page for sys.sp_trace_create for implementation details.)'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47639r10_chk'
  tag severity: 'medium'
  tag gid: 'V-41022'
  tag rid: 'SV-53397r3_rule'
  tag stig_id: 'SQL2-00-012800'
  tag gtitle: 'SRG-APP-000107-DB-000169'
  tag fix_id: 'F-46321r4_fix'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
