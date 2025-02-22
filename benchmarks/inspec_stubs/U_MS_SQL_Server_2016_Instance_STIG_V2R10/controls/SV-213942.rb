control 'SV-213942' do
  title 'SQL Server must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when SQL Server is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.  
 
When the need for system availability does not outweigh the need for a complete audit trail, SQL Server should shut down immediately, rolling back all in-flight transactions. 
 
Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If the system documentation indicates that availability takes precedence over audit trail completeness, this is not applicable (NA).  
 
If SQL Server Audit is in use, review the defined server audits by running the statement:  
 
SELECT * FROM sys.server_audits;  
 
By observing the [name] and [is_state_enabled] columns, identify the row or rows in use.  
 
If the [on_failure_desc] is "SHUTDOWN SERVER INSTANCE" on this/these row(s), this is not a finding. Otherwise, this is a finding.'
  desc 'fix', 'If SQL Server Audit is in use, configure SQL Server Audit to shut SQL Server down upon audit failure, to include running out of space for audit logs.  
 
Run this T-SQL script for each identified audit:  
 
ALTER SERVER AUDIT [AuditNameHere] WITH (STATE = OFF);  
GO  
ALTER SERVER AUDIT [AuditNameHere] WITH (ON_FAILURE = SHUTDOWN);  
GO  
ALTER SERVER AUDIT [AuditNameHere] WITH (STATE = ON);  
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15159r313609_chk'
  tag severity: 'medium'
  tag gid: 'V-213942'
  tag rid: 'SV-213942r879571_rule'
  tag stig_id: 'SQL6-D0-005600'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-15157r313610_fix'
  tag 'documentable'
  tag legacy: ['SV-93853', 'V-79147']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
