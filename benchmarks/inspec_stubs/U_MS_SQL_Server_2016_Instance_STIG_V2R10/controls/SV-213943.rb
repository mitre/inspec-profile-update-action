control 'SV-213943' do
  title 'SQL Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when SQL Server is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include; software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.  
 
When availability is an overriding concern, approved actions in response to an audit failure are as follows:  
 
(i) If the failure was caused by the lack of audit record storage capacity, SQL Server must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.  
 
(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, SQL Server must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.  
 
Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', %q(If the system documentation indicates that availability does not take precedence over audit trail completeness, this is not applicable (NA). 

Execute the following query:

SELECT a.name 'audit_name',
    a.type_desc 'storage_type',
    f.max_rollover_files
FROM sys.server_audits a
LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
WHERE a.is_state_enabled = 1

If no records are returned, this is a finding.

If the "storage_type" is "APPLICATION LOG" or "SECURITY LOG", this is not a finding.

If the "storage_type" is "FILE" and "max_rollover_files" is greater than zero, this is not a finding. Otherwise, this is a finding.)
  desc 'fix', 'If SQL Server Audit is in use, configure SQL Server Audit to continue to generate audit records, overwriting the oldest existing records, in the case of an auditing failure. 
 
Run this T-SQL script for each identified audit:  
 
ALTER SERVER AUDIT [AuditName] WITH (STATE = OFF);  
GO  
ALTER SERVER AUDIT [AuditName] to file (max_rollover_files = IntegerValue);  
GO  
ALTER SERVER AUDIT [AuditName] WITH (STATE = ON);  
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15160r754586_chk'
  tag severity: 'medium'
  tag gid: 'V-213943'
  tag rid: 'SV-213943r879571_rule'
  tag stig_id: 'SQL6-D0-005700'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-15158r313613_fix'
  tag 'documentable'
  tag legacy: ['SV-93855', 'V-79149']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
