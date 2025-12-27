control 'SV-207267' do
  title 'Exchange must have Administrator audit logging enabled.'
  desc "Unauthorized or malicious data changes can compromise the integrity and usefulness of the data. Automated attacks or malicious users with elevated privileges have the ability to effect change using the same mechanisms as email administrators. 

Auditing changes to access mechanisms not only supports accountability and nonrepudiation for those authorized to define the environment but also enables investigation of changes made by others who may not be authorized. 

Note: This administrator auditing feature audits all exchange changes regardless of the users' assigned role or permissions."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select Name, AdminAuditLogEnabled

If the value of AdminAuditLogEnabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogEnabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7525r393314_chk'
  tag severity: 'medium'
  tag gid: 'V-207267'
  tag rid: 'SV-207267r615936_rule'
  tag stig_id: 'EX13-MB-000005'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-7525r393315_fix'
  tag 'documentable'
  tag legacy: ['SV-84563', 'V-69941']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
