control 'SV-228354' do
  title 'Exchange must have Administrator audit logging enabled.'
  desc "Unauthorized or malicious data changes can compromise the integrity and usefulness of the data. Automated attacks or malicious users with elevated privileges have the ability to effect change using the same mechanisms as email administrators. 

Auditing any changes to access mechanisms not only supports accountability and nonrepudiation for those authorized to define the environment but also enables investigation of changes made by others who may not be authorized. 

Note: This administrator auditing feature audits all exchange changes regardless of the user's assigned role or permissions."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select Name, AdminAuditLogEnabled

If the value of "AdminAuditLogEnabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogEnabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30587r496858_chk'
  tag severity: 'medium'
  tag gid: 'V-228354'
  tag rid: 'SV-228354r612748_rule'
  tag stig_id: 'EX16-MB-000010'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-30572r496859_fix'
  tag 'documentable'
  tag legacy: ['SV-95333', 'V-80623']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
