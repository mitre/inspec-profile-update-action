control 'SV-84345' do
  title 'Exchange must have Administrator audit logging enabled.'
  desc "Unauthorized or malicious data changes can compromise the integrity and usefulness of the data. Automated attacks or malicious users with elevated privileges have the ability to affect change using the same mechanisms as email administrators.

Auditing changes to access mechanisms not only supports accountability and non-repudiation for those authorized to define the environment but also enables investigation of changes made by others who may not be authorized. 

Note: This administrator auditing feature audits all exchange changes regardless of the users' assigned role or permissions."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select Name, Identity, AdminAuditLogEnabled

If the value of AdminAuditLogEnabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogEnabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70165r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69723'
  tag rid: 'SV-84345r1_rule'
  tag stig_id: 'EX13-CA-000025'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-75927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
