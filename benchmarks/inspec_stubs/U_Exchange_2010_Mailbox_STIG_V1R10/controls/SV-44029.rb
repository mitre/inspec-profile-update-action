control 'SV-44029' do
  title 'Administrator audit logging must be enabled.'
  desc "Unauthorized or malicious data changes can compromise the integrity and usefulness of the data.  Automated attacks or malicious users with elevated privileges have the ability to affect change using the same mechanisms as email administrators.  

Auditing changes to access mechanisms not only supports accountability and non-repudiation for those authorized to define the environment but also enables investigation of changes made by others who may not be authorized.   

Note: This administrator auditing feature audits all exchange changes regardless of the users' assigned role or permissions."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select AdminAuditLogEnabled

If the value of 'AdminAuditLogEnabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig  -AdminAuditLogEnabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41716r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33609'
  tag rid: 'SV-44029r2_rule'
  tag stig_id: 'Exch-2-823'
  tag gtitle: 'Exch-2-823'
  tag fix_id: 'F-37501r1_fix'
  tag 'documentable'
end
