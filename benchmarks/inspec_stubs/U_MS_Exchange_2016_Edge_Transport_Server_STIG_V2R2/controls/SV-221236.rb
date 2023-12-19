control 'SV-221236' do
  title 'Exchange nonexistent recipients must not be blocked.'
  desc 'Spam originators, in an effort to refine mailing lists, sometimes use a technique where they first create fictitious names and then monitor rejected emails for non-existent recipients. Those not rejected are deemed to exist and are used in future spam mailings. 

To prevent this disclosure of existing email accounts to spammers, email to nonexistent recipients must not be blocked. Instead, it is recommended that all messages be received, then evaluated and disposed of without enabling the sender to determine existent vs. nonexistent recipients.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Open the Exchange Management Shell and enter the following command:

Get-RecipientFilterConfig | Select Name, RecipientValidationEnabled

If the value of "RecipientValidationEnabled" is not set to "False", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RecipientFilterConfig -RecipientValidationEnabled $false'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22951r411834_chk'
  tag severity: 'medium'
  tag gid: 'V-221236'
  tag rid: 'SV-221236r612603_rule'
  tag stig_id: 'EX16-ED-000370'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22940r411835_fix'
  tag 'documentable'
  tag legacy: ['SV-95263', 'V-80553']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
