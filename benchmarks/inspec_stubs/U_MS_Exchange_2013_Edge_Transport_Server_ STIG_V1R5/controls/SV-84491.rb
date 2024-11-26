control 'SV-84491' do
  title 'Exchange nonexistent recipients must not be blocked.'
  desc 'Spam originators, in an effort to refine mailing lists, sometimes use a technique where they first create fictitious names and then monitor rejected emails for non-existent recipients. Those not rejected are deemed to exist and are used in future spam mailings. 

To prevent this disclosure of existing email accounts to spammers, email to nonexistent recipients must not be blocked. Instead, it is recommended that all messages be received, then evaluated and disposed of without enabling the sender to determine existent vs. nonexistent recipients.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-RecipientFilterConfig | Select Name, RecipientValidationEnabled

If the value of RecipientValidationEnabled is not set to False, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RecipientFilterConfig -RecipientValidationEnabled $false'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70337r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69869'
  tag rid: 'SV-84491r1_rule'
  tag stig_id: 'EX13-EG-000185'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
