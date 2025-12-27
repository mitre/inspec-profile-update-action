control 'SV-44060' do
  title 'Non-existent recipients must not be blocked.'
  desc 'SPAM originators, in an effort to refine mailing lists, sometimes use a technique where they first create fictitious names, and then monitor rejected emails for non-existent recipients.  
Those not rejected, of course, are deemed to exist, and are therefore used in future SPAM mailings. 

To prevent this disclosure of existing email accounts to Spammers, this feature should not be employed.  Instead, it is recommended that all messages be received, then evaluated and disposed of without enabling the sender to determine recipients that are  existing vs. non-existing.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RecipientFilterConfig | Select RecipientValidationEnabled

If the value of 'RecipientValidationEnabled' is not set to 'False', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RecipientFilterConfig -RecipientValidationEnabled $False'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41750r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33640'
  tag rid: 'SV-44060r1_rule'
  tag stig_id: 'Exch-2-305'
  tag gtitle: 'Exch-2-305'
  tag fix_id: 'F-37533r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
