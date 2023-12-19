control 'SV-20652' do
  title 'Email software installation account usage must be logged.'
  desc 'Email Administrator or application owner accounts are granted more enhanced privileges than non-privileged users. It is especially important to grant access to privileged accounts to only those persons who are qualified and authorized to use them. Each use of the account should be logged to demonstrate this accountability.'
  desc 'check', 'Access the EDSP to verify logging procedure for software installation account usage. Examine evidence that logging is done for use of the correct account for email software installations and upgrades. 

If email software installation account usage is logged, this is not a finding.'
  desc 'fix', 'Implement a logging procedure for use of the email software installation account. Document it in the EDSP.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22676r5_chk'
  tag severity: 'low'
  tag gid: 'V-18868'
  tag rid: 'SV-20652r3_rule'
  tag stig_id: 'EMG3-028 EMail'
  tag gtitle: 'EMG3-028 Installation Account Usage Logged'
  tag fix_id: 'F-19572r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECPA-1'
end
