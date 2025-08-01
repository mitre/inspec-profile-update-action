control 'SV-82665' do
  title 'The Mainframe Product must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine Mainframe Product configuration settings.

Verify that the Mainframe Product account management settings enforce a limit of three consecutive invalid logon attempts by a user during a 15 minute time period. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to enforce a limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68175'
  tag rid: 'SV-82665r1_rule'
  tag stig_id: 'SRG-APP-000065-MFP-000093'
  tag gtitle: 'SRG-APP-000065-MFP-000093'
  tag fix_id: 'F-74291r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
