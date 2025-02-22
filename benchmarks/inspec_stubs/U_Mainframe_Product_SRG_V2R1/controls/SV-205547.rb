control 'SV-205547' do
  title 'The Mainframe Product must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine Mainframe Product configuration settings.

Verify that the Mainframe Product account management setting automatically locks the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5813r299874_chk'
  tag severity: 'medium'
  tag gid: 'V-205547'
  tag rid: 'SV-205547r851315_rule'
  tag stig_id: 'SRG-APP-000345-MFP-000094'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-5813r299875_fix'
  tag 'documentable'
  tag legacy: ['SV-82667', 'V-68177']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
