control 'SV-82667' do
  title 'The Mainframe Product must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine Mainframe Product configuration settings.

Verify that the Mainframe Product account management setting automatically locks the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68177'
  tag rid: 'SV-82667r1_rule'
  tag stig_id: 'SRG-APP-000345-MFP-000094'
  tag gtitle: 'SRG-APP-000345-MFP-000094'
  tag fix_id: 'F-74293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
