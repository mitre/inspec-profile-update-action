control 'SRG-NET-000395-VVSM-00010_rule' do
  title 'The Unified Communications Session Manager, when using locally stored user accounts, must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. 

This applies to network elements that have the concept of a user account (e.g., VPN, ALG, and proxy) as well as devices that can control traffic flow based on access authorizations (firewalls, IDPS).'
  desc 'check', 'Verify the Unified Communications Session Manager, when using locally stored user accounts, automatically locks the account until released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

If the Unified Communications Session Manager, when using locally stored user accounts, does not automatically lock the account until released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager, when using locally stored user accounts, to automatically lock the account until released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000395-VVSM-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000395-VVSM-00010'
  tag rid: 'SRG-NET-000395-VVSM-00010_rule'
  tag stig_id: 'SRG-NET-000395-VVSM-00010'
  tag gtitle: 'SRG-NET-000395-VVSM-00010'
  tag fix_id: 'F-SRG-NET-000395-VVSM-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
