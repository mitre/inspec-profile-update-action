control 'SV-45206' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors allowing unauthorized access to the system. These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', %q(Determine if default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have been disabled.
# cat /etc/shadow
If an account's password field is "*", "*LK*", or is prefixed with a '!', the account is locked or disabled.
If there are any unlocked default system accounts this is a finding.)
  desc 'fix', 'Lock the default system account(s).
# passwd -l <user>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42554r1_chk'
  tag severity: 'medium'
  tag gid: 'V-810'
  tag rid: 'SV-45206r1_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'GEN002640'
  tag fix_id: 'F-38602r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
