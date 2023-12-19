control 'SV-218375' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors allowing unauthorized access to the system. These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', %q(Determine if default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have been disabled.

# cat /etc/shadow

If an account's password field (which is the second field in the /etc/shadow file) is "*", "*LK*", or is prefixed with a '!', the account is locked or disabled.

If there are any unlocked default system accounts, this is a finding.)
  desc 'fix', 'Lock the default system account(s).
# passwd -l <user>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19850r569083_chk'
  tag severity: 'medium'
  tag gid: 'V-218375'
  tag rid: 'SV-218375r603259_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19848r569084_fix'
  tag 'documentable'
  tag legacy: ['V-810', 'SV-63809']
  tag cci: ['CCI-000366', 'CCI-000178']
  tag nist: ['CM-6 b', 'IA-5 e']
end
