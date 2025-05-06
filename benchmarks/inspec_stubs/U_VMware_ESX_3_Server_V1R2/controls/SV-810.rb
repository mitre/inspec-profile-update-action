control 'SV-810' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors allowing unauthorized access to the system.  These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', %q(Determine if default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp, gdm, lp, nobody) have been disabled.
# cat /etc/shadow
If an account's password field is "*", "*LK*", or is prefixed with a "!", the account is locked or disabled.
If there is any default system accounts not locked, this is a finding.)
  desc 'fix', 'Lock the default system account(s).
# passwd -l <user>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-552r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27263'
  tag rid: 'SV-810r2_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'GEN002640'
  tag fix_id: 'F-964r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001463']
  tag nist: ['AU-14 b']
end
