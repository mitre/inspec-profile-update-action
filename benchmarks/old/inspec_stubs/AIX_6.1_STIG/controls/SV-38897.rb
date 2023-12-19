control 'SV-38897' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors allowing unauthorized access to the system.  These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', 'Determine if default system accounts (such as those for guest, sys, bin, uucp, nuucp, daemon, smtp, and lpd) have been disabled.
Procedure:
# lsuser -a account_locked ALL

If there are any unlocked default system accounts,  this is a finding.'
  desc 'fix', 'Lock the default system account(s).
# chuser account_locked=true <user>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37188r1_chk'
  tag severity: 'medium'
  tag gid: 'V-810'
  tag rid: 'SV-38897r1_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'GEN002640'
  tag fix_id: 'F-24500r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
