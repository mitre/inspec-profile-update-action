control 'SV-227714' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors allowing unauthorized access to the system.  These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', %q(Determine if default system accounts (such as, those for sys, bin, uucp, nuucp, daemon, smtp, gdm, lp, nobody) have been disabled. 

# cat /etc/shadow 

If an account's password field is "*", "*LK*", "NP", or is prefixed with a "!", the account is locked or disabled. 

If any default system account is not locked and its use is not justified and documented with the ISSO, this is a finding.)
  desc 'fix', 'Lock the default system account(s).
# passwd -l <user>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29876r488726_chk'
  tag severity: 'medium'
  tag gid: 'V-227714'
  tag rid: 'SV-227714r603266_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29864r488727_fix'
  tag 'documentable'
  tag legacy: ['V-810', 'SV-39834']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
