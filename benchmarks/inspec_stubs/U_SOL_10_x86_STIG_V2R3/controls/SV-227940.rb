control 'SV-227940' do
  title 'The /etc/news/hosts.nntp.nolimit (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/hosts.nntp.nolimit permissions.

# ls -lL /etc/news/hosts.nntp.nolimit

If /etc/news/hosts.nntp.nolimit has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of /etc/news/hosts.nntp.nolimit to 0600.
# chmod 0600 /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30102r490240_chk'
  tag severity: 'medium'
  tag gid: 'V-227940'
  tag rid: 'SV-227940r854516_rule'
  tag stig_id: 'GEN006280'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30090r490241_fix'
  tag 'documentable'
  tag legacy: ['V-4274', 'SV-4274']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
