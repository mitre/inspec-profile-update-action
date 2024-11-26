control 'SV-4274' do
  title 'The /etc/news/hosts.nntp.nolimit (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/hosts.nntp.nolimit permissions.

# ls -lL /etc/news/hosts.nntp.nolimit

If /etc/news/hosts.nntp.nolimit has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of /etc/news/hosts.nntp.nolimit to 0600.
# chmod 0600 /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2093r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4274'
  tag rid: 'SV-4274r2_rule'
  tag stig_id: 'GEN006280'
  tag gtitle: 'GEN006280'
  tag fix_id: 'F-4185r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
