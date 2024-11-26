control 'SV-39252' do
  title 'The /etc/news/hosts.nntp.nolimit (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/hosts.nntp.nolimit permissions.

# find / -name hosts.nntp.nolimit

# ls -lL < hosts.nntp.nolimit file >

If hosts.nntp.nolimit has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of hosts.nntp.nolimit to 0600.
# chmod 0600 < hosts.nntp.nolimit file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38226r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4274'
  tag rid: 'SV-39252r1_rule'
  tag stig_id: 'GEN006280'
  tag gtitle: 'GEN006280'
  tag fix_id: 'F-33501r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
