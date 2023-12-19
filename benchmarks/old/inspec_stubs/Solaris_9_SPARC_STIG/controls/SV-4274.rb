control 'SV-4274' do
  title 'The /etc/news/hosts.nntp.nolimit (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'fix', 'Change the mode of /etc/news/hosts.nntp.nolimit to 0600.
# chmod 0600 /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
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
