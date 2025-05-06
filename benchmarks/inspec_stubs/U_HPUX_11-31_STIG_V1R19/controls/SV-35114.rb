control 'SV-35114' do
  title 'The /etc/news/hosts.nntp (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Locate/check the hosts.nntp permissions.
# find / -type f -name hosts.nntp | xargs -n1 ls -lL 

If hosts.nntp has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the hosts.nntp file to 0600.

# chmod 0600 <path>/hosts.nntp'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34958r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4273'
  tag rid: 'SV-35114r1_rule'
  tag stig_id: 'GEN006260'
  tag gtitle: 'GEN006260'
  tag fix_id: 'F-30262r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
