control 'SV-4273' do
  title 'The /etc/news/hosts.nntp (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/hosts.nntp permissions.

# ls -lL /etc/news/hosts.nntp

If /etc/news/hosts.nntp has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/hosts.nntp file to 0600.

# chmod 0600 /etc/news/hosts.nntp'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2092r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4273'
  tag rid: 'SV-4273r2_rule'
  tag stig_id: 'GEN006260'
  tag gtitle: 'GEN006260'
  tag fix_id: 'F-4184r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
