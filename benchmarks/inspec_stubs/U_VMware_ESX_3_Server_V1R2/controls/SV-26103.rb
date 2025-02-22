control 'SV-26103' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the permissions of the /etc/hosts.lpd file.
# ls -lL /etc/hosts.lpd
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the hosts.lpd file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27704r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22436'
  tag rid: 'SV-26103r1_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'GEN003950'
  tag fix_id: 'F-26285r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
