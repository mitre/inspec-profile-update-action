control 'SV-38807' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the permissions of the /etc/hosts.lpd file.
#aclget /etc/hosts.lpd 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the hosts.lpd file and disable extended permissions.

#acledit /etc/hosts.lpd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22436'
  tag rid: 'SV-38807r1_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'GEN003950'
  tag fix_id: 'F-31886r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
