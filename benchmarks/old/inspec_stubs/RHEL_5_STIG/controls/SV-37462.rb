control 'SV-37462' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22436'
  tag rid: 'SV-37462r1_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'GEN003950'
  tag fix_id: 'F-31372r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
