control 'SV-35143' do
  title 'The hosts.lpd (or equivalent) file must be owned by root, bin, sys, or lp.'
  desc 'Failure to give ownership of the hosts.lpd file to root, bin, sys, or lp provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file. Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'fix', 'Change the owner of the /etc/hosts.lpd file (or equivalent) to root, lp, or another privileged UID. 
# chown root <print service configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-828'
  tag rid: 'SV-35143r1_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'GEN003920'
  tag fix_id: 'F-30294r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
