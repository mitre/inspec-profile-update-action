control 'SV-4089' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', 'Check the ownership of system run control scripts.  If any are owned by a user other than root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# chown root <run control script>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-1674r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4089'
  tag rid: 'SV-4089r2_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'GEN001660'
  tag fix_id: 'F-4022r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
