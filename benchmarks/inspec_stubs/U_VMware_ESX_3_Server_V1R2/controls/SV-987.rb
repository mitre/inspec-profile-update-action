control 'SV-987' do
  title 'The at.allow file must have mode 0600 or less permissive.'
  desc 'Permissions more permissive than 0600 (read, write, and execute for the owner) may allow unauthorized or malicious access to the at.allow and/or at.deny files.'
  desc 'check', 'Check the mode of the at.allow file.  If the at.allow file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the at.allow file to 0600.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-800r2_chk'
  tag severity: 'medium'
  tag gid: 'V-987'
  tag rid: 'SV-987r2_rule'
  tag stig_id: 'GEN003340'
  tag gtitle: 'GEN003340'
  tag fix_id: 'F-1141r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
